//! File event eBPF programs.
//!
//! We split create/delete handling across syscall entry and exit:
//!
//! - `syscalls/sys_enter_openat` queues create candidates when `O_CREAT` is set.
//! - `vfs_create` marks candidates that actually created a new inode.
//! - `syscalls/sys_exit_openat` emits create events only when the syscall succeeds.
//! - `syscalls/sys_enter_unlinkat` queues delete candidates.
//! - `syscalls/sys_exit_unlinkat` emits delete events only when the syscall succeeds.
//! - `syscalls/sys_enter_renameat*` queues rename candidates.
//! - `syscalls/sys_exit_renameat*` emits rename events only when the syscall succeeds.
//!
//! This keeps the Linux MVP narrow while avoiding false positives from failed
//! syscalls or `openat(O_CREAT)` calls that never complete successfully.
//!
//! Every one of these syscalls takes its pathname as a `*at` argument pair: a
//! directory descriptor plus a name that may be relative to it. The descriptor
//! is captured alongside the name so userspace can rebuild the absolute path —
//! without it, `openat(dirfd, "passwd")` and `openat(AT_FDCWD, "passwd")` are
//! indistinguishable strings that name different files.
//!
//! Successful directory opens are reported too, under a kind the drain loop
//! consumes rather than forwarding. They are what lets a descriptor be named at
//! the moment it is created; reading it back from `/proc` when the event is
//! drained answers for whatever the number points at then, and a process
//! walking a tree recycles fd numbers faster than that. The filter is
//! `O_DIRECTORY | O_PATH` rather than every read-only open: measured on a lab
//! VM, indexing every read-only open costs 20-29% on a file-read-heavy
//! workload against ~0% for this one.
//!
//! sys_enter_openat tracepoint format (x86_64, 64-bit ABI):
//!   offset  0: common_type         (u16)
//!   offset  2: common_flags        (u8)
//!   offset  3: common_preempt_count(u8)
//!   offset  4: common_pid          (i32)
//!   offset  8: __syscall_nr        (i32)
//!   offset 12: _padding            (4 bytes)
//!   offset 16: dfd                 (i64  — directory file descriptor)
//!   offset 24: filename            (u64  — user pointer to path string)
//!   offset 32: flags               (i64  — open flags)
//!   offset 40: mode                (i64  — creation mode)
//!
//! sys_enter_unlinkat tracepoint format (same structure):
//!   offset 16: dfd                 (i64)
//!   offset 24: pathname            (u64  — user pointer to path string)
//!   offset 32: flag                (i64)
//!
//! sys_enter_renameat tracepoint format (x86_64, 64-bit ABI):
//!   offset 16: olddfd              (i64)
//!   offset 24: oldname             (u64  — user pointer to old path string)
//!   offset 32: newdfd              (i64)
//!   offset 40: newname             (u64  — user pointer to new path string)
//!
//! sys_exit_* tracepoint format (x86_64, 64-bit ABI):
//!   offset  0: common_type         (u16)
//!   offset  2: common_flags        (u8)
//!   offset  3: common_preempt_count(u8)
//!   offset  4: common_pid          (i32)
//!   offset  8: __syscall_nr        (i32)
//!   offset 12: _padding            (4 bytes)
//!   offset 16: ret                 (i64)

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, TracePointContext},
};

use crate::events::{
    FileEvent, FILE_FLAG_AUX_PATH_TRUNCATED, FILE_FLAG_PATH_TRUNCATED, FILE_PATH_LEN,
};

/// O_CREAT flag — create file if it does not exist.
const O_CREAT: u64 = 0x40;
const O_WRONLY: u64 = 0x1;
const O_RDWR: u64 = 0x2;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
/// The caller requires the target to be a directory. `opendir(3)` sets it, so
/// it covers how libc, Go, Rust, and Python obtain the descriptors that later
/// appear as a `dfd`.
const O_DIRECTORY: u64 = 0x1_0000;
/// The caller wants a handle to the location, not the contents. `O_PATH`
/// descriptors are legal `*at` directory descriptors.
const O_PATH: u64 = 0x20_0000;

const FILE_KIND_CREATE: u32 = 1;
const FILE_KIND_DELETE: u32 = 2;
const FILE_KIND_RENAME: u32 = 3;
const FILE_KIND_CHANGE: u32 = 4;
/// Not a file event: a directory descriptor being opened, reported so userspace
/// can name the `dfd` of later `*at` calls. Never reaches the engine.
const FILE_KIND_DIR_OPEN: u32 = 5;

/// Ring buffer shared with the userspace loader for file events.
///
/// Sized to hold roughly a thousand `FileEvent`s, the same burst headroom the
/// 96-byte-path layout had at 256 KiB.
#[map]
pub static FILE_RING: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Per-thread pending file operation, keyed by TID.
///
/// A thread is inside exactly one syscall at a time, so `openat`, `unlinkat`,
/// and `renameat*` share one slot per thread instead of one map each. At a
/// `FileEvent` of ~1 KiB that is the difference between 17 MiB and 51 MiB of
/// kernel memory.
#[map]
static FILE_PENDING: HashMap<u32, FileEvent> = HashMap::with_max_entries(16_384, 0);

/// Per-CPU staging area for the event under construction.
///
/// A `FileEvent` is far larger than the 512-byte BPF stack, so it is built in
/// map memory and copied straight from there into the pending map or the ring
/// buffer.
///
/// The slot is held for the handful of instructions between filling it and
/// `insert`ing it, so a tracepoint that nests on the same CPU in that window
/// can overwrite it — the same exposure `DNS_SCRATCH` carries. The cost is a
/// garbled path on a rare event, not a memory error, and the alternative
/// (per-thread scratch) would cost another map the size of `FILE_PENDING`.
#[map]
static FILE_SCRATCH: PerCpuArray<FileEvent> = PerCpuArray::with_max_entries(1, 0);

/// Per-thread marker that `vfs_create` ran for the pending open.
#[map]
static OPENAT_CREATED: HashMap<u32, u8> = HashMap::with_max_entries(16_384, 0);

/// Queue a potential file-create event for `openat(O_CREAT)`.
#[tracepoint]
pub fn handle_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_openat(&ctx) }.unwrap_or(1)
}

/// Mark a queued `openat(O_CREAT)` as a real create when the kernel reaches
/// `vfs_create`.
#[kprobe(function = "vfs_create")]
pub fn handle_vfs_create(ctx: ProbeContext) -> u32 {
    unsafe { try_handle_vfs_create(&ctx) }.unwrap_or(1)
}

/// Emit a file-create event only after `openat` succeeds.
#[tracepoint]
pub fn handle_openat_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_openat_exit(&ctx) }.unwrap_or(1)
}

/// Queue a potential file-delete event for `unlinkat`.
#[tracepoint]
pub fn handle_unlinkat(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_unlinkat(&ctx) }.unwrap_or(1)
}

/// Emit a file-delete event only after `unlinkat` succeeds.
#[tracepoint]
pub fn handle_unlinkat_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_unlinkat_exit(&ctx) }.unwrap_or(1)
}

/// Queue a potential file-rename event for `renameat`.
#[tracepoint]
pub fn handle_renameat(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_renameat(&ctx) }.unwrap_or(1)
}

/// Emit a file-rename event only after `renameat` succeeds.
#[tracepoint]
pub fn handle_renameat_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_renameat_exit(&ctx) }.unwrap_or(1)
}

/// Queue a potential file-rename event for `renameat2`.
#[tracepoint]
pub fn handle_renameat2(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_renameat(&ctx) }.unwrap_or(1)
}

/// Emit a file-rename event only after `renameat2` succeeds.
#[tracepoint]
pub fn handle_renameat2_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_renameat_exit(&ctx) }.unwrap_or(1)
}

#[inline(always)]
unsafe fn try_handle_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    let flags: u64 = ctx.read_at::<u64>(32)?;
    let tid = bpf_get_current_pid_tgid() as u32;
    if flags & O_CREAT != 0 {
        let _ = OPENAT_CREATED.remove(&tid);
        return queue_file_event(ctx, FILE_KIND_CREATE);
    }

    if flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND) != 0 {
        return queue_file_event(ctx, FILE_KIND_CHANGE);
    }

    // A directory open is not a file event, but it is the only moment at which
    // the descriptor a later `openat(dfd, "name")` refers to can be named
    // reliably. Reading it back from `/proc/<pid>/fd/<dfd>` when the event is
    // drained answers for whatever the number points at *then*, and a process
    // that walks a tree recycles fd numbers faster than that.
    if flags & (O_DIRECTORY | O_PATH) != 0 {
        return queue_file_event(ctx, FILE_KIND_DIR_OPEN);
    }

    // A read-only open queues nothing, and the thread cannot be inside another
    // tracked syscall while it enters this one, so anything still pending is a
    // leftover from a task that was killed mid-syscall and never reached its
    // exit tracepoint. Drop it here so the next `sys_exit_openat` cannot emit
    // a stale path.
    let _ = FILE_PENDING.remove(&tid);
    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_openat_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret: i64 = ctx.read_at::<i64>(16)?;
    let tid = bpf_get_current_pid_tgid() as u32;
    // Clean up the vfs_create marker regardless.
    let _ = OPENAT_CREATED.remove(&tid);
    // Emit for any successful openat(O_CREAT) — matches Sysmon Event ID 11 semantics,
    // which fires on any file creation/open-with-create, not only brand-new inodes.
    // The vfs_create kprobe path is kept for potential future filtering but is no
    // longer required to gate the event.
    if ret >= 0 {
        // The descriptor the open produced is the `dfd` userspace has to index
        // the path under, and it only exists at exit.
        if let Some(pending) = FILE_PENDING.get_ptr_mut(&tid) {
            if (*pending).kind == FILE_KIND_DIR_OPEN {
                (*pending).dfd = ret as i32;
            }
        }
    }
    emit_pending_file_event(
        FILE_KIND_CREATE,
        FILE_KIND_CHANGE,
        FILE_KIND_DIR_OPEN,
        ret >= 0,
    )
}

#[inline(always)]
unsafe fn try_handle_unlinkat(ctx: &TracePointContext) -> Result<u32, i64> {
    queue_file_event(ctx, FILE_KIND_DELETE)
}

#[inline(always)]
unsafe fn try_handle_unlinkat_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret: i64 = ctx.read_at::<i64>(16)?;
    emit_pending_file_event(
        FILE_KIND_DELETE,
        FILE_KIND_DELETE,
        FILE_KIND_DELETE,
        ret == 0,
    )
}

#[inline(always)]
unsafe fn try_handle_renameat(ctx: &TracePointContext) -> Result<u32, i64> {
    queue_rename_event(ctx)
}

#[inline(always)]
unsafe fn try_handle_renameat_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret: i64 = ctx.read_at::<i64>(16)?;
    emit_pending_file_event(
        FILE_KIND_RENAME,
        FILE_KIND_RENAME,
        FILE_KIND_RENAME,
        ret == 0,
    )
}

#[inline(always)]
unsafe fn try_handle_vfs_create(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    if FILE_PENDING.get_ptr(&tid).is_none() {
        return Ok(0);
    }

    let created: u8 = 1;
    let _ = OPENAT_CREATED.insert(&tid, &created, 0);
    Ok(0)
}

/// Copy a NUL-terminated user path into `dst`.
///
/// `Some(truncated)` on success. `None` means the string was unreadable or
/// empty — the per-CPU scratch buffer still holds the previous event's bytes in
/// that case, so the caller must abandon the event rather than emit whatever is
/// left there.
#[inline(always)]
unsafe fn read_user_path(ptr: u64, dst: &mut [u8; FILE_PATH_LEN]) -> Option<bool> {
    let Ok(read) = bpf_probe_read_user_str_bytes(ptr as *const u8, dst) else {
        return None;
    };
    if read.is_empty() {
        return None;
    }
    // The helper returns the byte count including the NUL, capped at the
    // destination size, so filling the buffer means the path was cut short. A
    // path that is exactly `FILE_PATH_LEN - 1` bytes long is flagged as well;
    // over-reporting truncation is the safe direction, since the flag only ever
    // tells a consumer not to trust the path as complete.
    Some(read.len() >= FILE_PATH_LEN - 1)
}

#[inline(always)]
unsafe fn queue_file_event(ctx: &TracePointContext, kind: u32) -> Result<u32, i64> {
    // openat and unlinkat share the layout: dfd at 16, pathname at 24.
    let dfd = ctx.read_at::<i64>(16)? as i32;
    let path_ptr: u64 = ctx.read_at::<u64>(24)?;
    if path_ptr == 0 {
        return Ok(0);
    }

    let Some(event) = FILE_SCRATCH.get_ptr_mut(0) else {
        return Ok(0);
    };

    let Some(truncated) = read_user_path(path_ptr, &mut (*event).path) else {
        return Ok(0);
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).kind = kind;
    (*event).pid = (pid_tgid >> 32) as u32;
    (*event).uid = bpf_get_current_uid_gid() as u32;
    (*event).flags = if truncated {
        FILE_FLAG_PATH_TRUNCATED
    } else {
        0
    };
    (*event).dfd = dfd;
    // `path` may itself be relative to `dfd`, and for a directory open the exit
    // overwrites `dfd` with the descriptor the open produced, so the base is
    // kept here as well. For the other kinds `aux_path` is empty and nothing
    // reads it.
    (*event).aux_dfd = dfd;
    (*event).aux_path[0] = 0;
    (*event).comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let tid = pid_tgid as u32;
    let _ = FILE_PENDING.insert(&tid, &*event, 0);
    Ok(0)
}

#[inline(always)]
unsafe fn queue_rename_event(ctx: &TracePointContext) -> Result<u32, i64> {
    let old_dfd = ctx.read_at::<i64>(16)? as i32;
    let old_path_ptr: u64 = ctx.read_at::<u64>(24)?;
    let new_dfd = ctx.read_at::<i64>(32)? as i32;
    let new_path_ptr: u64 = ctx.read_at::<u64>(40)?;
    if old_path_ptr == 0 || new_path_ptr == 0 {
        return Ok(0);
    }

    let Some(event) = FILE_SCRATCH.get_ptr_mut(0) else {
        return Ok(0);
    };

    // Source and destination are resolved against different descriptors —
    // `renameat(olddfd, "a", newdfd, "b")` is legal and common — so each name
    // keeps its own.
    let Some(target_truncated) = read_user_path(new_path_ptr, &mut (*event).path) else {
        return Ok(0);
    };
    let Some(source_truncated) = read_user_path(old_path_ptr, &mut (*event).aux_path) else {
        return Ok(0);
    };

    let mut flags = 0u32;
    if target_truncated {
        flags |= FILE_FLAG_PATH_TRUNCATED;
    }
    if source_truncated {
        flags |= FILE_FLAG_AUX_PATH_TRUNCATED;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).kind = FILE_KIND_RENAME;
    (*event).pid = (pid_tgid >> 32) as u32;
    (*event).uid = bpf_get_current_uid_gid() as u32;
    (*event).flags = flags;
    (*event).dfd = new_dfd;
    (*event).aux_dfd = old_dfd;
    (*event).comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let tid = pid_tgid as u32;
    let _ = FILE_PENDING.insert(&tid, &*event, 0);
    Ok(0)
}

/// Emit the entry queued by this thread's syscall entry, if it is still the
/// entry this exit is responsible for.
///
/// `kind_a`..`kind_c` are the kinds this exit tracepoint queues; a syscall that
/// only queues one passes it three times. A pending entry of any other kind
/// belongs to a syscall whose own exit never ran — a task killed mid-syscall —
/// and is dropped rather than emitted under this syscall's identity.
#[inline(always)]
unsafe fn emit_pending_file_event(
    kind_a: u32,
    kind_b: u32,
    kind_c: u32,
    should_emit: bool,
) -> Result<u32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(pending) = FILE_PENDING.get_ptr(&tid) else {
        return Ok(0);
    };

    let kind = (*pending).kind;
    if should_emit && (kind == kind_a || kind == kind_b || kind == kind_c) {
        // `output` hands the kernel the map value pointer and a constant length,
        // so the whole emit is one helper call the verifier checks by argument
        // type. `reserve` + `write` would instead round-trip a ~1 KiB value
        // through the 512-byte BPF stack, and reserve + `copy_nonoverlapping`
        // lowers to a byte-at-a-time loop between two pointer types whose
        // bounds the verifier has to re-derive on every iteration.
        let _ = FILE_RING.output::<FileEvent>(&*pending, 0);
    }

    let _ = FILE_PENDING.remove(&tid);
    Ok(0)
}
