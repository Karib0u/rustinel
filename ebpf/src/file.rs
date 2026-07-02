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
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};

use crate::events::FileEvent;

/// O_CREAT flag — create file if it does not exist.
const O_CREAT: u64 = 0x40;
const O_WRONLY: u64 = 0x1;
const O_RDWR: u64 = 0x2;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;

/// Ring buffer shared with the userspace loader for file events.
#[map]
pub static FILE_RING: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-thread pending `openat(O_CREAT)` operations.
#[map]
static OPENAT_PENDING: HashMap<u32, FileEvent> = HashMap::with_max_entries(16_384, 0);

/// Per-thread marker that `vfs_create` ran for the pending open.
#[map]
static OPENAT_CREATED: HashMap<u32, u8> = HashMap::with_max_entries(16_384, 0);

/// Per-thread pending `unlinkat` operations.
#[map]
static UNLINKAT_PENDING: HashMap<u32, FileEvent> = HashMap::with_max_entries(16_384, 0);

/// Per-thread pending `renameat*` operations.
#[map]
static RENAME_PENDING: HashMap<u32, FileEvent> = HashMap::with_max_entries(16_384, 0);

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
        return queue_file_event(ctx, 1, &OPENAT_PENDING);
    }

    if flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND) != 0 {
        return queue_file_event(ctx, 4, &OPENAT_PENDING);
    }

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
    emit_pending_file_event(&OPENAT_PENDING, ret >= 0)
}

#[inline(always)]
unsafe fn try_handle_unlinkat(ctx: &TracePointContext) -> Result<u32, i64> {
    queue_file_event(ctx, 2, &UNLINKAT_PENDING)
}

#[inline(always)]
unsafe fn try_handle_unlinkat_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret: i64 = ctx.read_at::<i64>(16)?;
    emit_pending_file_event(&UNLINKAT_PENDING, ret == 0)
}

#[inline(always)]
unsafe fn try_handle_renameat(ctx: &TracePointContext) -> Result<u32, i64> {
    queue_rename_event(ctx, &RENAME_PENDING)
}

#[inline(always)]
unsafe fn try_handle_renameat_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret: i64 = ctx.read_at::<i64>(16)?;
    emit_pending_file_event(&RENAME_PENDING, ret == 0)
}

#[inline(always)]
unsafe fn try_handle_vfs_create(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    if OPENAT_PENDING.get(&tid).is_none() {
        return Ok(0);
    }

    let created: u8 = 1;
    let _ = OPENAT_CREATED.insert(&tid, &created, 0);
    Ok(0)
}

#[inline(always)]
unsafe fn queue_file_event(
    ctx: &TracePointContext,
    kind: u32,
    pending: &HashMap<u32, FileEvent>,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    // Read user-space pointer to the file path (offset 24 for both openat and unlinkat).
    let path_ptr: u64 = ctx.read_at::<u64>(24)?;
    if path_ptr == 0 {
        return Ok(0);
    }

    let mut path = [0u8; 96];
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let _ = bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut path);
    if path[0] == 0 {
        return Ok(0);
    }

    let pending_event = FileEvent {
        kind,
        pid,
        uid,
        _pad0: 0,
        path,
        aux_path: [0u8; 96],
        comm,
    };

    let _ = pending.insert(&tid, &pending_event, 0);
    Ok(0)
}

#[inline(always)]
unsafe fn queue_rename_event(
    ctx: &TracePointContext,
    pending: &HashMap<u32, FileEvent>,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let old_path_ptr: u64 = ctx.read_at::<u64>(24)?;
    let new_path_ptr: u64 = ctx.read_at::<u64>(40)?;
    if old_path_ptr == 0 || new_path_ptr == 0 {
        return Ok(0);
    }

    let mut path = [0u8; 96];
    let mut aux_path = [0u8; 96];
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let _ = bpf_probe_read_user_str_bytes(new_path_ptr as *const u8, &mut path);
    let _ = bpf_probe_read_user_str_bytes(old_path_ptr as *const u8, &mut aux_path);
    if path[0] == 0 || aux_path[0] == 0 {
        return Ok(0);
    }

    let pending_event = FileEvent {
        kind: 3,
        pid,
        uid,
        _pad0: 0,
        path,
        aux_path,
        comm,
    };

    let _ = pending.insert(&tid, &pending_event, 0);
    Ok(0)
}

#[inline(always)]
unsafe fn emit_pending_file_event(
    pending: &HashMap<u32, FileEvent>,
    should_emit: bool,
) -> Result<u32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let pending_event = pending.get(&tid).copied();
    let _ = pending.remove(&tid);

    if !should_emit {
        return Ok(0);
    }

    let Some(event) = pending_event else {
        return Ok(0);
    };

    if let Some(mut entry) = FILE_RING.reserve::<FileEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}
