//! Process lifecycle eBPF programs.
//!
//! Attaches to `sched/sched_process_exec`. Fires after `execve` succeeds —
//! the process image has been replaced and the new binary is about to run.
//! `sched_process_fork` records parentage before reparenting can occur, and
//! `sched_process_exit` emits cache-maintenance stop events from the same ring.
//!
//! Command lines are captured in the kernel rather than read from
//! `/proc/<pid>/cmdline`, which a short-lived process can outrun. The argv
//! vector only exists in userspace memory while `execve` is still running, so
//! it is snapshotted at `syscalls/sys_enter_execve` (and `sys_enter_execveat`)
//! into [`ARGV_PENDING`], keyed by the calling thread, then attached to the
//! `sched_process_exec` event that follows. Failed `execve` calls leave a
//! pending entry behind; the map is LRU so those are evicted rather than
//! accumulating, and the next `execve` on the same thread overwrites the key
//! before it can be misattributed.
//!
//! sys_enter_execve tracepoint format (x86_64, 64-bit ABI):
//!   offset 16: filename            (u64  — user pointer to path string)
//!   offset 24: argv                (u64  — user pointer to char *const[])
//!   offset 32: envp                (u64)
//!
//! sys_enter_execveat tracepoint format (same structure):
//!   offset 16: fd                  (i64)
//!   offset 24: filename            (u64  — user pointer to path string)
//!   offset 32: argv                (u64  — user pointer to char *const[])
//!   offset 40: envp                (u64)
//!   offset 48: flags               (i64)

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};

use crate::events::{event_metadata, ProcessEvent, ARGV_CAPACITY, PROCESS_IMAGE_CAPACITY};
use crate::telemetry::{record_map_full, record_ring_full, record_submitted, PROCESS_FAMILY};

/// Loader-populated offsets for the process tracepoints used below.
///
/// Tracepoint layouts are not a stable ABI. Userspace parses each kernel's
/// format files, validates the required fields, and overrides this global
/// before any program is loaded.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessTracepointOffsets {
    pub exec_filename: u32,
    pub exec_pid: u32,
    pub exec_old_pid: u32,
    pub fork_parent_pid: u32,
    pub fork_child_pid: u32,
    pub clone_flags: u32,
    pub clone3_args: u32,
}

#[no_mangle]
pub static PROCESS_TRACEPOINT_OFFSETS: ProcessTracepointOffsets = ProcessTracepointOffsets {
    exec_filename: 0,
    exec_pid: 0,
    exec_old_pid: 0,
    fork_parent_pid: 0,
    fork_child_pid: 0,
    clone_flags: 0,
    clone3_args: 0,
};

/// Read a loader-patched global without letting LLVM fold its zero initializer
/// into the program instructions.
#[inline(always)]
unsafe fn tracepoint_offset(value: *const u32) -> usize {
    core::ptr::read_volatile(value) as usize
}

/// Ring buffer shared with the userspace loader for process events.
///
/// The 856-byte event leaves room for more than 2,400 queued events, including
/// the measured 1,600-event burst that motivated the image-path fallback.
#[map]
pub static PROCESS_RING: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

/// Current execution identity by thread-group ID.
#[map]
static PROCESS_START_TIMES: LruHashMap<u32, u64> = LruHashMap::with_max_entries(65_536, 0);

/// Fork-time relationship retained until process exit. The map is keyed by
/// child TGID for process creations. Thread creations are explicitly removed.
#[map]
static PROCESS_PARENTS: LruHashMap<u32, ForkRelationship> = LruHashMap::with_max_entries(65_536, 0);

/// Creation flags staged from the syscall entry until `sched_process_fork`.
#[map]
static CREATION_FLAGS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(4096, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct ForkRelationship {
    parent_start_time: u64,
    parent_pid: u32,
    creator_tid: u32,
    creator_tgid: u32,
    parent_pid_derived: u8,
    _pad: [u8; 3],
}

const CLONE_PARENT: u64 = 0x0000_8000;
const CLONE_THREAD: u64 = 0x0001_0000;

const PROCESS_EVENT_EXEC: u32 = 1;
const PROCESS_EVENT_EXIT: u32 = 2;

#[inline(always)]
pub unsafe fn current_process_start_time(pid: u32) -> u64 {
    PROCESS_START_TIMES.get(&pid).copied().unwrap_or(0)
}

/// Maximum bytes copied for a single argument, including its NUL terminator.
const ARGV_ARG_MAX: usize = 128;

/// Maximum number of argv entries walked. Bounds verifier complexity; argv
/// vectors longer than this are captured up to this point and flagged
/// truncated.
const ARGV_MAX_ARGS: usize = 32;

/// `argv` offset in the `sys_enter_execve` tracepoint record.
const EXECVE_ARGV_OFFSET: usize = 24;

/// `argv` offset in the `sys_enter_execveat` tracepoint record.
const EXECVEAT_ARGV_OFFSET: usize = 32;

/// Kernel-side argv snapshot, staged between `execve` entry and the
/// `sched_process_exec` that follows it.
#[repr(C)]
#[derive(Clone, Copy)]
struct ArgvSnapshot {
    /// Valid bytes in `args`.
    len: u16,
    /// Argv entries captured.
    count: u16,
    /// 1 when the argv vector did not fit the capture limits.
    truncated: u8,
    _pad: [u8; 3],
    /// NUL-separated argument bytes.
    args: [u8; ARGV_CAPACITY],
}

/// Per-CPU staging area. The snapshot is too large for the 512-byte BPF
/// stack, so it is built in map memory and then copied into the pending map.
#[map]
static ARGV_SCRATCH: PerCpuArray<ArgvSnapshot> = PerCpuArray::with_max_entries(1, 0);

/// Argv snapshots awaiting their `sched_process_exec`, keyed by the thread
/// that called `execve`. LRU so abandoned entries from failed execs age out.
#[map]
static ARGV_PENDING: LruHashMap<u32, ArgvSnapshot> = LruHashMap::with_max_entries(4096, 0);

/// Tracepoint handler for `sched/sched_process_exec`.
#[tracepoint]
pub fn handle_exec(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_exec(&ctx) }.unwrap_or(1)
}

/// Tracepoint handler for `sched/sched_process_exit`.
#[tracepoint]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_exit(&ctx) }.unwrap_or(1)
}

/// Tracepoint handler for `sched/sched_process_fork`.
#[tracepoint]
pub fn handle_fork(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_fork(&ctx) }.unwrap_or(1)
}

/// Stage the flags for legacy `clone(2)`.
#[tracepoint]
pub fn handle_clone(ctx: TracePointContext) -> u32 {
    unsafe { try_capture_clone_flags(&ctx) }.unwrap_or(1)
}

/// Stage the flags for `clone3(2)`.
#[tracepoint]
pub fn handle_clone3(ctx: TracePointContext) -> u32 {
    unsafe { try_capture_clone3_flags(&ctx) }.unwrap_or(1)
}

/// `fork(2)` always creates a new process with ordinary parent semantics.
#[tracepoint]
pub fn handle_process_fork(_ctx: TracePointContext) -> u32 {
    unsafe { stage_creation_flags(0) };
    0
}

/// `vfork(2)` uses ordinary parent semantics for attribution.
#[tracepoint]
pub fn handle_process_vfork(_ctx: TracePointContext) -> u32 {
    unsafe { stage_creation_flags(0) };
    0
}

/// Tracepoint handler for `syscalls/sys_enter_execve` — snapshots argv while
/// it is still mapped in the calling process.
#[tracepoint]
pub fn handle_execve(ctx: TracePointContext) -> u32 {
    unsafe { try_capture_argv(&ctx, EXECVE_ARGV_OFFSET) }.unwrap_or(1)
}

/// Tracepoint handler for `syscalls/sys_enter_execveat`.
#[tracepoint]
pub fn handle_execveat(ctx: TracePointContext) -> u32 {
    unsafe { try_capture_argv(&ctx, EXECVEAT_ARGV_OFFSET) }.unwrap_or(1)
}

#[inline(always)]
unsafe fn try_handle_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    // Read the new-process TGID from the tracepoint format.
    let pid: u32 = ctx.read_at::<u32>(tracepoint_offset(core::ptr::addr_of!(
        PROCESS_TRACEPOINT_OFFSETS.exec_pid
    )))?;
    // PID of the thread that called `execve`, before `de_thread` renamed it.
    let old_pid: u32 = ctx.read_at::<u32>(tracepoint_offset(core::ptr::addr_of!(
        PROCESS_TRACEPOINT_OFFSETS.exec_old_pid
    )))?;

    let uid = bpf_get_current_uid_gid() as u32;

    // Read the __data_loc encoded value for `filename`.
    // Low 16 bits = byte offset of the string from ctx.as_ptr().
    // High 16 bits = string length (including null terminator).
    let data_loc: u32 = ctx.read_at::<u32>(tracepoint_offset(core::ptr::addr_of!(
        PROCESS_TRACEPOINT_OFFSETS.exec_filename
    )))?;
    let str_offset = (data_loc & 0xFFFF) as usize;
    let str_len = (data_loc >> 16) as usize;
    let fname_ptr = (ctx.as_ptr() as usize + str_offset) as *const u8;

    // Read comm and image into local buffers, then copy into ring-buffer entry.
    // Keep buffers small enough to stay within the 512-byte BPF stack limit —
    // `args` is copied straight from map memory for the same reason.
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let mut image = [0u8; PROCESS_IMAGE_CAPACITY];

    // Read null-terminated executable path from kernel tracepoint data.
    // Ignore errors — an empty image is still a useful process event.
    let _ = bpf_probe_read_kernel_str_bytes(fname_ptr, &mut image);

    let (event_time_ns, source_seq) = event_metadata();
    let process_start_time = if PROCESS_START_TIMES.insert(&pid, &event_time_ns, 0).is_ok() {
        event_time_ns
    } else {
        let _ = PROCESS_START_TIMES.remove(&pid);
        record_map_full(PROCESS_FAMILY);
        0
    };
    let Some(mut entry) = PROCESS_RING.reserve::<ProcessEvent>(0) else {
        record_ring_full(PROCESS_FAMILY);
        return Ok(0);
    };
    let event = entry.as_mut_ptr();

    (*event).event_time_ns = event_time_ns;
    (*event).source_seq = source_seq;
    (*event).cgroup_id = bpf_get_current_cgroup_id();
    (*event).process_start_time = process_start_time;
    (*event).kind = PROCESS_EVENT_EXEC;
    (*event).pid = pid;
    (*event).uid = uid;
    attach_fork_relationship(event, pid);
    (*event).comm = comm;
    (*event).image = image;
    (*event).image_truncated = (str_len > image.len()) as u8;
    (*event)._pad1 = 0;

    attach_pending_argv(event, old_pid);

    entry.submit(0);
    record_submitted(PROCESS_FAMILY);

    Ok(0)
}

#[inline(always)]
unsafe fn attach_fork_relationship(event: *mut ProcessEvent, pid: u32) {
    let Some(relationship) = PROCESS_PARENTS.get(&pid) else {
        (*event).parent_process_start_time = 0;
        (*event).parent_pid = 0;
        (*event).creator_tid = 0;
        (*event).creator_tgid = 0;
        (*event).parent_pid_derived = 0;
        return;
    };

    (*event).parent_process_start_time = relationship.parent_start_time;
    (*event).parent_pid = relationship.parent_pid;
    (*event).creator_tid = relationship.creator_tid;
    (*event).creator_tgid = relationship.creator_tgid;
    (*event).parent_pid_derived = relationship.parent_pid_derived;
}

#[inline(always)]
unsafe fn try_handle_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    let trace_parent_tid = ctx.read_at::<u32>(tracepoint_offset(core::ptr::addr_of!(
        PROCESS_TRACEPOINT_OFFSETS.fork_parent_pid
    )))?;
    let child_tid = ctx.read_at::<u32>(tracepoint_offset(core::ptr::addr_of!(
        PROCESS_TRACEPOINT_OFFSETS.fork_child_pid
    )))?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let creator_tgid = (pid_tgid >> 32) as u32;
    let creator_tid = pid_tgid as u32;

    if child_tid == 0 || creator_tgid == 0 || trace_parent_tid != creator_tid {
        return Ok(0);
    }

    let flags = CREATION_FLAGS.get(&creator_tid).copied().unwrap_or(0);
    let _ = CREATION_FLAGS.remove(&creator_tid);

    if flags & CLONE_THREAD != 0 {
        // A new task in the same thread group is not a process parent edge.
        // Remove a stale PID-reuse entry instead of letting it reach exec.
        let _ = PROCESS_PARENTS.remove(&child_tid);
        return Ok(0);
    }

    let relationship = ForkRelationship {
        parent_start_time: current_process_start_time(creator_tgid),
        // `parent_pid` in the tracepoint is the creator TID. The helper gives
        // us both identities, so process parentage uses the creator TGID.
        // CLONE_PARENT cannot be resolved with stable helpers. In that case
        // this is explicitly an approximation and userspace marks it Derived.
        parent_pid: creator_tgid,
        creator_tid,
        creator_tgid,
        parent_pid_derived: ((flags & CLONE_PARENT) != 0) as u8,
        _pad: [0u8; 3],
    };
    if PROCESS_PARENTS
        .insert(&child_tid, &relationship, 0)
        .is_err()
    {
        record_map_full(PROCESS_FAMILY);
    }
    Ok(0)
}

#[inline(always)]
unsafe fn try_capture_clone_flags(ctx: &TracePointContext) -> Result<u32, i64> {
    let flags = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        PROCESS_TRACEPOINT_OFFSETS.clone_flags
    )))?;
    stage_creation_flags(flags);
    Ok(0)
}

#[inline(always)]
unsafe fn try_capture_clone3_flags(ctx: &TracePointContext) -> Result<u32, i64> {
    let args = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        PROCESS_TRACEPOINT_OFFSETS.clone3_args
    )))?;
    let flags = if args == 0 {
        0
    } else {
        bpf_probe_read_user::<u64>(args as *const u64)?
    };
    stage_creation_flags(flags);
    Ok(0)
}

#[inline(always)]
unsafe fn stage_creation_flags(flags: u64) {
    let creator_tid = bpf_get_current_pid_tgid() as u32;
    if CREATION_FLAGS.insert(&creator_tid, &flags, 0).is_err() {
        record_map_full(PROCESS_FAMILY);
    }
}

/// Move the argv captured at `execve` entry into the outgoing event.
///
/// The snapshot is keyed by the thread that entered `execve`. For a
/// single-threaded exec that thread is the one running now, so
/// `bpf_get_current_pid_tgid` finds it. When a non-leader thread execs,
/// `de_thread` has already given it the group leader's PID by the time this
/// tracepoint fires, and the original TID is only available as the
/// tracepoint's `old_pid`.
#[inline(always)]
unsafe fn attach_pending_argv(event: *mut ProcessEvent, old_pid: u32) {
    let tid = bpf_get_current_pid_tgid() as u32;
    let mut pending = ARGV_PENDING.get(&tid);
    let mut key = tid;
    if pending.is_none() && old_pid != tid {
        pending = ARGV_PENDING.get(&old_pid);
        key = old_pid;
    }

    let Some(snapshot) = pending else {
        // No kernel capture. Userspace leaves CommandLine absent.
        (*event).args_len = 0;
        (*event).args_count = 0;
        (*event).args_truncated = 0;
        return;
    };

    (*event).args_len = snapshot.len;
    (*event).args_count = snapshot.count;
    (*event).args_truncated = snapshot.truncated;
    (*event).args = snapshot.args;

    let _ = ARGV_PENDING.remove(&key);
}

#[inline(always)]
unsafe fn try_capture_argv(ctx: &TracePointContext, argv_offset: usize) -> Result<u32, i64> {
    let argv: u64 = ctx.read_at::<u64>(argv_offset)?;

    let Some(scratch) = ARGV_SCRATCH.get_ptr_mut(0) else {
        return Ok(0);
    };
    (*scratch).len = 0;
    (*scratch).count = 0;
    (*scratch).truncated = 0;
    (*scratch)._pad = [0u8; 3];
    (*scratch).args = [0u8; ARGV_CAPACITY];

    if argv != 0 {
        read_argv(scratch, argv as *const *const u8);
    }

    // Insert unconditionally, even when nothing was captured: an empty entry
    // still overwrites any snapshot left behind by an earlier failed `execve`
    // on this thread, so a later exec can never pick up stale argv.
    let tid = bpf_get_current_pid_tgid() as u32;
    if ARGV_PENDING.insert(&tid, &*scratch, 0).is_err() {
        record_map_full(PROCESS_FAMILY);
    }

    Ok(0)
}

/// Walk the userspace argv vector into `scratch`, NUL-separating entries.
///
/// Stops at the argv terminator, at [`ARGV_MAX_ARGS`] entries, or when the
/// next argument no longer fits [`ARGV_CAPACITY`], flagging `truncated` in
/// the latter two cases.
#[inline(always)]
unsafe fn read_argv(scratch: *mut ArgvSnapshot, argv: *const *const u8) {
    let mut offset: usize = 0;
    let mut count: u16 = 0;

    for index in 0..ARGV_MAX_ARGS {
        let Ok(arg_ptr) = bpf_probe_read_user::<*const u8>(argv.add(index)) else {
            break;
        };

        if arg_ptr.is_null() {
            // Argv terminator: the whole vector fit.
            (*scratch).len = offset as u16;
            (*scratch).count = count;
            return;
        }

        if offset + ARGV_ARG_MAX >= ARGV_CAPACITY {
            break;
        }
        // Redundant with the bound above, but it gives the verifier a hard
        // ceiling on the destination offset without tracking the loop state.
        let base = offset & (ARGV_CAPACITY - ARGV_ARG_MAX - 1);

        let dest =
            core::slice::from_raw_parts_mut((*scratch).args.as_mut_ptr().add(base), ARGV_ARG_MAX);
        let Ok(written) = bpf_probe_read_user_str_bytes(arg_ptr, dest) else {
            break;
        };

        // `bpf_probe_read_user_str` silently truncates an over-long argument
        // to the buffer size, NUL included, so a full buffer means the
        // argument was cut. Preserve that fidelity signal on the event.
        if written.len() >= ARGV_ARG_MAX - 1 {
            (*scratch).truncated = 1;
        }

        // `bpf_probe_read_user_str` writes the NUL; keep it as the separator.
        offset = base + written.len() + 1;
        count += 1;
    }

    (*scratch).len = offset as u16;
    (*scratch).count = count;
    (*scratch).truncated = 1;
}

#[inline(always)]
unsafe fn try_handle_exit(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // `sched_process_exit` fires for individual threads. Emit a process-stop
    // event only for the thread-group leader so shared ProcessCache eviction
    // tracks processes rather than worker-thread churn.
    if pid == 0 || pid != tid {
        return Ok(0);
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let process_start_time = current_process_start_time(pid);

    let Some(mut entry) = PROCESS_RING.reserve::<ProcessEvent>(0) else {
        let _ = PROCESS_START_TIMES.remove(&pid);
        let _ = PROCESS_PARENTS.remove(&pid);
        record_ring_full(PROCESS_FAMILY);
        return Ok(0);
    };
    let event = entry.as_mut_ptr();
    let (event_time_ns, source_seq) = event_metadata();

    (*event).event_time_ns = event_time_ns;
    (*event).source_seq = source_seq;
    (*event).cgroup_id = bpf_get_current_cgroup_id();
    (*event).process_start_time = process_start_time;
    (*event).parent_process_start_time = 0;
    (*event).kind = PROCESS_EVENT_EXIT;
    (*event).pid = pid;
    (*event).uid = uid;
    (*event).parent_pid = 0;
    (*event).creator_tid = 0;
    (*event).creator_tgid = 0;
    (*event).comm = comm;
    (*event).image = [0u8; PROCESS_IMAGE_CAPACITY];
    (*event).args_len = 0;
    (*event).args_count = 0;
    (*event).args_truncated = 0;
    (*event).image_truncated = 0;
    (*event).parent_pid_derived = 0;
    (*event)._pad1 = 0;

    entry.submit(0);
    let _ = PROCESS_START_TIMES.remove(&pid);
    let _ = PROCESS_PARENTS.remove(&pid);
    record_submitted(PROCESS_FAMILY);

    Ok(0)
}
