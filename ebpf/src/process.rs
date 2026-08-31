//! Process exec eBPF program.
//!
//! Attaches to `sched/sched_process_exec`. Fires after `execve` succeeds —
//! the process image has been replaced and the new binary is about to run.
//! Also attaches to `sched/sched_process_exit` to emit cache-maintenance
//! stop events from the same ring buffer.
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
//! sched_process_exec tracepoint format (from kernel trace event headers):
//!   offset  0: common_type         (u16)
//!   offset  2: common_flags        (u8)
//!   offset  3: common_preempt_count(u8)
//!   offset  4: common_pid          (i32)  — scheduling PID (may be a thread)
//!   offset  8: __data_loc filename (u32)  — encoded: low16 = str offset, high16 = len
//!   offset 12: pid                 (i32)  — TGID of the new process
//!   offset 16: old_pid             (i32)  — previous TGID (thread that called exec)
//!   offset 20+: variable string data
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
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};

use crate::events::{ProcessEvent, ARGV_CAPACITY};

/// Ring buffer shared with the userspace loader for process events.
///
/// 2 MiB: carrying argv grew `ProcessEvent` from 160 to 680 bytes, so the
/// previous 512 KiB held roughly a quarter as many events. Sizing up keeps
/// the same burst headroom in *events*, which is what a `reserve` failure —
/// a silently dropped process event — actually depends on.
#[map]
pub static PROCESS_RING: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

const PROCESS_EVENT_EXEC: u32 = 1;
const PROCESS_EVENT_EXIT: u32 = 2;

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
    let pid: u32 = ctx.read_at::<u32>(12)?;
    // PID of the thread that called `execve`, before `de_thread` renamed it.
    let old_pid: u32 = ctx.read_at::<u32>(16)?;

    let uid = bpf_get_current_uid_gid() as u32;

    // Read the __data_loc encoded value for `filename`.
    // Low 16 bits = byte offset of the string from ctx.as_ptr().
    // High 16 bits = string length (including null terminator).
    let data_loc: u32 = ctx.read_at::<u32>(8)?;
    let str_offset = (data_loc & 0xFFFF) as usize;
    let fname_ptr = (ctx.as_ptr() as usize + str_offset) as *const u8;

    // Read comm and image into local buffers, then copy into ring-buffer entry.
    // Keep buffers small enough to stay within the 512-byte BPF stack limit —
    // `args` is copied straight from map memory for the same reason.
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let mut image = [0u8; 128];

    // Read null-terminated executable path from kernel tracepoint data.
    // Ignore errors — an empty image is still a useful process event.
    let _ = bpf_probe_read_kernel_str_bytes(fname_ptr, &mut image);

    let Some(mut entry) = PROCESS_RING.reserve::<ProcessEvent>(0) else {
        return Ok(0);
    };
    let event = entry.as_mut_ptr();

    (*event).kind = PROCESS_EVENT_EXEC;
    (*event).pid = pid;
    (*event).uid = uid;
    (*event)._pad = 0;
    (*event).comm = comm;
    (*event).image = image;
    (*event)._pad1 = [0u8; 3];

    attach_pending_argv(event, old_pid);

    entry.submit(0);

    Ok(0)
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
        // No kernel capture — userspace falls back to `/proc/<pid>/cmdline`.
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
    let _ = ARGV_PENDING.insert(&tid, &*scratch, 0);

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

        if offset + ARGV_ARG_MAX > ARGV_CAPACITY {
            break;
        }
        // Redundant with the bound above, but it gives the verifier a hard
        // ceiling on the destination offset without tracking the loop state.
        let base = offset & (ARGV_CAPACITY - 1);

        let dest =
            core::slice::from_raw_parts_mut((*scratch).args.as_mut_ptr().add(base), ARGV_ARG_MAX);
        let Ok(written) = bpf_probe_read_user_str_bytes(arg_ptr, dest) else {
            break;
        };

        // `bpf_probe_read_user_str` silently truncates an over-long argument
        // to the buffer size, NUL included, so a full buffer means the
        // argument was cut. Flag it — userspace prefers `/proc` over an
        // incomplete kernel capture.
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

    let Some(mut entry) = PROCESS_RING.reserve::<ProcessEvent>(0) else {
        return Ok(0);
    };
    let event = entry.as_mut_ptr();

    (*event).kind = PROCESS_EVENT_EXIT;
    (*event).pid = pid;
    (*event).uid = uid;
    (*event)._pad = 0;
    (*event).comm = comm;
    (*event).image = [0u8; 128];
    (*event).args_len = 0;
    (*event).args_count = 0;
    (*event).args_truncated = 0;
    (*event)._pad1 = [0u8; 3];

    entry.submit(0);

    Ok(0)
}
