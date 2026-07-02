//! Process exec eBPF program.
//!
//! Attaches to `sched/sched_process_exec`. Fires after `execve` succeeds —
//! the process image has been replaced and the new binary is about to run.
//! Also attaches to `sched/sched_process_exit` to emit cache-maintenance
//! stop events from the same ring buffer.
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

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_uid_gid, bpf_probe_read_kernel_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    EbpfContext,
};

use crate::events::ProcessEvent;

/// Ring buffer shared with the userspace loader for process events.
/// 512 KiB gives headroom for burst exec activity.
#[map]
pub static PROCESS_RING: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

const PROCESS_EVENT_EXEC: u32 = 1;
const PROCESS_EVENT_EXIT: u32 = 2;

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

#[inline(always)]
unsafe fn try_handle_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    // Read the new-process TGID from the tracepoint format.
    let pid: u32 = ctx.read_at::<u32>(12)?;

    let uid = bpf_get_current_uid_gid() as u32;

    // Read the __data_loc encoded value for `filename`.
    // Low 16 bits = byte offset of the string from ctx.as_ptr().
    // High 16 bits = string length (including null terminator).
    let data_loc: u32 = ctx.read_at::<u32>(8)?;
    let str_offset = (data_loc & 0xFFFF) as usize;
    let fname_ptr = (ctx.as_ptr() as usize + str_offset) as *const u8;

    // Read comm and image into local buffers, then copy into ring-buffer entry.
    // Keep buffers small enough to stay within the 512-byte BPF stack limit.
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let mut image = [0u8; 128];

    // Read null-terminated executable path from kernel tracepoint data.
    // Ignore errors — an empty image is still a useful process event.
    let _ = bpf_probe_read_kernel_str_bytes(fname_ptr, &mut image);

    if let Some(mut entry) = PROCESS_RING.reserve::<ProcessEvent>(0) {
        entry.write(ProcessEvent {
            kind: PROCESS_EVENT_EXEC,
            pid,
            uid,
            _pad: 0,
            comm,
            image,
        });
        entry.submit(0);
    }

    Ok(0)
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

    if let Some(mut entry) = PROCESS_RING.reserve::<ProcessEvent>(0) {
        entry.write(ProcessEvent {
            kind: PROCESS_EVENT_EXIT,
            pid,
            uid,
            _pad: 0,
            comm,
            image: [0u8; 128],
        });
        entry.submit(0);
    }

    Ok(0)
}
