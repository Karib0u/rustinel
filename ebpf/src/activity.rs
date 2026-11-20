//! Count activity separately from path-bearing file events.

use core::intrinsics::{atomic_xadd, AtomicOrdering};

use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::TracePointContext,
};
use rustinel_ebpf_common::activity_abi::{
    ia32_file_syscall, ia32_successful_exit, ActivityLoss, ActivityOffsets, ActivityProcessKey,
    ACTIVITY_SOURCE_COUNT, IA32_FILE_ACTIVITY_INDEX, IO_URING_ACTIVITY_INDEX,
    PROCESS_ACTIVITY_CAPACITY,
};

use crate::process::current_process_start_time;

#[no_mangle]
pub static ACTIVITY_OFFSETS: ActivityOffsets = ActivityOffsets {
    io_uring_sq_thread: 0,
    ia32_status: 0,
    syscall_id: 0,
    syscall_ret: 0,
};

#[map]
static IO_URING_ACTIVITY: HashMap<ActivityProcessKey, u64> =
    HashMap::with_max_entries(PROCESS_ACTIVITY_CAPACITY, 0);

#[map]
static IA32_FILE_ACTIVITY: HashMap<ActivityProcessKey, u64> =
    HashMap::with_max_entries(PROCESS_ACTIVITY_CAPACITY, 0);

#[map]
static ACTIVITY_LOSS: PerCpuArray<ActivityLoss> =
    PerCpuArray::with_max_entries(ACTIVITY_SOURCE_COUNT, 0);

#[tracepoint]
pub fn handle_io_uring_submit(ctx: TracePointContext) -> u32 {
    let offset = unsafe { core::ptr::read_volatile(&ACTIVITY_OFFSETS.io_uring_sq_thread) } as usize;
    // SQPOLL executes in a kernel thread, which may serve more than one ring.
    // Count those requests without claiming an owning process.
    if unsafe { ctx.read_at::<u8>(offset) } != Ok(0) {
        record_unattributed(IO_URING_ACTIVITY_INDEX);
    } else {
        count_current_process(&IO_URING_ACTIVITY, IO_URING_ACTIVITY_INDEX);
    }
    0
}

#[tracepoint]
pub fn handle_ia32_file_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_count_ia32_file_exit(&ctx) }.unwrap_or(0)
}

#[inline(always)]
unsafe fn try_count_ia32_file_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let id_offset = core::ptr::read_volatile(&ACTIVITY_OFFSETS.syscall_id) as usize;
    let ret_offset = core::ptr::read_volatile(&ACTIVITY_OFFSETS.syscall_ret) as usize;
    if !ia32_file_syscall(ctx.read_at::<i64>(id_offset)?) {
        return Ok(0);
    }

    let ret = ctx.read_at::<i64>(ret_offset)?;
    let task = bpf_get_current_task();
    let status_offset = core::ptr::read_volatile(&ACTIVITY_OFFSETS.ia32_status);
    let status =
        bpf_probe_read_kernel::<u32>(task.wrapping_add(status_offset as u64) as *const u32)
            .map_err(|error| error as i64)?;
    if ia32_successful_exit(status, ret) {
        count_current_process(&IA32_FILE_ACTIVITY, IA32_FILE_ACTIVITY_INDEX);
    }
    Ok(0)
}

#[inline(always)]
fn record_unattributed(index: u32) {
    if let Some(loss) = ACTIVITY_LOSS.get_ptr_mut(index) {
        unsafe { (*loss).unattributed = (*loss).unattributed.wrapping_add(1) };
    }
}

#[inline(always)]
fn count_current_process(map: &HashMap<ActivityProcessKey, u64>, index: u32) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let process_start_time = unsafe { current_process_start_time(pid) };
    if pid == 0 || process_start_time == 0 {
        record_unattributed(index);
        return;
    }
    let key = ActivityProcessKey {
        pid,
        _pad: 0,
        process_start_time,
    };
    if let Some(count) = map.get_ptr_mut(&key) {
        unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(count, 1) };
    } else if map.insert(&key, &1, BPF_NOEXIST as u64).is_err() {
        // Another thread in the same process may have inserted the key.
        if let Some(count) = map.get_ptr_mut(&key) {
            unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(count, 1) };
        } else if let Some(loss) = ACTIVITY_LOSS.get_ptr_mut(index) {
            unsafe { (*loss).map_full = (*loss).map_full.wrapping_add(1) };
        }
    }
}
