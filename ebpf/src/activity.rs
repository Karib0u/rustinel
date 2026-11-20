//! Count activity separately from path-bearing file events.

use core::intrinsics::{atomic_xadd, AtomicOrdering};

use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::TracePointContext,
};
use rustinel_ebpf_common::activity_abi::{
    ActivityLoss, ActivityOffsets, ActivityProcessKey, ACTIVITY_SOURCE_COUNT,
    IO_URING_ACTIVITY_INDEX, PROCESS_ACTIVITY_CAPACITY,
};

use crate::process::current_process_start_time;

#[no_mangle]
pub static ACTIVITY_OFFSETS: ActivityOffsets = ActivityOffsets {
    io_uring_sq_thread: 0,
};

#[map]
static IO_URING_ACTIVITY: HashMap<ActivityProcessKey, u64> =
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
