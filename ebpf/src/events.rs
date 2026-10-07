//! Kernel-side event helpers. The event types themselves live in
//! `rustinel-ebpf-common`, shared with the userspace decoder.

pub use rustinel_ebpf_common::events::*;

use core::intrinsics::{atomic_xadd, AtomicOrdering};

use aya_ebpf::helpers::bpf_ktime_get_boot_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;

#[map]
static SOURCE_SEQUENCE: Array<u64> = Array::with_max_entries(1, 0);

/// Timestamp and global submission order assigned immediately before an event
/// enters a ring buffer.
#[inline(always)]
pub fn event_metadata() -> (u64, u64) {
    let event_time_ns = unsafe { bpf_ktime_get_boot_ns() };
    let source_seq = unsafe {
        let Some(value) = SOURCE_SEQUENCE.get_ptr_mut(0) else {
            return (event_time_ns, 0);
        };
        atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(value, 1) + 1
    };
    (event_time_ns, source_seq)
}
