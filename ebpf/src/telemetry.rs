//! Kernel-side Linux eBPF pipeline counters.

use aya_ebpf::{macros::map, maps::PerCpuArray};

pub const PROCESS_FAMILY: u32 = 0;
pub const NETWORK_FAMILY: u32 = 1;
pub const FILE_FAMILY: u32 = 2;
pub const DNS_FAMILY: u32 = 3;
pub const FAMILY_COUNT: u32 = 4;

/// One CPU's cumulative counters for one ring family.
///
/// This layout is mirrored by the userspace loader.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelCounters {
    pub kernel_seen: u64,
    pub kernel_submitted: u64,
    pub kernel_ring_full: u64,
    pub kernel_oversized: u64,
    pub kernel_map_full: u64,
}

#[map]
pub static LINUX_EBPF_COUNTERS: PerCpuArray<KernelCounters> =
    PerCpuArray::with_max_entries(FAMILY_COUNT, 0);

#[inline(always)]
fn increment(value: *mut u64) {
    unsafe {
        *value = (*value).wrapping_add(1);
    }
}

#[inline(always)]
pub fn record_submitted(family: u32) {
    let Some(counters) = LINUX_EBPF_COUNTERS.get_ptr_mut(family) else {
        return;
    };
    unsafe {
        increment(&mut (*counters).kernel_seen);
        increment(&mut (*counters).kernel_submitted);
    }
}

#[inline(always)]
pub fn record_ring_full(family: u32) {
    let Some(counters) = LINUX_EBPF_COUNTERS.get_ptr_mut(family) else {
        return;
    };
    unsafe {
        increment(&mut (*counters).kernel_seen);
        increment(&mut (*counters).kernel_ring_full);
    }
}

#[allow(dead_code)]
#[inline(always)]
pub fn record_oversized(family: u32) {
    let Some(counters) = LINUX_EBPF_COUNTERS.get_ptr_mut(family) else {
        return;
    };
    unsafe {
        increment(&mut (*counters).kernel_seen);
        increment(&mut (*counters).kernel_oversized);
    }
}

#[inline(always)]
pub fn record_map_full(family: u32) {
    let Some(counters) = LINUX_EBPF_COUNTERS.get_ptr_mut(family) else {
        return;
    };
    unsafe {
        increment(&mut (*counters).kernel_map_full);
    }
}
