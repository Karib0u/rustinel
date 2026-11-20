//! Layouts for the bounded Linux activity counters.

pub const PROCESS_ACTIVITY_CAPACITY: u32 = 4096;
pub const IO_URING_ACTIVITY_INDEX: u32 = 0;
pub const ACTIVITY_SOURCE_COUNT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActivityOffsets {
    pub io_uring_sq_thread: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActivityProcessKey {
    pub pid: u32,
    pub _pad: u32,
    pub process_start_time: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActivityLoss {
    pub unattributed: u64,
    pub map_full: u64,
}

const _: () = assert!(core::mem::size_of::<ActivityOffsets>() == 4);
const _: () = assert!(core::mem::size_of::<ActivityProcessKey>() == 16);
const _: () = assert!(core::mem::size_of::<ActivityLoss>() == 16);

#[cfg(feature = "aya")]
crate::impl_pod!(ActivityOffsets, ActivityProcessKey, ActivityLoss);
