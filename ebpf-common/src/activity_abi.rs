//! Layouts for the bounded Linux activity counters.

pub const PROCESS_ACTIVITY_CAPACITY: u32 = 4096;
pub const IO_URING_ACTIVITY_INDEX: u32 = 0;
pub const IA32_FILE_ACTIVITY_INDEX: u32 = 1;
pub const ACTIVITY_SOURCE_COUNT: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActivityOffsets {
    pub io_uring_sq_thread: u32,
    pub ia32_status: u32,
    pub syscall_id: u32,
    pub syscall_ret: u32,
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

const _: () = assert!(core::mem::size_of::<ActivityOffsets>() == 16);
const _: () = assert!(core::mem::size_of::<ActivityProcessKey>() == 16);
const _: () = assert!(core::mem::size_of::<ActivityLoss>() == 16);

#[cfg(feature = "aya")]
crate::impl_pod!(ActivityOffsets, ActivityProcessKey, ActivityLoss);

#[inline(always)]
pub fn ia32_successful_exit(status: u32, result: i64) -> bool {
    // x86 thread_info.status TS_COMPAT, set until syscall exit work finishes.
    result >= 0 && status & 0x0002 != 0
}

#[inline(always)]
pub fn ia32_file_syscall(id: i64) -> bool {
    // i386 syscall table: legacy open/creat/unlink/rename/mkdir/rmdir and
    // the corresponding *at operations (openat2 and renameat2 included).
    matches!(id, 5 | 8 | 10 | 38..=40 | 295 | 296 | 301 | 302 | 353 | 437)
}
