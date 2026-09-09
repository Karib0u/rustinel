//! Runtime BTF read plans and measured process identity, shared with userspace.

pub const FIELD_COUNT: usize = 10;
pub const MAX_STEPS: usize = 6;
pub const START_BOOTTIME: usize = 0;
pub const EUID: usize = 1;
pub const EGID: usize = 2;
pub const MOUNT_NS: usize = 3;
pub const PID_NS: usize = 4;
pub const NET_NS: usize = 5;
pub const SESSION_ID: usize = 6;
pub const TTY_MAJOR: usize = 7;
pub const TTY_MINOR: usize = 8;
pub const TTY_INDEX: usize = 9;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReadStep {
    pub offset: u32,
    /// Nonzero stride selects pid.numbers[pid.level], for the active namespace.
    pub stride: u32,
    pub level_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReadPlan {
    /// Zero disables this field. Every other step dereferences a pointer;
    /// the final step reads a scalar of the field's specified width.
    pub len: u32,
    pub steps: [ReadStep; MAX_STEPS],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TaskIdentity {
    pub values: [u64; FIELD_COUNT],
    /// A zero value is valid (especially effective root) only with this bit set.
    pub valid: u32,
    pub real_gid: u32,
}

/// Startup inventory identity is accepted only after kernel birth-time matching.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InventoryIdentity {
    pub start_ticks: u64,
    pub clock_ticks_per_second: u64,
    pub identity_time: u64,
}

pub const INVENTORY_CAPACITY: u32 = 8192;
