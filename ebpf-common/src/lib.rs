//! Kernel/userspace ABI of the Linux eBPF sensor, declared once.
//!
//! Both the eBPF programs (`ebpf/`) and the agent depend on this crate, so a
//! `repr(C)` event type or runtime layout has exactly one definition and the
//! two sides cannot drift apart. The crate is `no_std` so it builds for the
//! `bpfel-unknown-none` target.

#![no_std]

pub mod events;
pub mod file_identity_abi;
pub mod socket_tuple_abi;
pub mod task_identity_abi;

/// Marks plain-data ABI structs as `aya::Pod`.
///
/// # Safety
///
/// Every listed type must be `repr(C)`, made only of fixed-width integers and
/// arrays of them, and have no padding bytes, so that every bit pattern is a
/// valid value. The layout asserts next to each type pin the sizes.
#[cfg(feature = "aya")]
macro_rules! impl_pod {
    ($($ty:ty),+ $(,)?) => {
        $(
            // SAFETY: see the macro documentation; each type is repr(C) and made
            // only of fixed-width integers with no padding.
            unsafe impl aya::Pod for $ty {}
        )+
    };
}
#[cfg(feature = "aya")]
pub(crate) use impl_pod;
