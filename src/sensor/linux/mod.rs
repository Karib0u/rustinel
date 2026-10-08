//! Linux sensor support.

pub(crate) mod abi;
pub mod ebpf;
pub mod events;
mod inventory;
pub mod paths;
pub mod task_btf;
pub(crate) mod telemetry;
mod tracepoint_format;

pub use ebpf::EbpfSensor;
pub(crate) use paths::LinuxHostExtension;
pub use rustinel_ebpf_common::{file_identity_abi, socket_tuple_abi};

/// Environment variable that overrides the embedded eBPF object at runtime.
/// Set this to an absolute path to a compiled `.o` file during development to
/// avoid rebuilding the whole binary after every eBPF change.
pub const EBPF_OBJECT_ENV: &str = "RUSTINEL_EBPF_OBJECT";

/// How `build.rs` chose the embedded object: `prebuilt`, `source`, or `stub`.
///
/// A `stub` has no programs and the sensor refuses to start with it.
pub const EBPF_OBJECT_SOURCE: &str = env!("RUSTINEL_EBPF_SOURCE");

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../build/ebpf_select.rs"]
mod ebpf_select;

/// eBPF object embedded at compile time by `build.rs`.
///
/// The object is included with the correct alignment for ELF parsing.
/// At runtime the loader falls back to this unless `RUSTINEL_EBPF_OBJECT`
/// is set.
pub static EBPF_BYTES: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rustinel-ebpf"));
