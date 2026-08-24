//! Linux sensor support.

pub mod ebpf;
pub mod events;
pub mod paths;

pub use ebpf::EbpfSensor;

/// Environment variable that overrides the embedded eBPF object at runtime.
/// Set this to an absolute path to a compiled `.o` file during development to
/// avoid rebuilding the whole binary after every eBPF change.
pub const EBPF_OBJECT_ENV: &str = "RUSTINEL_EBPF_OBJECT";

/// eBPF object embedded at compile time by `build.rs`.
///
/// The object is included with the correct alignment for ELF parsing.
/// At runtime the loader falls back to this unless `RUSTINEL_EBPF_OBJECT`
/// is set.
pub static EBPF_BYTES: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rustinel-ebpf"));
