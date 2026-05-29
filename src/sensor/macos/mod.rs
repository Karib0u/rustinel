//! macOS sensor support.
//!
//! Telemetry on macOS comes from two native sources:
//!
//! - Endpoint Security ([`esf`]) for process and file events.
//! - `/dev/bpf` capture (later phase) for network and DNS.

pub mod bpf;
pub mod esf;
mod packet;
mod socket;

pub use bpf::BpfSensor;
pub use esf::EsfSensor;
