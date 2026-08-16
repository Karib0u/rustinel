//! Behavioral recording.
//!
//! Capture is the endpoint-behavior analogue of a packet capture: it records
//! the canonical normalized events Rustinel's event-based detectors consume,
//! not raw ETW/eBPF/ESF payloads and not alert output. A recording can be
//! re-evaluated later against a different detector configuration, on any
//! platform, without re-running the sample that produced it.
//!
//! A recording is two files: a streaming NDJSON payload with one
//! [`NormalizedEvent`](crate::models::NormalizedEvent) per line, and a
//! [`CaptureManifest`] sidecar recording what the payload contains and whether
//! it is trustworthy.
//!
//! Recordings describe endpoint activity in detail — command lines, file paths,
//! destinations, and user names — so they carry the same sensitivity, and the
//! same owner-only file permissions, as alert output.

pub mod manifest;
mod writer;

pub use manifest::{
    manifest_path_for, CaptureEventCounts, CaptureManifest, CaptureStatus, CAPTURE_SCHEMA_VERSION,
};
pub use writer::{CaptureRecorder, CaptureSink};
