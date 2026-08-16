//! Behavioral-recording manifest.
//!
//! Every recording is a pair: the NDJSON payload holding one canonical
//! [`NormalizedEvent`](crate::models::NormalizedEvent) per line, and this
//! sidecar describing what the payload contains and whether it can be trusted.
//!
//! The manifest is written twice. Once when the capture session opens, marked
//! [`CaptureStatus::Incomplete`] so a recording left behind by a killed process
//! is never mistaken for a finished one, and once at clean shutdown with the
//! final counters and payload checksum.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::sensor::Platform;

/// Version of the recording format: the manifest layout together with the
/// NDJSON event schema it describes. Consumers reject versions they do not
/// understand rather than guessing at unknown fields.
pub const CAPTURE_SCHEMA_VERSION: u32 = 1;

/// Suffix appended to the payload stem to derive the manifest path.
const MANIFEST_EXTENSION: &str = "manifest.json";

/// Whether a recording covers the whole capture session.
///
/// Only [`CaptureStatus::Complete`] recordings carry every event the sensors
/// produced. Anything else means the stream has holes, whether from an
/// interrupted session or from events the writer could not keep up with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    /// The session ended cleanly and no event was lost.
    Complete,
    /// The session was interrupted, or events were lost while writing.
    Incomplete,
}

impl CaptureStatus {
    pub fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Per-session event accounting.
///
/// `received` always equals `written + lost`: every event handed to the capture
/// sink is accounted for, so loss can never hide behind a plausible-looking
/// count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureEventCounts {
    /// Normalized events handed to the capture sink.
    pub received: u64,
    /// Events serialized and written to the payload.
    pub written: u64,
    /// Events dropped because the queue was full, or that failed to serialize
    /// or write.
    pub lost: u64,
}

/// Sidecar describing a behavioral recording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureManifest {
    /// Recording format version; see [`CAPTURE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// File name of the NDJSON payload this manifest describes.
    pub payload: String,
    /// Rustinel version that produced the recording.
    pub rustinel_version: String,
    /// Platform whose sensors produced the events.
    pub platform: Platform,
    /// RFC 3339 timestamp of when capture started.
    pub started_at: String,
    /// RFC 3339 timestamp of when capture was finalized; absent while running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// Whether the recording covers the whole session.
    pub status: CaptureStatus,
    /// Event accounting for the session.
    pub events: CaptureEventCounts,
    /// Payload size in bytes at finalization.
    pub payload_bytes: u64,
    /// SHA-256 of the payload, present once the recording is finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
}

impl CaptureManifest {
    /// Build the manifest for a session that has just started.
    pub fn started(payload_path: &Path, platform: Platform, started_at: String) -> Self {
        Self {
            schema_version: CAPTURE_SCHEMA_VERSION,
            payload: payload_file_name(payload_path),
            rustinel_version: env!("CARGO_PKG_VERSION").to_string(),
            platform,
            started_at,
            ended_at: None,
            status: CaptureStatus::Incomplete,
            events: CaptureEventCounts::default(),
            payload_bytes: 0,
            payload_sha256: None,
        }
    }

    /// Whether this manifest describes a recording a consumer can trust in
    /// full: a known schema version, a clean finish, and a payload checksum to
    /// verify against.
    pub fn is_replayable(&self) -> bool {
        self.schema_version == CAPTURE_SCHEMA_VERSION
            && self.status.is_complete()
            && self.payload_sha256.is_some()
    }
}

/// Manifest path for a payload: the payload path with its extension replaced by
/// `manifest.json`, so `capture.ndjson` is described by `capture.manifest.json`.
pub fn manifest_path_for(payload_path: &Path) -> PathBuf {
    payload_path.with_extension(MANIFEST_EXTENSION)
}

fn payload_file_name(payload_path: &Path) -> String {
    payload_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_path_replaces_the_payload_extension() {
        assert_eq!(
            manifest_path_for(Path::new("/captures/session.ndjson")),
            PathBuf::from("/captures/session.manifest.json")
        );
    }

    #[test]
    fn manifest_path_appends_when_the_payload_has_no_extension() {
        assert_eq!(
            manifest_path_for(Path::new("/captures/session")),
            PathBuf::from("/captures/session.manifest.json")
        );
    }

    #[test]
    fn a_started_manifest_is_not_replayable() {
        let manifest = CaptureManifest::started(
            Path::new("/captures/session.ndjson"),
            Platform::Linux,
            "2026-08-16T10:00:00Z".to_string(),
        );

        assert_eq!(manifest.payload, "session.ndjson");
        assert_eq!(manifest.status, CaptureStatus::Incomplete);
        assert!(!manifest.is_replayable());
    }

    #[test]
    fn a_finalized_manifest_round_trips_through_json() {
        let mut manifest = CaptureManifest::started(
            Path::new("session.ndjson"),
            Platform::Windows,
            "2026-08-16T10:00:00Z".to_string(),
        );
        manifest.ended_at = Some("2026-08-16T10:05:00Z".to_string());
        manifest.status = CaptureStatus::Complete;
        manifest.events = CaptureEventCounts {
            received: 3,
            written: 3,
            lost: 0,
        };
        manifest.payload_bytes = 128;
        manifest.payload_sha256 = Some("abc123".to_string());

        let json = serde_json::to_string(&manifest).expect("manifest serializes");
        let parsed: CaptureManifest = serde_json::from_str(&json).expect("manifest deserializes");

        assert_eq!(parsed, manifest);
        assert!(parsed.is_replayable());
    }

    #[test]
    fn a_recording_from_a_future_schema_is_not_replayable() {
        let mut manifest = CaptureManifest::started(
            Path::new("session.ndjson"),
            Platform::MacOS,
            "2026-08-16T10:00:00Z".to_string(),
        );
        manifest.status = CaptureStatus::Complete;
        manifest.payload_sha256 = Some("abc123".to_string());
        manifest.schema_version = CAPTURE_SCHEMA_VERSION + 1;

        assert!(!manifest.is_replayable());
    }
}
