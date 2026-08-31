//! Opening and verifying a behavioral recording.
//!
//! Replay reads a recording written by `rustinel capture` on any host, so it
//! cannot assume the file is intact or that this build understands it. Every
//! recording is checked before a single event is evaluated: the manifest must
//! describe this payload, use a schema version this build knows, report a clean
//! capture session, and match the payload's checksum. A recording that fails any
//! of those is rejected with the reason, never partially replayed.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use sha2::{Digest, Sha256};

use crate::capture::{manifest_path_for, CaptureManifest, CaptureStatus, CAPTURE_SCHEMA_VERSION};
use crate::models::NormalizedEvent;

/// Bytes read per checksum pass over the payload.
const CHECKSUM_CHUNK_BYTES: usize = 64 * 1024;

/// A verified recording, ready to replay.
#[derive(Debug)]
pub struct Recording {
    payload_path: PathBuf,
    manifest_path: PathBuf,
    manifest: CaptureManifest,
}

impl Recording {
    /// Open the recording at `payload_path` and verify it end to end.
    pub fn open(payload_path: &Path) -> anyhow::Result<Self> {
        if !payload_path.exists() {
            bail!("recording not found: {}", payload_path.display());
        }

        let manifest_path = manifest_path_for(payload_path);
        if !manifest_path.exists() {
            bail!(
                "recording {} has no manifest at {}; a recording is the payload and its manifest \
                 sidecar, so copy both",
                payload_path.display(),
                manifest_path.display()
            );
        }

        let body = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read manifest {}", manifest_path.display()))?;
        let manifest: CaptureManifest = serde_json::from_str(&body)
            .with_context(|| format!("failed to parse manifest {}", manifest_path.display()))?;

        verify(payload_path, &manifest_path, &manifest)?;

        Ok(Self {
            payload_path: payload_path.to_path_buf(),
            manifest_path,
            manifest,
        })
    }

    pub fn payload_path(&self) -> &Path {
        &self.payload_path
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn manifest(&self) -> &CaptureManifest {
        &self.manifest
    }

    /// Stream the recorded events in the order they were captured.
    ///
    /// The payload is not loaded into memory: a recording of a long session can
    /// be much larger than the host has RAM for.
    pub fn events(&self) -> anyhow::Result<RecordedEvents> {
        let file = File::open(&self.payload_path)
            .with_context(|| format!("failed to open recording {}", self.payload_path.display()))?;
        Ok(RecordedEvents {
            lines: BufReader::new(file).lines(),
            payload_path: self.payload_path.clone(),
            line_number: 0,
        })
    }
}

/// Iterator over the normalized events in a recording payload.
pub struct RecordedEvents {
    lines: std::io::Lines<BufReader<File>>,
    payload_path: PathBuf,
    line_number: u64,
}

impl Iterator for RecordedEvents {
    type Item = anyhow::Result<NormalizedEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = match self.lines.next()? {
                Ok(line) => line,
                Err(err) => {
                    return Some(Err(anyhow::Error::new(err)
                        .context(format!("failed to read {}", self.payload_path.display()))))
                }
            };
            self.line_number += 1;

            if line.trim().is_empty() {
                continue;
            }

            // The checksum already proved the payload is byte-for-byte what
            // capture wrote, so a line that will not parse is a real defect
            // rather than a damaged file. Name the line so it can be found.
            return Some(serde_json::from_str(&line).with_context(|| {
                format!(
                    "failed to parse event on line {} of {}",
                    self.line_number,
                    self.payload_path.display()
                )
            }));
        }
    }
}

fn verify(
    payload_path: &Path,
    manifest_path: &Path,
    manifest: &CaptureManifest,
) -> anyhow::Result<()> {
    if manifest.schema_version != CAPTURE_SCHEMA_VERSION {
        bail!(
            "recording {} uses capture schema version {}, and this build of Rustinel \
             (v{}) understands version {}; replay it with a Rustinel version that \
             matches the recording",
            payload_path.display(),
            manifest.schema_version,
            env!("CARGO_PKG_VERSION"),
            CAPTURE_SCHEMA_VERSION
        );
    }

    let payload_name = payload_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if manifest.payload != payload_name {
        bail!(
            "manifest {} describes the recording '{}', not '{}'; the payload and its manifest \
             have been separated or renamed",
            manifest_path.display(),
            manifest.payload,
            payload_name
        );
    }

    if manifest.status != CaptureStatus::Complete {
        bail!(
            "recording {} is incomplete: the capture session was interrupted or lost {} of {} \
             events, so replaying it would report detections over a stream with holes in it",
            payload_path.display(),
            manifest.events.lost,
            manifest.events.received
        );
    }

    let Some(expected) = manifest.payload_sha256.as_deref() else {
        bail!(
            "recording {} was finalized without a checksum and cannot be verified",
            payload_path.display()
        );
    };

    let actual = checksum(payload_path)?;
    if actual != expected {
        bail!(
            "recording {} does not match its manifest checksum (expected {}, found {}); it has \
             been modified or truncated since capture, or copied through something that \
             rewrote its line endings — move recordings as binary files",
            payload_path.display(),
            expected,
            actual
        );
    }

    Ok(())
}

fn checksum(payload_path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(payload_path)
        .with_context(|| format!("failed to open recording {}", payload_path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHECKSUM_CHUNK_BYTES];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read recording {}", payload_path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureEventCounts, CaptureRecorder};
    use crate::models::{EventCategory, EventFields, NormalizedEvent, ProcessCreationFields};
    use crate::sensor::Platform;

    fn process_event(pid: &str) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: "2026-08-16T10:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                command_line: Some("cmd.exe /c whoami".to_string()),
                process_id: Some(pid.to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        }
    }

    /// Write a complete two-event recording and return its payload path.
    async fn complete_recording(directory: &Path) -> PathBuf {
        let payload = directory.join("session.ndjson");
        let recorder =
            CaptureRecorder::start(payload.clone(), Platform::Windows).expect("capture starts");
        let sink = recorder.sink();
        sink.record(&process_event("100"));
        sink.record(&process_event("200"));
        drop(sink);
        recorder.finish().await.expect("capture finalizes");
        payload
    }

    fn rewrite_manifest(payload: &Path, edit: impl FnOnce(&mut CaptureManifest)) {
        let path = manifest_path_for(payload);
        let mut manifest: CaptureManifest =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("manifest exists"))
                .expect("manifest parses");
        edit(&mut manifest);
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&manifest).expect("manifest serializes"),
        )
        .expect("manifest rewritten");
    }

    #[tokio::test]
    async fn a_complete_recording_replays_its_events_in_order() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = complete_recording(temp.path()).await;

        let recording = Recording::open(&payload).expect("recording opens");
        let events: Vec<NormalizedEvent> = recording
            .events()
            .expect("payload opens")
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("events parse");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].get_field("ProcessId"), Some("100"));
        assert_eq!(events[1].get_field("ProcessId"), Some("200"));
        assert_eq!(recording.manifest().platform, Platform::Windows);
    }

    #[tokio::test]
    async fn an_incomplete_recording_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = complete_recording(temp.path()).await;
        rewrite_manifest(&payload, |manifest| {
            manifest.status = CaptureStatus::Incomplete;
            manifest.events = CaptureEventCounts {
                received: 3,
                written: 2,
                lost: 1,
            };
        });

        let err = Recording::open(&payload).expect_err("incomplete recordings are rejected");
        assert!(err.to_string().contains("incomplete"), "{err}");
    }

    #[tokio::test]
    async fn a_modified_payload_fails_the_checksum() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = complete_recording(temp.path()).await;
        let mut body = std::fs::read_to_string(&payload).expect("payload exists");
        body = body.replace("whoami", "whoareyou");
        std::fs::write(&payload, body).expect("payload rewritten");

        let err = Recording::open(&payload).expect_err("a modified recording is rejected");
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    #[tokio::test]
    async fn an_unsupported_schema_version_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = complete_recording(temp.path()).await;
        rewrite_manifest(&payload, |manifest| {
            manifest.schema_version = CAPTURE_SCHEMA_VERSION + 1;
        });

        let err = Recording::open(&payload).expect_err("unknown schema versions are rejected");
        assert!(err.to_string().contains("schema version"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_manifest_is_reported_with_the_path_it_looked_for() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = complete_recording(temp.path()).await;
        std::fs::remove_file(manifest_path_for(&payload)).expect("manifest removed");

        let err =
            Recording::open(&payload).expect_err("a recording without a manifest is rejected");
        assert!(err.to_string().contains("session.manifest.json"), "{err}");
    }

    #[test]
    fn a_missing_recording_is_reported_by_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("absent.ndjson");

        let err = Recording::open(&missing).expect_err("a missing recording is rejected");
        assert!(err.to_string().contains("absent.ndjson"), "{err}");
    }
}
