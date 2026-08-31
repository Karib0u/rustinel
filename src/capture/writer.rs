//! Capture sink and NDJSON payload writer.
//!
//! [`CaptureSink`] sits at the post-normalization boundary of the shared event
//! pipeline: it is handed each canonical [`NormalizedEvent`] before alert-only
//! enrichment or any detector evaluation, so a recording reflects what the
//! sensors observed rather than what detection made of it.
//!
//! Serialization happens on the calling thread and the resulting line is handed
//! to a background writer through a bounded queue. When that queue is full the
//! event is counted as lost and the recording is finalized as
//! [`CaptureStatus::Incomplete`] — capture never silently discards an event.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::capture::manifest::{
    manifest_path_for, CaptureEventCounts, CaptureManifest, CaptureStatus,
};
use crate::models::NormalizedEvent;
use crate::sensor::Platform;
use crate::utils::fs::{restrict_directory_permissions, restrict_file_permissions};
use crate::utils::{now_timestamp_string, LogRateLimiter};

/// Target name for capture operational logs.
const TARGET_CAPTURE: &str = "capture";

/// Queue depth between the normalization boundary and the writer task. Deep
/// enough to absorb sensor bursts, bounded so a stalled disk cannot grow memory
/// without limit.
const QUEUE_CAPACITY: usize = 16_384;

/// Events buffered before the payload is flushed. Bounds how much of the tail
/// a killed process can lose, and keeps the file readable with standard tools
/// while the session is still running.
const FLUSH_INTERVAL_EVENTS: u64 = 512;

/// Minimum spacing between loss warnings, so a saturated queue cannot flood the
/// operational log.
const LOSS_LOG_WINDOW: Duration = Duration::from_secs(10);

/// Event accounting shared between the sink and the writer task.
#[derive(Debug, Default)]
struct CaptureCounters {
    received: AtomicU64,
    written: AtomicU64,
    lost: AtomicU64,
}

impl CaptureCounters {
    fn snapshot(&self) -> CaptureEventCounts {
        CaptureEventCounts {
            received: self.received.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            lost: self.lost.load(Ordering::Relaxed),
        }
    }
}

/// Handle used by the event pipeline to record normalized events.
///
/// Cloning is cheap; every clone feeds the same recording.
#[derive(Clone)]
pub struct CaptureSink {
    tx: mpsc::Sender<String>,
    counters: Arc<CaptureCounters>,
    loss_log: Arc<Mutex<LogRateLimiter>>,
}

impl CaptureSink {
    /// Record one normalized event into the payload.
    ///
    /// Never blocks the caller: the event is either queued for the writer or
    /// counted as lost.
    pub fn record(&self, event: &NormalizedEvent) {
        self.counters.received.fetch_add(1, Ordering::Relaxed);

        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                self.count_loss("serialize", &err.to_string());
                return;
            }
        };

        if let Err(err) =
            crate::telemetry::try_send(crate::telemetry::ChannelId::CaptureWriter, &self.tx, line)
        {
            let reason = match err {
                mpsc::error::TrySendError::Full(_) => "queue full",
                mpsc::error::TrySendError::Closed(_) => "writer stopped",
            };
            self.count_loss("enqueue", reason);
        }
    }

    /// Current event accounting for the session.
    pub fn counts(&self) -> CaptureEventCounts {
        self.counters.snapshot()
    }

    fn count_loss(&self, stage: &str, reason: &str) {
        let lost = self.counters.lost.fetch_add(1, Ordering::Relaxed) + 1;

        let decision = match self.loss_log.lock() {
            Ok(mut limiter) => limiter.should_emit(stage),
            // A poisoned limiter must not silence the loss report.
            Err(poisoned) => poisoned.into_inner().should_emit(stage),
        };
        if decision.should_emit {
            warn!(
                target: TARGET_CAPTURE,
                stage,
                reason,
                lost_total = lost,
                suppressed_warnings = decision.suppressed_since_last_emit,
                "Capture lost an event; the recording will be marked incomplete"
            );
        }
    }
}

/// An open capture session: the NDJSON payload, its manifest, and the
/// background task writing to them.
pub struct CaptureRecorder {
    sink: CaptureSink,
    payload_path: PathBuf,
    manifest_path: PathBuf,
    manifest: CaptureManifest,
    counters: Arc<CaptureCounters>,
    /// Held so the writer keeps running; dropped by [`Self::finish`] to signal
    /// shutdown.
    tx: Option<mpsc::Sender<String>>,
    worker: JoinHandle<PayloadDigest>,
    /// Set for loss the sink cannot observe, such as a sensor dying mid-session.
    forced_incomplete: Arc<AtomicBool>,
}

/// What the writer task observed about the payload it produced.
struct PayloadDigest {
    bytes: u64,
    sha256: String,
    write_failed: bool,
}

impl CaptureRecorder {
    /// Open a capture session writing to `payload_path`.
    ///
    /// Creates the parent directory when needed, restricts the recording to the
    /// owner, and writes an initial manifest marked
    /// [`CaptureStatus::Incomplete`] so an interrupted session is never
    /// mistaken for a finished one.
    ///
    /// Must be called from within a Tokio runtime.
    pub fn start(payload_path: PathBuf, platform: Platform) -> anyhow::Result<Self> {
        let manifest_path = manifest_path_for(&payload_path);
        let file = create_payload_file(&payload_path)?;

        let manifest = CaptureManifest::started(&payload_path, platform, now_timestamp_string());
        write_manifest(&manifest_path, &manifest)?;

        let counters = Arc::new(CaptureCounters::default());
        let (tx, rx) = mpsc::channel::<String>(QUEUE_CAPACITY);
        let worker_counters = Arc::clone(&counters);
        let worker_path = payload_path.clone();
        let worker = tokio::task::spawn_blocking(move || {
            write_payload(rx, file, worker_counters, worker_path)
        });

        info!(
            target: TARGET_CAPTURE,
            payload = %payload_path.display(),
            manifest = %manifest_path.display(),
            "Capture session started"
        );

        Ok(Self {
            sink: CaptureSink {
                tx: tx.clone(),
                counters: Arc::clone(&counters),
                loss_log: Arc::new(Mutex::new(LogRateLimiter::new(LOSS_LOG_WINDOW))),
            },
            payload_path,
            manifest_path,
            manifest,
            counters,
            tx: Some(tx),
            worker,
            forced_incomplete: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Mark the recording as incomplete for a reason the sink cannot see.
    ///
    /// Event loss inside the capture pipeline is already counted, but a sensor
    /// that stops feeding events produces a recording that looks lossless while
    /// missing everything after the failure.
    pub fn mark_incomplete(&self, reason: &str) {
        if !self.forced_incomplete.swap(true, Ordering::Relaxed) {
            warn!(
                target: TARGET_CAPTURE,
                reason,
                "Recording will be marked incomplete"
            );
        }
    }

    /// Sink handle for the event pipeline.
    pub fn sink(&self) -> CaptureSink {
        self.sink.clone()
    }

    /// Path of the NDJSON payload.
    pub fn payload_path(&self) -> &Path {
        &self.payload_path
    }

    /// Path of the manifest sidecar.
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Current event accounting, for progress reporting.
    pub fn counts(&self) -> CaptureEventCounts {
        self.counters.snapshot()
    }

    /// Drain queued events, flush the payload, and finalize the manifest.
    ///
    /// The recording is marked [`CaptureStatus::Complete`] only when every
    /// received event reached the payload.
    pub async fn finish(mut self) -> anyhow::Result<CaptureManifest> {
        // Dropping every sender ends the writer loop once the queue drains.
        drop(self.tx.take());
        drop(self.sink);

        let digest = self
            .worker
            .await
            .context("capture writer task failed to complete")?;

        let events = self.counters.snapshot();
        let status = if events.lost == 0
            && !digest.write_failed
            && !self.forced_incomplete.load(Ordering::Relaxed)
        {
            CaptureStatus::Complete
        } else {
            CaptureStatus::Incomplete
        };

        self.manifest.ended_at = Some(now_timestamp_string());
        self.manifest.status = status;
        self.manifest.events = events;
        self.manifest.payload_bytes = digest.bytes;
        self.manifest.payload_sha256 = Some(digest.sha256);
        write_manifest(&self.manifest_path, &self.manifest)?;

        Ok(self.manifest)
    }
}

fn create_payload_file(payload_path: &Path) -> anyhow::Result<File> {
    if let Some(directory) = payload_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
    {
        std::fs::create_dir_all(directory).with_context(|| {
            format!("failed to create capture directory {}", directory.display())
        })?;
        if let Err(err) = restrict_directory_permissions(directory) {
            warn!(
                target: TARGET_CAPTURE,
                directory = %directory.display(),
                error = %err,
                "Unable to restrict capture directory permissions"
            );
        }
    }

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(payload_path)
        .with_context(|| format!("failed to create recording {}", payload_path.display()))?;

    restrict_file_permissions(payload_path).with_context(|| {
        format!(
            "failed to restrict permissions on recording {}",
            payload_path.display()
        )
    })?;

    Ok(file)
}

fn write_manifest(manifest_path: &Path, manifest: &CaptureManifest) -> anyhow::Result<()> {
    let body = serde_json::to_string_pretty(manifest).context("failed to serialize manifest")?;
    std::fs::write(manifest_path, format!("{body}\n"))
        .with_context(|| format!("failed to write manifest {}", manifest_path.display()))?;
    restrict_file_permissions(manifest_path).with_context(|| {
        format!(
            "failed to restrict permissions on manifest {}",
            manifest_path.display()
        )
    })?;
    Ok(())
}

/// Writer loop: one JSON object per line, hashing the payload as it goes so the
/// manifest checksum never requires a second pass over the file.
fn write_payload(
    mut rx: mpsc::Receiver<String>,
    file: File,
    counters: Arc<CaptureCounters>,
    payload_path: PathBuf,
) -> PayloadDigest {
    let mut writer = BufWriter::new(file);
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut since_flush = 0u64;
    let mut write_failed = false;

    while let Some(line) = rx.blocking_recv() {
        let mut record = line.into_bytes();
        record.push(b'\n');

        match writer.write_all(&record) {
            Ok(()) => {
                hasher.update(&record);
                bytes += record.len() as u64;
                counters.written.fetch_add(1, Ordering::Relaxed);
                since_flush += 1;
            }
            Err(err) => {
                counters.lost.fetch_add(1, Ordering::Relaxed);
                if !write_failed {
                    warn!(
                        target: TARGET_CAPTURE,
                        payload = %payload_path.display(),
                        error = %err,
                        "Failed to write to the recording; it will be marked incomplete"
                    );
                }
                write_failed = true;
            }
        }

        if since_flush >= FLUSH_INTERVAL_EVENTS {
            since_flush = 0;
            if let Err(err) = writer.flush() {
                warn!(
                    target: TARGET_CAPTURE,
                    payload = %payload_path.display(),
                    error = %err,
                    "Failed to flush the recording"
                );
                write_failed = true;
            }
        }
    }

    if let Err(err) = writer.flush() {
        warn!(
            target: TARGET_CAPTURE,
            payload = %payload_path.display(),
            error = %err,
            "Failed to flush the recording at shutdown"
        );
        write_failed = true;
    }

    PayloadDigest {
        bytes,
        sha256: hex::encode(hasher.finalize()),
        write_failed,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::models::{EventCategory, EventFields, ProcessCreationFields};

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

    fn read_manifest(path: &Path) -> CaptureManifest {
        let body = std::fs::read_to_string(path).expect("manifest exists");
        serde_json::from_str(&body).expect("manifest parses")
    }

    #[tokio::test]
    async fn records_every_event_in_order() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = temp.path().join("session.ndjson");
        let recorder =
            CaptureRecorder::start(payload.clone(), Platform::Windows).expect("capture starts");
        let sink = recorder.sink();

        for pid in ["100", "200", "100"] {
            sink.record(&process_event(pid));
        }
        drop(sink);

        let manifest = recorder.finish().await.expect("capture finalizes");

        let body = std::fs::read_to_string(&payload).expect("payload exists");
        let pids: Vec<String> = body
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).expect("line parses");
                value["fields"]["ProcessId"]
                    .as_str()
                    .expect("ProcessId present")
                    .to_string()
            })
            .collect();

        // Repeated events are kept: capture does not deduplicate.
        assert_eq!(pids, vec!["100", "200", "100"]);
        assert_eq!(
            manifest.events,
            CaptureEventCounts {
                received: 3,
                written: 3,
                lost: 0,
            }
        );
        assert_eq!(manifest.status, CaptureStatus::Complete);
    }

    #[tokio::test]
    async fn finalized_manifest_describes_the_payload() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = temp.path().join("session.ndjson");
        let recorder =
            CaptureRecorder::start(payload.clone(), Platform::Windows).expect("capture starts");
        let manifest_path = recorder.manifest_path().to_path_buf();
        recorder.sink().record(&process_event("100"));

        let manifest = recorder.finish().await.expect("capture finalizes");
        let persisted = read_manifest(&manifest_path);

        let body = std::fs::read(&payload).expect("payload exists");
        assert_eq!(manifest.payload, "session.ndjson");
        assert_eq!(manifest.payload_bytes, body.len() as u64);
        assert_eq!(
            manifest.payload_sha256.as_deref(),
            Some(hex::encode(Sha256::digest(&body)).as_str())
        );
        assert_eq!(manifest.platform, Platform::Windows);
        assert_eq!(manifest.rustinel_version, env!("CARGO_PKG_VERSION"));
        assert!(manifest.ended_at.is_some());
        assert!(manifest.is_replayable());
        assert_eq!(persisted, manifest);
    }

    #[tokio::test]
    async fn a_session_in_progress_is_marked_incomplete_on_disk() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = temp.path().join("session.ndjson");
        let recorder = CaptureRecorder::start(payload, Platform::Linux).expect("capture starts");
        let manifest_path = recorder.manifest_path().to_path_buf();
        recorder.sink().record(&process_event("100"));

        // The state a killed process would leave behind: the manifest exists,
        // but nothing has finalized it.
        let manifest = read_manifest(&manifest_path);
        assert_eq!(manifest.status, CaptureStatus::Incomplete);
        assert!(manifest.payload_sha256.is_none());
        assert!(manifest.ended_at.is_none());
        assert!(!manifest.is_replayable());

        recorder.finish().await.expect("capture finalizes");
    }

    #[tokio::test]
    async fn lost_events_are_counted_and_mark_the_recording_incomplete() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = temp.path().join("session.ndjson");
        let recorder = CaptureRecorder::start(payload, Platform::Linux).expect("capture starts");
        let sink = recorder.sink();

        // A closed queue stands in for a writer that can no longer accept
        // events; the sink must account for the loss rather than ignore it.
        let saturated = CaptureSink {
            tx: mpsc::channel::<String>(1).0,
            counters: Arc::clone(&sink.counters),
            loss_log: Arc::clone(&sink.loss_log),
        };
        drop(sink);
        saturated.record(&process_event("100"));
        let counts = saturated.counts();
        drop(saturated);

        assert_eq!(counts.received, 1);
        assert_eq!(counts.lost, 1);

        let manifest = recorder.finish().await.expect("capture finalizes");
        assert_eq!(manifest.status, CaptureStatus::Incomplete);
        assert_eq!(
            manifest.events.received,
            manifest.events.written + manifest.events.lost
        );
        assert!(!manifest.is_replayable());
    }

    #[tokio::test]
    async fn generic_events_are_recorded_alongside_typed_ones() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = temp.path().join("session.ndjson");
        let recorder =
            CaptureRecorder::start(payload.clone(), Platform::MacOS).expect("capture starts");
        let sink = recorder.sink();

        let mut generic = process_event("100");
        generic.category = EventCategory::Process;
        generic.fields = EventFields::Generic(HashMap::from([(
            "Image".to_string(),
            "/bin/zsh".to_string(),
        )]));
        sink.record(&generic);
        drop(sink);

        recorder.finish().await.expect("capture finalizes");

        let body = std::fs::read_to_string(&payload).expect("payload exists");
        assert_eq!(body.lines().count(), 1);
        assert!(body.contains("/bin/zsh"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recording_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let payload = temp.path().join("nested").join("session.ndjson");
        let recorder =
            CaptureRecorder::start(payload.clone(), Platform::MacOS).expect("capture starts");
        let manifest_path = recorder.manifest_path().to_path_buf();
        recorder.finish().await.expect("capture finalizes");

        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&payload), 0o600);
        assert_eq!(mode(&manifest_path), 0o600);
        assert_eq!(mode(payload.parent().expect("parent")), 0o700);
    }
}
