//! Alert sink for ECS NDJSON output.
//!
//! Writes ECS alerts as one JSON object per line, with optional fixed-window
//! deduplication that collapses repeated identical alerts into a single rollup
//! carrying `event.count` — the number of repeats it suppressed, so that the live
//! first occurrence is not counted twice.  See [`dedup`] for the full semantics.
//!
//! Every alert written to the file, rollups included, is also offered to the
//! configured [`webhook`] destinations.

pub mod dedup;
pub mod webhook;

use crate::identity::Identity;
use crate::models::ecs::EcsAlert;
use crate::models::{Alert, YaraScanSource};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info};
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking};

pub use dedup::Deduplicator;
pub use webhook::WebhookDispatcher;

#[derive(Clone)]
pub(crate) struct AlertWriterMetrics {
    dropped: ErrorCounter,
    offered: Arc<AtomicU64>,
}

impl AlertWriterMetrics {
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.dropped_lines() as u64
    }

    pub(crate) fn accepted(&self) -> u64 {
        self.offered
            .load(Ordering::Relaxed)
            .saturating_sub(self.dropped())
    }
}

#[derive(Clone)]
pub struct AlertSink {
    writer: NonBlocking,
    writer_metrics: AlertWriterMetrics,
    dedup: Option<Arc<Deduplicator>>,
    webhooks: Option<Arc<WebhookDispatcher>>,
    identity: Option<Arc<Identity>>,
}

/// An alert with the sink's host and agent identity merged in. Both outputs
/// serialize this one value, so NDJSON and webhooks carry identical fields.
#[derive(serde::Serialize)]
struct IdentifiedAlert<'a> {
    #[serde(flatten)]
    ecs: &'a EcsAlert,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    identity: Option<&'a Identity>,
}

impl AlertSink {
    pub fn new(writer: NonBlocking) -> Self {
        let writer_metrics = AlertWriterMetrics {
            dropped: writer.error_counter(),
            offered: Arc::new(AtomicU64::new(0)),
        };
        Self {
            writer,
            writer_metrics,
            dedup: None,
            webhooks: None,
            identity: None,
        }
    }

    pub(crate) fn writer_metrics(&self) -> AlertWriterMetrics {
        self.writer_metrics.clone()
    }

    /// Stamp every live alert, rollups included, with this host and agent
    /// identity. Replay never calls this, so replayed detections carry none.
    pub fn with_identity(mut self, identity: Arc<Identity>) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Attach webhook destinations.  Call before handing the sink to any
    /// handler, including the dedup flush worker, so rollups are delivered too.
    pub fn with_webhooks(mut self, webhooks: Arc<WebhookDispatcher>) -> Self {
        self.webhooks = Some(webhooks);
        self
    }

    /// Return the attached webhook dispatcher, if any.
    pub fn webhooks(&self) -> Option<&Arc<WebhookDispatcher>> {
        self.webhooks.as_ref()
    }

    /// Attach a deduplicator.  Call before handing the sink to any handler.
    pub fn with_deduplicator(mut self, dedup: Arc<Deduplicator>) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Return a reference to the attached deduplicator, if any.
    pub fn dedup(&self) -> Option<&Arc<Deduplicator>> {
        self.dedup.as_ref()
    }

    /// Write a raw ECS alert directly (bypasses dedup — used by the flush path).
    pub fn write_ecs(&self, ecs: &EcsAlert) {
        let identified = IdentifiedAlert {
            ecs,
            identity: self.identity.as_deref(),
        };
        match serde_json::to_string(&identified) {
            Ok(mut line) => {
                // NonBlocking queues every write() as its own message, so the
                // newline must travel in the same write as the object: with
                // writeln! two concurrent alerts can land as `{A}{B}\n\n`.
                line.push('\n');
                self.writer_metrics.offered.fetch_add(1, Ordering::Relaxed);
                let mut writer = self.writer.clone();
                let written = writer.write_all(line.as_bytes());
                // Webhook delivery is independent of the file: neither a file
                // error nor a delivery problem affects the other.
                if let Some(webhooks) = &self.webhooks {
                    webhooks.dispatch(&line.as_bytes()[..line.len() - 1]);
                }
                if let Err(err) = written {
                    error!(error = %err, "Failed to write ECS alert");
                    return;
                }
                info!(
                    target: "engine",
                    engine = %ecs.edr_rule_engine,
                    severity = %ecs.edr_rule_severity,
                    rule = %ecs.rule_name,
                    process = ecs.process_executable.as_deref(),
                    pid = ecs.process_pid,
                    file = ecs.file_path.as_deref(),
                    repeats = ecs.event_count,
                    "{}",
                    if ecs.event_count.is_some() {
                        "Detection repeats aggregated"
                    } else {
                        "Detection triggered"
                    }
                );
            }
            Err(err) => {
                error!(error = %err, "Failed to serialize ECS alert");
            }
        }
    }

    /// Write an alert, routing through dedup when enabled.
    pub fn write_alert(&self, alert: &Alert) {
        self.write_mapped_alert(alert, EcsAlert::from(alert));
    }

    /// Write a YARA alert with an explicit scan source. The source is output
    /// independently of match-debug detail and participates in deduplication.
    pub fn write_yara_alert(&self, alert: &Alert, source: YaraScanSource) {
        let mut ecs = EcsAlert::from(alert);
        ecs.edr_yara_scan_source = Some(source);
        self.write_mapped_alert(alert, ecs);
    }

    fn write_mapped_alert(&self, alert: &Alert, ecs: EcsAlert) {
        if let Some(dedup) = &self.dedup {
            if dedup.record(&ecs, alert) {
                // First occurrence — emit immediately.
                self.write_ecs(&ecs);
            }
            // Suppressed — dedup will emit a rollup at window close.
        } else {
            self.write_ecs(&ecs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AlertSeverity, DetectionEngine, NormalizedEvent};
    use crate::telemetry::TelemetrySnapshot;
    use std::sync::{mpsc, Barrier, Mutex};

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct SlowWriter {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        blocked: bool,
    }

    impl Write for SlowWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if !self.blocked {
                self.blocked = true;
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn saturated_alert_writer_appears_in_telemetry_snapshot() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(1)
            .finish(SlowWriter {
                started: started_tx,
                release: release_rx,
                blocked: false,
            });
        let sink = AlertSink::new(writer);
        let event: NormalizedEvent = serde_json::from_value(serde_json::json!({
            "timestamp": "2026-09-13T20:29:41Z",
            "platform": "linux",
            "provider": "ebpf",
            "category": "Process",
            "event_id": 1,
            "opcode": 1,
            "fields": { "Image": "/bin/true", "ProcessId": "3051" }
        }))
        .unwrap();
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "slow writer".into(),
            rule_description: None,
            rule_id: None,
            sigma_metadata: None,
            engine: DetectionEngine::Sigma,
            event,
            match_details: None,
        };

        sink.write_alert(&alert);
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        for _ in 0..9 {
            sink.write_alert(&alert);
        }

        let snapshot = TelemetrySnapshot::capture_with_alert_writer(
            &sink.writer_metrics(),
            &crate::telemetry::PipelineProbes::default(),
        );
        release_tx.send(()).unwrap();
        drop(sink);
        drop(guard);

        let channel = snapshot.channels.last().unwrap();
        assert_eq!(channel.channel, "alert_writer");
        assert_eq!(channel.dropped, 8);
        assert_eq!(channel.accepted, 2);
    }

    #[test]
    fn concurrent_writers_emit_one_alert_per_line() {
        const THREADS: usize = 4;
        const ALERTS_PER_THREAD: usize = 2_000;

        let output = SharedWriter(Arc::new(Mutex::new(Vec::new())));
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .finish(output.clone());
        let sink = AlertSink::new(writer);
        let event: NormalizedEvent = serde_json::from_value(serde_json::json!({
            "timestamp": "2026-09-13T20:29:41Z",
            "platform": "linux",
            "provider": "ebpf",
            "category": "Process",
            "event_id": 1,
            "opcode": 1,
            "fields": { "Image": "/tmp/rustinel_atomic_canary/canary-exec", "ProcessId": "3051" }
        }))
        .unwrap();
        let barrier = Arc::new(Barrier::new(THREADS));

        let handles: Vec<_> = [
            DetectionEngine::Sigma,
            DetectionEngine::Ioc,
            DetectionEngine::Yara,
            DetectionEngine::Sigma,
        ]
        .into_iter()
        .enumerate()
        .map(|(thread, engine)| {
            let sink = sink.clone();
            let barrier = Arc::clone(&barrier);
            let alert = Alert {
                severity: AlertSeverity::High,
                rule_name: format!("concurrent writer {thread}"),
                rule_description: None,
                rule_id: None,
                sigma_metadata: None,
                engine,
                event: event.clone(),
                match_details: None,
            };
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..ALERTS_PER_THREAD {
                    sink.write_alert(&alert);
                }
            })
        })
        .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        drop(sink);
        drop(guard);

        let json = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let mut per_thread = [0usize; THREADS];
        for line in json.lines() {
            let alert: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("unparsable NDJSON line ({err}): {line:?}"));
            let rule = alert["rule.name"].as_str().unwrap();
            let thread: usize = rule.rsplit(' ').next().unwrap().parse().unwrap();
            per_thread[thread] += 1;
        }
        assert_eq!(per_thread, [ALERTS_PER_THREAD; THREADS]);
    }
}
