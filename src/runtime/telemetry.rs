//! Runtime wiring for the pipeline drop counters.
//!
//! The counters themselves are always live; this is the piece that publishes
//! them outside the process so `rustinel doctor` can read them.

use std::path::PathBuf;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::alerts::{AlertSink, AlertWriterMetrics};
use crate::config::AppConfig;
use crate::telemetry::{snapshot_path, spawn_reporter, write_final_snapshot};

/// Background task publishing the pipeline counters for `rustinel doctor`.
pub struct TelemetryReporter {
    path: PathBuf,
    handle: JoinHandle<()>,
    alert_writer: AlertWriterMetrics,
}

impl TelemetryReporter {
    /// Start publishing, unless the operator turned persistence off.
    pub fn start(cfg: &AppConfig, alert_sink: &AlertSink) -> Option<Self> {
        if !cfg.telemetry.enabled {
            return None;
        }

        let path = snapshot_path(&cfg.logging.directory);
        let alert_writer = alert_sink.writer_metrics();
        let handle = spawn_reporter(
            path.clone(),
            Duration::from_secs(cfg.telemetry.snapshot_interval_secs),
            alert_writer.clone(),
        );
        Some(Self {
            path,
            handle,
            alert_writer,
        })
    }

    /// Stop publishing after one final write.
    ///
    /// The last interval's drops are the ones an operator is most likely to be
    /// asking about — an agent that shed events and then stopped — so the
    /// shutdown snapshot is written rather than left to a tick that never came.
    pub async fn finish(self) {
        self.handle.abort();
        let _ = self.handle.await;
        write_final_snapshot(&self.path, &self.alert_writer);
    }
}
