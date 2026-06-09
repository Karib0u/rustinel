//! Alert sink for ECS NDJSON output.
//!
//! Writes ECS alerts as one JSON object per line, with optional sliding-window
//! deduplication that collapses repeated identical alerts into a single rollup
//! carrying `event.count`.

pub mod dedup;

use crate::models::ecs::EcsAlert;
use crate::models::Alert;
use std::io::Write;
use std::sync::Arc;
use tracing::error;
use tracing_appender::non_blocking::NonBlocking;

pub use dedup::Deduplicator;

#[derive(Clone)]
pub struct AlertSink {
    writer: NonBlocking,
    dedup: Option<Arc<Deduplicator>>,
}

impl AlertSink {
    pub fn new(writer: NonBlocking) -> Self {
        Self {
            writer,
            dedup: None,
        }
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
        match serde_json::to_string(ecs) {
            Ok(line) => {
                let mut writer = self.writer.clone();
                if let Err(err) = writeln!(writer, "{}", line) {
                    error!(error = %err, "Failed to write ECS alert");
                }
            }
            Err(err) => {
                error!(error = %err, "Failed to serialize ECS alert");
            }
        }
    }

    /// Write an alert, routing through dedup when enabled.
    pub fn write_alert(&self, alert: &Alert) {
        let ecs = EcsAlert::from(alert);

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
