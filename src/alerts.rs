//! Alert sink for ECS NDJSON output.
//!
//! Writes ECS alerts as one JSON object per line.

use crate::models::ecs::EcsAlert;
use crate::models::Alert;
use std::io::Write;
use tracing::error;
use tracing_appender::non_blocking::NonBlocking;

#[derive(Clone)]
pub struct AlertSink {
    writer: NonBlocking,
}

impl AlertSink {
    pub fn new(writer: NonBlocking) -> Self {
        Self { writer }
    }

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

    pub fn write_alert(&self, alert: &Alert) {
        let ecs = EcsAlert::from(alert);
        self.write_ecs(&ecs);
    }
}
