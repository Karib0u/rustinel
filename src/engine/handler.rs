//! Sigma detection event handler
//!
//! Implements the EventHandler trait to process ETW events
//! through the Sigma detection engine.

use crate::alerts::AlertSink;
use crate::collector::EventHandler;
use crate::engine::Engine;
use crate::models::EventCategory;
use crate::normalizer::Normalizer;
use ferrisetw::EventRecord;
use std::sync::Arc;
use tracing::{debug, info};

/// Target name for engine operational logs
const TARGET_ENGINE: &str = "engine";

/// Sigma detection handler that normalizes events and checks them against Sigma rules
pub struct SigmaDetectionHandler {
    /// Normalizer for converting ETW events to Sysmon-compatible format
    pub normalizer: Arc<Normalizer>,
    /// Sigma detection engine
    pub engine: Arc<Engine>,
    /// ECS NDJSON alert sink
    pub alert_sink: AlertSink,
}

impl EventHandler for SigmaDetectionHandler {
    fn handle_event(&self, record: &EventRecord, category: EventCategory) {
        // Debug: Log that we received an event (moved to DEBUG level)
        tracing::debug!(
            target: TARGET_ENGINE,
            category = ?category,
            provider = ?record.provider_id(),
            event_id = record.event_id(),
            opcode = record.opcode(),
            "Event received"
        );

        // Normalize the event
        match self.normalizer.normalize(record, category) {
            Some(normalized_event) => {
                tracing::debug!(target: TARGET_ENGINE, "Event normalized successfully");

                // Debug: Show normalized event (OPTIMIZED: only serialize if TRACE is enabled)
                if tracing::enabled!(tracing::Level::TRACE) {
                    if let Ok(json) = serde_json::to_string(&normalized_event) {
                        tracing::trace!(target: TARGET_ENGINE, normalized_json = %json, "Normalized event");
                    }
                }

                // Check against Sigma rules
                if let Some(alert) = self.engine.check_event(&normalized_event) {
                    // 1. Operational Log (Text) - For debugging and monitoring
                    info!(
                        target: TARGET_ENGINE,
                        rule = %alert.rule_name,
                        severity = ?alert.severity,
                        category = ?alert.event.category,
                        "Sigma detection triggered"
                    );

                    // 2. Security Alert (ECS NDJSON) - For SIEM ingestion
                    self.alert_sink.write_alert(&alert);
                } else {
                    // No match - moved to TRACE level (most verbose)
                    tracing::trace!(target: TARGET_ENGINE, "No Sigma rule matched this event");
                }
            }
            None => {
                if category == EventCategory::Process && record.opcode() == 2 {
                    tracing::debug!(
                        target: TARGET_ENGINE,
                        "Process stop event processed for cache maintenance"
                    );
                    return;
                }

                // Failed normalization - only log in debug mode
                debug!(
                    target: TARGET_ENGINE,
                    event_id = record.event_id(),
                    opcode = record.opcode(),
                    "Failed to normalize event"
                );
            }
        }
    }
}
