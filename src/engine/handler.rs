//! Normalized-event handler: the shared boundary between sensors and everything
//! downstream of normalization.
//!
//! Sensor events are normalized exactly once here. What happens next depends on
//! how the handler is configured: live protection evaluates the normalized
//! event against the detectors, and capture records it. Both read the same
//! canonical event from the same stateful [`Normalizer`], so a recording
//! contains precisely what live detection would have seen.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::debug;

use crate::alerts::AlertSink;
use crate::capture::CaptureSink;
use crate::engine::{DetectorStore, EventDetectors};
use crate::normalizer::Normalizer;
use crate::response::ResponseEngine;
use crate::sensor::{SensorAction, SensorEvent, SensorEventHandler};

/// Target name for engine operational logs.
const TARGET_ENGINE: &str = "engine";

/// Detection side of the pipeline: rule evaluation, alerting, and response.
pub struct DetectionPipeline {
    /// Live detector store (sigma/ioc hot-reloaded atomically).
    pub detectors: Arc<DetectorStore>,
    /// Hash worker channel (optional).
    pub ioc_hash_tx: Option<mpsc::Sender<(String, u32)>>,
    /// ECS NDJSON alert sink.
    pub alert_sink: AlertSink,
    /// Active response engine.
    pub response_engine: ResponseEngine,
}

/// Handler that normalizes sensor events and dispatches them to capture,
/// detection, or both.
pub struct NormalizedEventHandler {
    /// Normalizer for converting sensor events to the normalized event model.
    pub normalizer: Arc<Normalizer>,
    /// Behavioral recording sink. Fed immediately after normalization, before
    /// alert-only enrichment or any detector evaluation.
    pub capture: Option<CaptureSink>,
    /// Detection pipeline. Absent when the session only records, which is what
    /// keeps capture from evaluating rules or invoking active response.
    pub detection: Option<DetectionPipeline>,
}

impl NormalizedEventHandler {
    /// Live protection: evaluate every normalized event against the detectors.
    pub fn detecting(normalizer: Arc<Normalizer>, detection: DetectionPipeline) -> Self {
        Self {
            normalizer,
            capture: None,
            detection: Some(detection),
        }
    }

    /// Capture: record every normalized event and evaluate nothing.
    pub fn recording(normalizer: Arc<Normalizer>, capture: CaptureSink) -> Self {
        Self {
            normalizer,
            capture: Some(capture),
            detection: None,
        }
    }
}

impl SensorEventHandler for NormalizedEventHandler {
    fn handle_event(&self, event: &SensorEvent) {
        tracing::trace!(
            target: TARGET_ENGINE,
            category = ?event.category(),
            provider = event.provider,
            action = ?event.action,
            pid = event.pid,
            "Event received"
        );

        match self.normalizer.normalize(event) {
            Some(normalized_event) => {
                tracing::trace!(target: TARGET_ENGINE, "Event normalized successfully");

                if tracing::enabled!(tracing::Level::TRACE) {
                    if let Ok(json) = serde_json::to_string(&normalized_event) {
                        tracing::trace!(target: TARGET_ENGINE, normalized_json = %json, "Normalized event");
                    }
                }

                // Record before enrichment: a recording holds the canonical
                // event, not the alert-only process context added below.
                if let Some(capture) = &self.capture {
                    capture.record(&normalized_event);
                }

                let Some(detection) = &self.detection else {
                    return;
                };

                if let Some(tx) = &detection.ioc_hash_tx {
                    if event.category() == crate::models::EventCategory::Process
                        && event.action == SensorAction::Start
                    {
                        if let crate::models::EventFields::ProcessCreation(fields) =
                            &normalized_event.fields
                        {
                            if let Some(image) = fields.image.as_deref() {
                                let pid = fields
                                    .process_id
                                    .as_deref()
                                    .and_then(|value| value.parse::<u32>().ok())
                                    .or(event.pid)
                                    .unwrap_or(0);

                                if let Err(err) = crate::telemetry::try_send(
                                    crate::telemetry::ChannelId::IocHash,
                                    tx,
                                    (image.to_string(), pid),
                                ) {
                                    debug!(
                                        target: TARGET_ENGINE,
                                        pid = pid,
                                        image = image,
                                        error = %err,
                                        "IOC hash queue full; dropping job"
                                    );
                                }
                            }
                        }
                    }
                }

                // The same detector service replay runs, over the same event.
                let detectors = EventDetectors::snapshot(&detection.detectors);
                let alerts = detectors.evaluate(&normalized_event);
                if alerts.is_empty() {
                    tracing::trace!(target: TARGET_ENGINE, "No rule matched this event");
                }

                for mut alert in alerts {
                    // Alert-only enrichment: live has the process cache and the
                    // originating PID, so it can fill in context the canonical
                    // event does not carry.
                    self.normalizer
                        .enrich_process_context(&mut alert.event, event.pid.unwrap_or(0));

                    detection.alert_sink.write_alert(&alert);
                    detection.response_engine.handle_alert(&alert);
                }
            }
            None => {
                if event.category() == crate::models::EventCategory::Process
                    && event.action == SensorAction::Stop
                {
                    tracing::trace!(
                        target: TARGET_ENGINE,
                        "Process stop event processed for cache maintenance"
                    );
                    return;
                }

                debug!(
                    target: TARGET_ENGINE,
                    category = ?event.category(),
                    action = ?event.action,
                    pid = event.pid,
                    "Failed to normalize event"
                );
            }
        }
    }
}
