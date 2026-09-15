//! Canonical-event handler shared by live detection and capture.
//!
//! [`HostState`] has already normalized and enriched each event before this
//! handler receives it. Live protection evaluates the generated normalized
//! view, while capture persists that same view without running detectors.

use std::sync::Arc;

use crate::alerts::AlertSink;
use crate::capture::CaptureSink;
use crate::engine::{DetectionPass, DetectorStore, EventDetectors};
use crate::models::CanonicalEvent;
use crate::response::ResponseEngine;
use crate::sensor::CanonicalEventHandler;
use crate::state::HostState;

/// Target name for engine operational logs.
const TARGET_ENGINE: &str = "engine";

/// Detection side of the pipeline: rule evaluation, alerting, and response.
pub struct DetectionPipeline {
    /// Live detector store (sigma/ioc hot-reloaded atomically).
    pub detectors: Arc<DetectorStore>,
    /// ECS NDJSON alert sink.
    pub alert_sink: AlertSink,
    /// Active response engine.
    pub response_engine: ResponseEngine,
}

/// Handler that dispatches canonical events to capture, detection, or both.
pub struct NormalizedEventHandler {
    /// Host state retained for live-only alert context enrichment.
    pub host_state: Arc<HostState>,
    /// Behavioral recording sink. Fed immediately after canonicalization, before
    /// alert-only enrichment or any detector evaluation.
    pub capture: Option<CaptureSink>,
    /// Detection pipeline. Absent when the session only records, which is what
    /// keeps capture from evaluating rules or invoking active response.
    pub detection: Option<DetectionPipeline>,
}

impl NormalizedEventHandler {
    /// Live protection: evaluate every canonical event against the detectors.
    pub fn detecting(host_state: Arc<HostState>, detection: DetectionPipeline) -> Self {
        Self {
            host_state,
            capture: None,
            detection: Some(detection),
        }
    }

    /// Capture: record every canonical event and evaluate nothing.
    pub fn recording(host_state: Arc<HostState>, capture: CaptureSink) -> Self {
        Self {
            host_state,
            capture: Some(capture),
            detection: None,
        }
    }
}

impl CanonicalEventHandler for NormalizedEventHandler {
    fn handle_event(&self, event: &CanonicalEvent) {
        tracing::trace!(
            target: TARGET_ENGINE,
            category = ?event.normalized().category,
            provider = %event.normalized().provider,
            action = ?event.action,
            pid = event.pid,
            "Event received"
        );

        let normalized_event = event.normalized();
        tracing::trace!(target: TARGET_ENGINE, "Canonical event received");

        if tracing::enabled!(tracing::Level::TRACE) {
            if let Ok(json) = serde_json::to_string(normalized_event) {
                tracing::trace!(target: TARGET_ENGINE, normalized_json = %json, "Normalized view");
            }
        }

        // Capture accepts the canonical boundary and persists its stable
        // generated view before alert-only enrichment.
        if let Some(capture) = &self.capture {
            capture.record(event);
        }

        let Some(detection) = &self.detection else {
            return;
        };

        // The same canonical detector service is used by replay. An event
        // whose deferred pass is pending leaves those rules to that pass.
        let detectors = EventDetectors::snapshot(&detection.detectors);
        let pass = if event.deferred_pass_pending() {
            DetectionPass::Admission
        } else {
            DetectionPass::All
        };
        let alerts = detectors.evaluate_pass(event, pass);
        if alerts.is_empty() {
            tracing::trace!(target: TARGET_ENGINE, "No rule matched this event");
        }

        for mut alert in alerts {
            self.host_state
                .enrich_process_context(&mut alert.event, event.process_start_key);

            detection.alert_sink.write_alert(&alert);
            detection.response_engine.handle_alert(&alert);
        }
    }
}
