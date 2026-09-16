//! The canonical-event detector service.
//!
//! This is the single place where a [`CanonicalEvent`] is turned into
//! alerts. Live protection calls it from the sensor pipeline; `rustinel replay`
//! calls it over a recording. Neither owns a matching implementation of its own,
//! so a replayed event is evaluated by exactly the code that would have seen it
//! live.
//!
//! The service covers only the detectors that read the normalized event itself:
//! Sigma and the inline IOC checks. Detectors that need the artifact behind the
//! event — YARA, and IOC hash matching — are driven from the live pipeline,
//! which has the file to read. So are alert-only enrichment, deduplication, and
//! active response: what a caller does with an alert is the caller's business.

use std::sync::Arc;

use crate::engine::{DetectionPass, DetectorStore};
use crate::ioc::IocEngine;
use crate::models::{Alert, CanonicalEvent};
use crate::sensor::ProcessStartKey;

pub(crate) struct EventAlert {
    pub(crate) alert: Alert,
    pub(crate) process_start_key: Option<ProcessStartKey>,
}

/// The event-based detectors, evaluated together in a fixed order.
///
/// Holding the engines by `Arc` lets a live caller take a consistent snapshot of
/// the hot-reloadable [`DetectorStore`] for the duration of one event.
pub struct EventDetectors {
    sigma: Arc<crate::engine::Engine>,
    ioc: Arc<IocEngine>,
}

impl EventDetectors {
    pub fn new(sigma: Arc<crate::engine::Engine>, ioc: Arc<IocEngine>) -> Self {
        Self { sigma, ioc }
    }

    /// Snapshot the currently loaded detectors from a hot-reloadable store.
    pub fn snapshot(store: &DetectorStore) -> Self {
        Self {
            sigma: Arc::clone(&store.sigma()),
            ioc: Arc::clone(&store.ioc()),
        }
    }

    /// Evaluate one normalized event.
    ///
    /// Returns the selected Sigma detection, any Sigma correlations, and IOC
    /// matches in a deterministic order. The same event evaluated against the
    /// same detectors produces the same alerts in the same sequence.
    pub fn evaluate(&self, event: &CanonicalEvent) -> Vec<Alert> {
        self.evaluate_pass(event, DetectionPass::All)
    }

    /// Evaluate one detection pass of an event.
    ///
    /// Inline IOC checks belong to the admission side: they run with
    /// [`DetectionPass::All`] and [`DetectionPass::Admission`], never again in
    /// the deferred pass.
    pub fn evaluate_pass(&self, event: &CanonicalEvent, pass: DetectionPass) -> Vec<Alert> {
        self.evaluate_pass_with_origins(event, pass)
            .into_iter()
            .map(|result| result.alert)
            .collect()
    }

    pub(crate) fn evaluate_pass_with_origins(
        &self,
        event: &CanonicalEvent,
        pass: DetectionPass,
    ) -> Vec<EventAlert> {
        let mut alerts = self
            .sigma
            .evaluate_canonical_event_pass(event, pass)
            .into_iter()
            .map(|result| EventAlert {
                alert: result.alert,
                process_start_key: result.process_start_key,
            })
            .collect::<Vec<_>>();

        if pass.includes_admission() {
            for ioc_match in self.ioc.check_event(event) {
                alerts.push(EventAlert {
                    alert: self.ioc.build_alert_for_match(&ioc_match, event),
                    process_start_key: event.process_start_key,
                });
            }
        }

        alerts
    }
}
