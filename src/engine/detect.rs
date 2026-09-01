//! The normalized-event detector service.
//!
//! This is the single place where a canonical [`NormalizedEvent`] is turned into
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

use crate::ioc::IocEngine;
use crate::models::{Alert, NormalizedEvent};
use crate::reload::DetectorStore;

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
    pub fn evaluate(&self, event: &NormalizedEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        alerts.extend(self.sigma.evaluate_event(event));

        for ioc_match in self.ioc.check_event(event) {
            alerts.push(self.ioc.build_alert_for_match(&ioc_match, event));
        }

        alerts
    }
}
