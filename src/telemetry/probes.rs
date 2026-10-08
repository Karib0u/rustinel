//! Handles from the running pipeline to the telemetry snapshot.
//!
//! The host-state and artifact-resolver sections of the snapshot read live
//! stores that the pipeline owns.
//! Each runtime builds one [`PipelineProbes`], attaches its own stores, and
//! hands it to the reporter, so two runtimes in one process publish their own
//! numbers instead of whichever registered last.
//! Probes hold weak references: the snapshot never keeps a store alive.

use std::sync::{Arc, Mutex, Weak};

use crate::artifact::ArtifactResolverSnapshot;
use crate::state::HostStateSnapshot;
use crate::telemetry::{WebhookCounters, WebhookSnapshot};

type Probe<T> = Box<dyn Fn() -> Option<T> + Send + Sync>;

#[derive(Default)]
struct Slots {
    host: Mutex<Option<Probe<HostStateSnapshot>>>,
    sensors: Mutex<Option<Probe<super::SensorTelemetry>>>,
    webhooks: Mutex<Vec<Weak<WebhookCounters>>>,
    artifact: Mutex<Option<Probe<ArtifactResolverSnapshot>>>,
}

/// Shared, cloneable set of probes for one runtime.
#[derive(Clone, Default)]
pub struct PipelineProbes {
    slots: Arc<Slots>,
}

impl PipelineProbes {
    /// Publish `host`'s state sections in this runtime's snapshots.
    pub fn attach_host(&self, host: &Arc<crate::state::HostState>) {
        let weak = Arc::downgrade(host);
        *lock(&self.slots.host) = Some(Box::new({
            let weak = weak.clone();
            move || weak.upgrade().map(|state| state.snapshot())
        }));
        *lock(&self.slots.sensors) = Some(Box::new(move || {
            weak.upgrade().map(|state| state.sensor_telemetry())
        }));
    }

    /// Publish the artifact resolver's counters in this runtime's snapshots.
    pub(crate) fn attach_artifact(&self, resolver: &crate::artifact::ArtifactResolverHandle) {
        *lock(&self.slots.artifact) = Some(resolver.probe());
    }

    /// Publish the alert webhook destinations in this runtime's snapshots.
    pub(crate) fn attach_webhooks(&self, counters: &[Arc<WebhookCounters>]) {
        *lock(&self.slots.webhooks) = counters.iter().map(Arc::downgrade).collect();
    }

    pub(super) fn webhook_snapshots(&self) -> Vec<WebhookSnapshot> {
        lock(&self.slots.webhooks)
            .iter()
            .filter_map(Weak::upgrade)
            .map(|counters| counters.snapshot())
            .collect()
    }

    pub(super) fn sensor_telemetry(&self) -> super::SensorTelemetry {
        lock(&self.slots.sensors)
            .as_ref()
            .and_then(|probe| probe())
            .unwrap_or_default()
    }

    pub(super) fn host_snapshot(&self) -> Option<HostStateSnapshot> {
        lock(&self.slots.host).as_ref().and_then(|probe| probe())
    }

    pub(super) fn artifact_snapshot(&self) -> Option<ArtifactResolverSnapshot> {
        lock(&self.slots.artifact)
            .as_ref()
            .and_then(|probe| probe())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{HostState, StateLimits};

    #[test]
    fn probes_report_nothing_until_attached_or_after_the_store_is_gone() {
        let probes = PipelineProbes::default();
        assert!(probes.host_snapshot().is_none());

        let host = Arc::new(HostState::new(StateLimits::default()));
        probes.attach_host(&host);
        assert!(probes.host_snapshot().is_some());

        drop(host);
        assert!(probes.host_snapshot().is_none());
    }

    #[test]
    fn two_runtimes_keep_separate_probes() {
        let (a, b) = (PipelineProbes::default(), PipelineProbes::default());
        let host_a = Arc::new(HostState::new(StateLimits::default()));
        let host_b = Arc::new(HostState::new(StateLimits::default()));
        a.attach_host(&host_a);
        b.attach_host(&host_b);
        drop(host_b);

        assert!(a.host_snapshot().is_some());
        assert!(b.host_snapshot().is_none());
    }
}
