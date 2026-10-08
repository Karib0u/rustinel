//! Ingress: the sensor-facing handler that selects artifact targets, queues
//! their resolution, and hands every event to the ordered stages.
//!
//! Ingress never routes an event on its own authority. Each event goes to
//! [`AdmissionIngress::admit`] exactly once, whether or not it queued work,
//! so admission order is ingest order. See [`crate::stages`] for the ordering
//! and budget rules.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::debug;

use super::job::{ArtifactJob, ResolvePlan};
use super::resolver::ArtifactResolver;
use super::snapshot::ResolverState;
use super::target::{measures_identity_on_arrival, ArtifactKind, ArtifactTarget};
use super::written_file::WRITTEN_FILE_QUEUE_CAPACITY;
use super::ARTIFACT_QUEUE_CAPACITY;
use super::{open_artifact, ArtifactOpener, ArtifactResolverHandle, ArtifactRuntime};
use crate::models::{CanonicalEvent, EventFields};
use crate::scanner;
use crate::sensor::{CanonicalEventHandler, SensorAction, SensorEventRouter};
use crate::stages::admission::{self, Admission, AdmissionIngress};
use crate::stages::deferred::{self, DeferredDetection, DeferredIngress};
use crate::state::HostState;

/// Create the upstream router, its ordered admission stage, and the bounded
/// artifact resolver.
pub(crate) fn spawn_artifact_resolver(
    downstream: Arc<SensorEventRouter>,
    host_state: Arc<HostState>,
    runtime: ArtifactRuntime,
) -> (
    Arc<SensorEventRouter>,
    JoinHandle<()>,
    ArtifactResolverHandle,
) {
    let state = Arc::new(ResolverState::new());
    if let Some(detectors) = &runtime.detectors {
        // Weak, so a store outliving its resolver never keeps it alive.
        let resolver = Arc::downgrade(&state);
        detectors.subscribe_yara_swap(move |generation| {
            if let Some(state) = resolver.upgrade() {
                state.invalidate_yara_generation(generation);
            }
        });
    }
    let parts = ResolverParts::new(
        downstream,
        host_state,
        runtime,
        Arc::clone(&state),
        ARTIFACT_QUEUE_CAPACITY,
        WRITTEN_FILE_QUEUE_CAPACITY,
    );
    let mut upstream = SensorEventRouter::new();
    upstream.register_handler(Box::new(parts.ingress));
    let admission = parts.admission;
    let deferred = parts.deferred;
    let resolver = parts.resolver;
    let resolve_rx = parts.resolve_rx;
    let written_rx = parts.written_rx;
    let worker = tokio::task::spawn_blocking(move || {
        run_resolver_stages(
            admission,
            deferred,
            resolver,
            resolve_rx,
            written_rx,
            Arc::new(open_artifact),
        )
    });
    (
        Arc::new(upstream),
        worker,
        ArtifactResolverHandle::new(state),
    )
}

/// Run admission on the calling thread, and resolution and deferred detection
/// beside it, returning once every queue has closed and drained.
pub(super) fn run_resolver_stages(
    admission: Admission,
    deferred: Option<DeferredDetection>,
    resolver: ArtifactResolver,
    mut resolve_rx: mpsc::Receiver<ArtifactJob>,
    mut written_rx: mpsc::Receiver<ArtifactJob>,
    open: ArtifactOpener,
) {
    std::thread::scope(|scope| {
        let written_resolver = resolver.clone();
        let written_open = Arc::clone(&open);
        let spawned = std::thread::Builder::new()
            .name("artifact-written-files".to_string())
            .spawn_scoped(scope, move || {
                written_resolver.run_queue(&mut written_rx, written_open, true)
            });
        if let Err(error) = spawned {
            debug!(target: "artifact", %error, "Could not start written-file resolver");
        }
        let spawned = std::thread::Builder::new()
            .name("artifact-resolver".to_string())
            .spawn_scoped(scope, move || resolver.run(&mut resolve_rx, open));
        if let Err(error) = spawned {
            // The receiver was moved into the failed closure and is dropped, so
            // ingress sees a closed queue and admits base events.
            debug!(target: "artifact", %error, "Could not start artifact resolver");
        }
        if let Some(deferred) = deferred {
            let spawned = std::thread::Builder::new()
                .name("artifact-deferred-detection".to_string())
                .spawn_scoped(scope, move || deferred.run());
            if let Err(error) = spawned {
                // The dropped receiver makes ingress keep every rule at
                // admission, so no deferred-pass rule goes unevaluated.
                debug!(target: "artifact", %error, "Could not start deferred detection");
            }
        }
        admission.run();
    });
}

/// The halves of the resolver, wired to each other but not yet running.
pub(super) struct ResolverParts {
    pub(super) ingress: ArtifactEventHandler,
    pub(super) admission: Admission,
    pub(super) deferred: Option<DeferredDetection>,
    pub(super) resolver: ArtifactResolver,
    pub(super) resolve_rx: mpsc::Receiver<ArtifactJob>,
    pub(super) written_rx: mpsc::Receiver<ArtifactJob>,
}

impl ResolverParts {
    pub(super) fn new(
        downstream: Arc<SensorEventRouter>,
        host_state: Arc<HostState>,
        runtime: ArtifactRuntime,
        state: Arc<ResolverState>,
        resolve_capacity: usize,
        written_capacity: usize,
    ) -> Self {
        let (resolve_tx, resolve_rx) = mpsc::channel(resolve_capacity);
        let (written_tx, written_rx) = mpsc::channel(written_capacity);
        let (admission_ingress, admission) =
            admission::channel(downstream, Arc::clone(&state.counters.admission));
        // Only a detecting runtime has rules to defer; capture evaluates none.
        let (deferred_ingress, deferred) = match &runtime.detectors {
            Some(detectors) => {
                let (ingress, stage) = deferred::channel(
                    Arc::clone(detectors),
                    Arc::clone(&host_state),
                    runtime.alert_sink.clone(),
                    runtime.response_engine.clone(),
                    Arc::clone(&state.counters.deferred),
                );
                (Some(ingress), Some(stage))
            }
            None => (None, None),
        };
        Self {
            ingress: ArtifactEventHandler {
                resolve_tx,
                written_tx,
                admission: admission_ingress,
                deferred: deferred_ingress,
                runtime: runtime.clone(),
                state: Arc::clone(&state),
            },
            admission,
            deferred,
            resolver: ArtifactResolver::new(host_state, runtime, state),
            resolve_rx,
            written_rx,
        }
    }
}

pub(super) struct ArtifactEventHandler {
    resolve_tx: mpsc::Sender<ArtifactJob>,
    pub(super) written_tx: mpsc::Sender<ArtifactJob>,
    admission: AdmissionIngress,
    /// Present when a detecting runtime can defer rules to after resolution.
    deferred: Option<DeferredIngress>,
    runtime: ArtifactRuntime,
    pub(super) state: Arc<ResolverState>,
}

impl CanonicalEventHandler for ArtifactEventHandler {
    fn handle_event(&self, event: &CanonicalEvent) {
        let Some(mut target) =
            ArtifactTarget::select_event(event, self.runtime.written_files.as_ref())
        else {
            if matches!(event.normalized().fields, EventFields::FileEvent(_))
                && matches!(
                    event.action,
                    SensorAction::Create | SensorAction::Modify | SensorAction::Rename
                )
                && self.runtime.written_files.is_some()
            {
                self.state
                    .counters
                    .written_file_rejected
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.admission.admit(event, None, false);
            return;
        };
        let mut plan = ResolvePlan::snapshot(&self.runtime, event, &target);
        if plan.needs.is_empty() {
            self.admission.admit(event, None, false);
            return;
        }
        // Selection and the initial consumer check do no process/filesystem I/O.
        // Only eligible images need an arrival-time snapshot of local proc entries.
        target.capture_process_context(event);
        if crate::utils::process::linux_exec_uses_proc(&target.display_path) {
            // Descriptor images use the measured executable for allowlisting.
            plan = ResolvePlan::snapshot(&self.runtime, event, &target);
            if plan.needs.is_empty() {
                self.admission.admit(event, None, false);
                return;
            }
        }
        if target.kind == ArtifactKind::WrittenFile
            && target.expected.is_none()
            && !measures_identity_on_arrival(event.normalized().platform)
        {
            // Without an event-time identity the resolver could scan whatever
            // replaced the file and report it as the file this event wrote.
            self.state
                .counters
                .identity_unavailable
                .fetch_add(1, Ordering::Relaxed);
            self.admission.admit(event, None, false);
            return;
        }
        // Only Sigma-visible enrichment holds admission. Hashes and YARA
        // raise their own alerts and finish after the event has moved on.
        let (pe_ready, pe) = if plan.needs.pe_metadata {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (deferred_ready, deferred_fields) =
            if plan.deferred.is_empty() || self.deferred.is_none() {
                (None, None)
            } else {
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                (Some(tx), Some(rx))
            };
        let deferred_needs = plan.deferred;
        let written_file = (target.kind == ArtifactKind::WrittenFile)
            .then(|| Box::new(event.normalized().clone()));
        let kind = target.kind;
        let job = ArtifactJob {
            target,
            plan,
            enqueued_at: Instant::now(),
            pe_ready,
            deferred_ready,
            resolved_pe: None,
            resolved_hashes: None,
            process_start_key: event.process_start_key,
            provenance: scanner::scan_subject_provenance(event.provenance()),
            platform: event.normalized().platform,
            provider: event.normalized().provider.clone(),
            written_file,
        };
        match crate::telemetry::try_send(
            if kind == ArtifactKind::WrittenFile {
                crate::telemetry::ChannelId::ArtifactWrittenFiles
            } else {
                crate::telemetry::ChannelId::ArtifactResolution
            },
            if kind == ArtifactKind::WrittenFile {
                &self.written_tx
            } else {
                &self.resolve_tx
            },
            job,
        ) {
            Ok(()) => {
                self.state.counters.queued.fetch_add(1, Ordering::Relaxed);
                let deferred = deferred_fields.is_some_and(|fields| {
                    self.deferred
                        .as_ref()
                        .is_some_and(|stage| stage.defer(event, deferred_needs, fields))
                });
                self.admission.admit(event, pe, deferred);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.state.record_drop(kind);
                self.state
                    .counters
                    .queue_saturated
                    .fetch_add(1, Ordering::Relaxed);
                debug!("Artifact resolver queue full; admitting base event");
                self.admission.admit(event, None, false);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.state.record_drop(kind);
                debug!("Artifact resolver stopped; admitting base event");
                self.admission.admit(event, None, false);
            }
        }
    }
}

#[cfg(test)]
mod tests;
