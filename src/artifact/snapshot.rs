//! Resolver counters, the telemetry snapshot built from them, and the handle
//! that lets doctor and rule reload reach the running resolver.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::job::ARTIFACT_DEADLINE;
use super::stores::ArtifactStores;
use super::stores::ARTIFACT_STORE_CAPACITY;
use super::target::ArtifactKind;
use super::written_file::WRITTEN_FILE_QUEUE_CAPACITY;
use super::ARTIFACT_QUEUE_CAPACITY;
use crate::stages::admission::{AdmissionCounters, ADMISSION_BUDGET};
use crate::stages::deferred::{DeferredCounters, DEFERRED_DETECTION_BUDGET};

/// Resolver/store state persisted in the telemetry snapshot read by doctor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactResolverSnapshot {
    pub queue_capacity: usize,
    /// Written-file channel and settle-table capacity; zero in older snapshots.
    #[serde(default)]
    pub written_file_queue_capacity: usize,
    pub deadline_ms: u64,
    pub admission_budget_ms: u64,
    pub queued: u64,
    pub resolved: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub queue_saturated: u64,
    /// Jobs shed by queue pressure, closure, worker failure, or expiry.
    #[serde(default)]
    pub process_image_dropped: u64,
    #[serde(default)]
    pub loaded_image_dropped: u64,
    #[serde(default)]
    pub written_file_dropped: u64,
    /// File events rejected by the selector or without a usable target path.
    #[serde(default)]
    pub written_file_rejected: u64,
    /// Repeated writes replaced by the latest event for the same path/object.
    #[serde(default)]
    pub written_file_coalesced: u64,
    pub worker_saturated: u64,
    pub deadline_exceeded: u64,
    /// Events admitted without PE metadata because it missed the budget.
    pub admission_budget_exceeded: u64,
    /// Ingress sends that waited for room in the admission queue.
    pub admission_backpressure: u64,
    pub open_failed: u64,
    pub identity_mismatch: u64,
    /// Selected written files skipped because no object identity was
    /// available to validate the opened file against: the sensor measured
    /// none, or, on Windows, the file is not on a local volume.
    #[serde(default)]
    pub identity_unavailable: u64,
    pub read_failed: u64,
    pub consumer_failed: u64,
    pub oversized: u64,
    pub evicted: u64,
    /// Events whose deferred-pass rules waited for `Hashes`/`Imphash`.
    #[serde(default)]
    pub deferred_queued: u64,
    /// Deferred passes evaluated with at least one artifact field.
    #[serde(default)]
    pub deferred_enriched: u64,
    /// Deferred passes evaluated without artifact fields, because resolution
    /// failed, was shed, or produced nothing for the file.
    #[serde(default)]
    pub deferred_unenriched: u64,
    /// Deferred passes evaluated without artifact fields because
    /// [`DEFERRED_DETECTION_BUDGET`] expired first. Counted in
    /// `deferred_unenriched` too.
    #[serde(default)]
    pub deferred_budget_exceeded: u64,
    /// Events whose deferred-pass rules ran at admission, without artifact
    /// fields, because the deferred queue was full.
    #[serde(default)]
    pub deferred_queue_saturated: u64,
    #[serde(default)]
    pub deferred_budget_ms: u64,
    /// Maximum extra time correlation updates wait for an earlier event's
    /// deferred pass so every window sees ingest order.
    #[serde(default)]
    pub correlation_lateness_ms: u64,
    pub pe_entries: usize,
    pub hash_entries: usize,
    pub imphash_entries: usize,
    pub signature_entries: usize,
    pub yara_entries: usize,
    pub yara_generation: u64,
}

#[derive(Default)]
pub(super) struct ResolverCounters {
    pub(super) admission: Arc<AdmissionCounters>,
    pub(super) deferred: Arc<DeferredCounters>,
    pub(super) queued: AtomicU64,
    pub(super) resolved: AtomicU64,
    pub(super) cache_hits: AtomicU64,
    pub(super) cache_misses: AtomicU64,
    pub(super) queue_saturated: AtomicU64,
    pub(super) process_image_dropped: AtomicU64,
    pub(super) loaded_image_dropped: AtomicU64,
    pub(super) written_file_dropped: AtomicU64,
    pub(super) written_file_rejected: AtomicU64,
    pub(super) written_file_coalesced: AtomicU64,
    pub(super) worker_saturated: AtomicU64,
    pub(super) deadline_exceeded: AtomicU64,
    pub(super) open_failed: AtomicU64,
    pub(super) identity_mismatch: AtomicU64,
    pub(super) identity_unavailable: AtomicU64,
    pub(super) read_failed: AtomicU64,
    pub(super) consumer_failed: AtomicU64,
    pub(super) oversized: AtomicU64,
}

pub(super) struct ResolverState {
    pub(super) counters: ResolverCounters,
    pub(super) stores: Mutex<ArtifactStores>,
}

impl ResolverState {
    pub(super) fn record_drop(&self, kind: ArtifactKind) {
        let counter = match kind {
            ArtifactKind::ProcessImage => &self.counters.process_image_dropped,
            ArtifactKind::LoadedImage => &self.counters.loaded_image_dropped,
            ArtifactKind::WrittenFile => &self.counters.written_file_dropped,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn new() -> Self {
        Self {
            counters: ResolverCounters::default(),
            stores: Mutex::new(ArtifactStores::new(ARTIFACT_STORE_CAPACITY)),
        }
    }

    pub(super) fn snapshot(&self) -> ArtifactResolverSnapshot {
        let stores = self
            .stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ArtifactResolverSnapshot {
            queue_capacity: ARTIFACT_QUEUE_CAPACITY,
            written_file_queue_capacity: WRITTEN_FILE_QUEUE_CAPACITY,
            deadline_ms: ARTIFACT_DEADLINE.as_millis() as u64,
            admission_budget_ms: ADMISSION_BUDGET.as_millis() as u64,
            queued: self.counters.queued.load(Ordering::Relaxed),
            resolved: self.counters.resolved.load(Ordering::Relaxed),
            cache_hits: self.counters.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.counters.cache_misses.load(Ordering::Relaxed),
            queue_saturated: self.counters.queue_saturated.load(Ordering::Relaxed),
            process_image_dropped: self.counters.process_image_dropped.load(Ordering::Relaxed),
            loaded_image_dropped: self.counters.loaded_image_dropped.load(Ordering::Relaxed),
            written_file_dropped: self.counters.written_file_dropped.load(Ordering::Relaxed),
            written_file_rejected: self.counters.written_file_rejected.load(Ordering::Relaxed),
            written_file_coalesced: self.counters.written_file_coalesced.load(Ordering::Relaxed),
            worker_saturated: self.counters.worker_saturated.load(Ordering::Relaxed),
            deadline_exceeded: self.counters.deadline_exceeded.load(Ordering::Relaxed),
            admission_budget_exceeded: self
                .counters
                .admission
                .budget_exceeded
                .load(Ordering::Relaxed),
            admission_backpressure: self.counters.admission.backpressure.load(Ordering::Relaxed),
            open_failed: self.counters.open_failed.load(Ordering::Relaxed),
            identity_mismatch: self.counters.identity_mismatch.load(Ordering::Relaxed),
            identity_unavailable: self.counters.identity_unavailable.load(Ordering::Relaxed),
            read_failed: self.counters.read_failed.load(Ordering::Relaxed),
            consumer_failed: self.counters.consumer_failed.load(Ordering::Relaxed),
            oversized: self.counters.oversized.load(Ordering::Relaxed),
            evicted: stores.evicted,
            deferred_queued: self.counters.deferred.queued.load(Ordering::Relaxed),
            deferred_enriched: self.counters.deferred.enriched.load(Ordering::Relaxed),
            deferred_unenriched: self.counters.deferred.unenriched.load(Ordering::Relaxed),
            deferred_budget_exceeded: self
                .counters
                .deferred
                .budget_exceeded
                .load(Ordering::Relaxed),
            deferred_queue_saturated: self
                .counters
                .deferred
                .queue_saturated
                .load(Ordering::Relaxed),
            deferred_budget_ms: DEFERRED_DETECTION_BUDGET.as_millis() as u64,
            correlation_lateness_ms: crate::engine::CORRELATION_REORDER_BUDGET.as_millis() as u64,
            pe_entries: stores.pe.len(),
            hash_entries: stores.hashes.len(),
            imphash_entries: stores.imphashes.len(),
            signature_entries: stores.signatures.len(),
            yara_entries: stores.yara.len(),
            yara_generation: stores.yara_generation.unwrap_or_default(),
        }
    }
}

/// Keeps the resolver stores alive until the caller has written its final
/// telemetry snapshot, even after the queue worker has drained.
pub(crate) struct ArtifactResolverHandle {
    state: Arc<ResolverState>,
}

impl ArtifactResolverHandle {
    pub(super) fn new(state: Arc<ResolverState>) -> Self {
        Self { state }
    }

    /// A weak reader of the resolver snapshot, for the telemetry reporter.
    pub(crate) fn probe(&self) -> Box<dyn Fn() -> Option<ArtifactResolverSnapshot> + Send + Sync> {
        let weak = Arc::downgrade(&self.state);
        Box::new(move || weak.upgrade().map(|state| state.snapshot()))
    }
}

impl ResolverState {
    /// Drop generation-bound YARA entries as soon as a rule reload commits.
    pub(super) fn invalidate_yara_generation(&self, generation: u64) {
        self.stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .invalidate_yara(Some(generation));
    }
}

#[cfg(test)]
impl ArtifactResolverHandle {
    pub(crate) fn empty() -> Self {
        Self {
            state: Arc::new(ResolverState::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_file_capacity_is_separate_and_old_snapshots_remain_readable() {
        let state = ResolverState::new();
        let snapshot = state.snapshot();
        assert_eq!(snapshot.queue_capacity, ARTIFACT_QUEUE_CAPACITY);
        assert_eq!(
            snapshot.written_file_queue_capacity,
            WRITTEN_FILE_QUEUE_CAPACITY
        );
        let mut json = serde_json::to_value(snapshot).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("written_file_queue_capacity");
        let older: ArtifactResolverSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(older.written_file_queue_capacity, 0);
    }
}
