//! Bounded, single-open resolution of file artifacts.
//!
//! Every on-disk consumer (Windows PE enrichment, IOC hashing, and YARA) reads
//! the same identity-validated handle once, and the bytes fan out to each
//! requested consumer. Targets are process images, loaded images, and, when a
//! [`WrittenFileSelector`] chooses them, files named by canonical file events.
//!
//! Admission to detection and capture follows ingest order. Only enrichment
//! that Sigma can match, PE metadata today, may hold an event, and for at most
//! [`ADMISSION_BUDGET`]; events behind it wait in order. Hash and YARA
//! consumers finish after admission because they raise their own alerts.
//!
//! `Hashes` and `Imphash` cost too much for that budget. Sigma rules that
//! select on them are left out of admission and evaluated once, in ingest
//! order, by the deferred detection stage when those fields are resolved or
//! [`DEFERRED_DETECTION_BUDGET`] expires, whichever comes first.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::alerts::AlertSink;
use crate::engine::{ArtifactFieldNeeds, DetectionPass, DetectorStore, EventDetectors};
use crate::ioc::{ComputedHashes, HashRequirements};
use crate::models::{
    Alert, CanonicalEvent, EventFields, FileEventFields, FileObjectIdentity, MatchDebugLevel,
    NormalizedEvent, YaraRuleMatch, YaraScanSource,
};
use crate::response::ResponseEngine;
use crate::scanner::{self, ScanError, Scanner};
use crate::sensor::{CanonicalEventHandler, Platform, SensorAction, SensorEventRouter};
use crate::state::HostState;
use crate::utils::file_identity::{self, FileIdentity};

/// The queue is deliberately smaller than sensor ingress: when artifact I/O is
/// slow, the resolver sheds enrichment while the base event still gets routed.
pub(crate) const ARTIFACT_QUEUE_CAPACITY: usize = 256;
const ARTIFACT_STORE_CAPACITY: usize = 10_000;
const ARTIFACT_DEADLINE: Duration = Duration::from_secs(10);
const ARTIFACT_MAX_READ_BYTES: u64 = 256 * 1024 * 1024;
const PE_MAX_READ_BYTES: u64 = 128 * 1024 * 1024;
const ARTIFACT_IO_ISOLATION_LIMIT: usize = 4;
/// File create and modify events can arrive before the writer has finished.
/// Delay their background resolution so short writes settle before opening.
const WRITTEN_FILE_SETTLE_DELAY: Duration = Duration::from_millis(250);
const WRITTEN_FILE_MAGIC_BYTES: usize = 16;
/// Longest Sigma-visible enrichment may hold an event at admission. Past it
/// the event is admitted, still in ingest order, without those fields.
pub(crate) const ADMISSION_BUDGET: Duration = Duration::from_millis(100);
/// Admission entries only have to absorb the events that arrive while the
/// head of the queue waits out its budget.
const ADMISSION_QUEUE_CAPACITY: usize = 4096;
/// Longest a deferred-pass event waits for `Hashes` and `Imphash`, measured
/// from its arrival. Past it the deferred rules evaluate it without them, so
/// their detections reach correlation at most this late.
pub(crate) const DEFERRED_DETECTION_BUDGET: Duration = crate::engine::CORRELATION_REORDER_BUDGET;
/// Deferred entries wait at most their budget, so the queue only absorbs the
/// artifact events of one budget window. When it is full, the event keeps
/// every rule at admission instead.
const DEFERRED_QUEUE_CAPACITY: usize = 1024;
type ArtifactOpener = Arc<dyn Fn(&Path) -> io::Result<File> + Send + Sync>;

/// Work requested from one shared artifact read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ArtifactNeeds {
    pub hashes: HashRequirements,
    pub imphash: bool,
    pub pe_metadata: bool,
    pub signature: bool,
    pub yara: bool,
}

/// Windows version-resource metadata. The data shape is platform-neutral so
/// artifact stores and diagnostics compile on every supported target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeMetadata {
    /// Original filename declared by the version resource.
    pub original_filename: Option<String>,
    /// Product name declared by the version resource.
    pub product: Option<String>,
    /// File description declared by the version resource.
    pub description: Option<String>,
    /// Company name declared by the version resource.
    pub company: Option<String>,
    /// File version declared by the version resource.
    pub file_version: Option<String>,
}

impl ArtifactNeeds {
    /// Whether digests or the imphash still have to come from the bytes.
    fn needs_digest_read(self) -> bool {
        self.hashes.md5 || self.hashes.sha1 || self.hashes.sha256 || self.imphash
    }

    fn is_empty(self) -> bool {
        !self.hashes.md5
            && !self.hashes.sha1
            && !self.hashes.sha256
            && !self.imphash
            && !self.pe_metadata
            && !self.signature
            && !self.yara
    }
}

/// Results computed from a single identity-validated open handle.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // imphash and signature are extension points for #319/#320.
pub(crate) struct Artifact {
    pub identity: Option<FileIdentity>,
    pub hashes: Option<ComputedHashes>,
    /// Reserved for #319; it will consume the already-read bytes here.
    pub imphash: Option<String>,
    pub pe_metadata: Option<PeMetadata>,
    /// Reserved for #320; unknown remains distinct from unsigned.
    pub signature: Option<ArtifactSignature>,
    pub yara: Option<Vec<YaraRuleMatch>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // populated by the Authenticode consumer in #320.
pub(crate) enum ArtifactSignature {
    Unknown,
    Unsigned,
    Invalid,
    Valid { signer: Option<String> },
}

/// Resolver/store state persisted in the telemetry snapshot read by doctor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactResolverSnapshot {
    pub queue_capacity: usize,
    pub deadline_ms: u64,
    pub admission_budget_ms: u64,
    pub queued: u64,
    pub resolved: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub queue_saturated: u64,
    pub worker_saturated: u64,
    pub deadline_exceeded: u64,
    /// Events admitted without PE metadata because it missed the budget.
    pub admission_budget_exceeded: u64,
    /// Ingress sends that waited for room in the admission queue.
    pub admission_backpressure: u64,
    pub open_failed: u64,
    pub identity_mismatch: u64,
    /// Selected written files skipped because the sensor supplied no
    /// event-time identity to validate the opened file against.
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
struct ResolverCounters {
    queued: AtomicU64,
    resolved: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    queue_saturated: AtomicU64,
    worker_saturated: AtomicU64,
    deadline_exceeded: AtomicU64,
    admission_budget_exceeded: AtomicU64,
    admission_backpressure: AtomicU64,
    open_failed: AtomicU64,
    identity_mismatch: AtomicU64,
    identity_unavailable: AtomicU64,
    read_failed: AtomicU64,
    consumer_failed: AtomicU64,
    oversized: AtomicU64,
    deferred_queued: AtomicU64,
    deferred_enriched: AtomicU64,
    deferred_unenriched: AtomicU64,
    deferred_budget_exceeded: AtomicU64,
    deferred_queue_saturated: AtomicU64,
}

struct ResolverState {
    counters: ResolverCounters,
    stores: Mutex<ArtifactStores>,
}

impl ResolverState {
    fn new() -> Self {
        Self {
            counters: ResolverCounters::default(),
            stores: Mutex::new(ArtifactStores::new(ARTIFACT_STORE_CAPACITY)),
        }
    }

    fn snapshot(&self) -> ArtifactResolverSnapshot {
        let stores = self
            .stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ArtifactResolverSnapshot {
            queue_capacity: ARTIFACT_QUEUE_CAPACITY,
            deadline_ms: ARTIFACT_DEADLINE.as_millis() as u64,
            admission_budget_ms: ADMISSION_BUDGET.as_millis() as u64,
            queued: self.counters.queued.load(Ordering::Relaxed),
            resolved: self.counters.resolved.load(Ordering::Relaxed),
            cache_hits: self.counters.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.counters.cache_misses.load(Ordering::Relaxed),
            queue_saturated: self.counters.queue_saturated.load(Ordering::Relaxed),
            worker_saturated: self.counters.worker_saturated.load(Ordering::Relaxed),
            deadline_exceeded: self.counters.deadline_exceeded.load(Ordering::Relaxed),
            admission_budget_exceeded: self
                .counters
                .admission_budget_exceeded
                .load(Ordering::Relaxed),
            admission_backpressure: self.counters.admission_backpressure.load(Ordering::Relaxed),
            open_failed: self.counters.open_failed.load(Ordering::Relaxed),
            identity_mismatch: self.counters.identity_mismatch.load(Ordering::Relaxed),
            identity_unavailable: self.counters.identity_unavailable.load(Ordering::Relaxed),
            read_failed: self.counters.read_failed.load(Ordering::Relaxed),
            consumer_failed: self.counters.consumer_failed.load(Ordering::Relaxed),
            oversized: self.counters.oversized.load(Ordering::Relaxed),
            evicted: stores.evicted,
            deferred_queued: self.counters.deferred_queued.load(Ordering::Relaxed),
            deferred_enriched: self.counters.deferred_enriched.load(Ordering::Relaxed),
            deferred_unenriched: self.counters.deferred_unenriched.load(Ordering::Relaxed),
            deferred_budget_exceeded: self
                .counters
                .deferred_budget_exceeded
                .load(Ordering::Relaxed),
            deferred_queue_saturated: self
                .counters
                .deferred_queue_saturated
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

static ACTIVE: LazyLock<Mutex<Weak<ResolverState>>> = LazyLock::new(|| Mutex::new(Weak::new()));

pub fn active_snapshot() -> Option<ArtifactResolverSnapshot> {
    ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .upgrade()
        .map(|state| state.snapshot())
}

/// Drop generation-bound YARA entries as soon as a rule reload commits.
pub(crate) fn invalidate_yara_generation(generation: u64) {
    let Some(state) = ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .upgrade()
    else {
        return;
    };
    state
        .stores
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .invalidate_yara(Some(generation));
}

/// Keeps the resolver stores alive until the caller has written its final
/// telemetry snapshot, even after the queue worker has drained.
pub(crate) struct ArtifactResolverHandle {
    _state: Arc<ResolverState>,
}

#[cfg(test)]
impl ArtifactResolverHandle {
    pub(crate) fn empty() -> Self {
        Self {
            _state: Arc::new(ResolverState::new()),
        }
    }
}

/// Chooses which canonical file events become written-file artifact targets.
///
/// This is the whole of the written-file scan policy (#324): settle,
/// extension, magic-byte, and size gates decide here. Identity validation,
/// allowlists, scan limits, caching, and outcome counters come from the
/// resolver for every selected target.
pub(crate) type WrittenFileSelector =
    Arc<dyn Fn(&CanonicalEvent, &FileEventFields) -> bool + Send + Sync>;

/// Select complete canonical file paths for written-file content inspection.
/// Content qualification happens on the resolver's identity-validated handle.
pub(crate) fn written_file_scan_selector() -> WrittenFileSelector {
    Arc::new(|_, fields| fields.path_truncated.is_none())
}

#[derive(Clone)]
pub(crate) struct ArtifactRuntime {
    pub detectors: Option<Arc<DetectorStore>>,
    pub alert_sink: Option<AlertSink>,
    pub response_engine: Option<ResponseEngine>,
    pub match_debug: MatchDebugLevel,
    pub yara_allowlist_paths: Vec<String>,
    pub pe_metadata: bool,
    /// `None` selects no file events, so only process and loaded images are
    /// resolved.
    pub written_files: Option<WrittenFileSelector>,
}

impl ArtifactRuntime {
    pub(crate) fn capture(platform: Platform) -> Self {
        Self {
            detectors: None,
            alert_sink: None,
            response_engine: None,
            match_debug: MatchDebugLevel::Off,
            yara_allowlist_paths: Vec::new(),
            pe_metadata: platform == Platform::Windows,
            written_files: None,
        }
    }
}

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
    *ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::downgrade(&state);
    let parts = ResolverParts::new(
        downstream,
        host_state,
        runtime,
        Arc::clone(&state),
        ARTIFACT_QUEUE_CAPACITY,
    );
    let mut upstream = SensorEventRouter::new();
    upstream.register_handler(Box::new(parts.ingress));
    let admission = parts.admission;
    let deferred = parts.deferred;
    let resolver = parts.resolver;
    let resolve_rx = parts.resolve_rx;
    let worker = tokio::task::spawn_blocking(move || {
        run_resolver_stages(
            admission,
            deferred,
            resolver,
            resolve_rx,
            Arc::new(open_artifact),
        )
    });
    (
        Arc::new(upstream),
        worker,
        ArtifactResolverHandle { _state: state },
    )
}

/// Run admission on the calling thread, and resolution and deferred detection
/// beside it, returning once every queue has closed and drained.
fn run_resolver_stages(
    admission: Admission,
    deferred: Option<DeferredDetection>,
    resolver: ArtifactResolver,
    mut resolve_rx: mpsc::Receiver<ArtifactJob>,
    open: ArtifactOpener,
) {
    std::thread::scope(|scope| {
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
struct ResolverParts {
    ingress: ArtifactEventHandler,
    admission: Admission,
    deferred: Option<DeferredDetection>,
    resolver: ArtifactResolver,
    resolve_rx: mpsc::Receiver<ArtifactJob>,
}

impl ResolverParts {
    fn new(
        downstream: Arc<SensorEventRouter>,
        host_state: Arc<HostState>,
        runtime: ArtifactRuntime,
        state: Arc<ResolverState>,
        resolve_capacity: usize,
    ) -> Self {
        let (resolve_tx, resolve_rx) = mpsc::channel(resolve_capacity);
        let (admission_tx, admission_rx) = std::sync::mpsc::sync_channel(ADMISSION_QUEUE_CAPACITY);
        let pending = Arc::new(AtomicUsize::new(0));
        // Only a detecting runtime has rules to defer; capture evaluates none.
        let (deferred_tx, deferred) = match &runtime.detectors {
            Some(detectors) => {
                let (tx, rx) = std::sync::mpsc::sync_channel(DEFERRED_QUEUE_CAPACITY);
                (
                    Some(tx),
                    Some(DeferredDetection {
                        rx,
                        detectors: Arc::clone(detectors),
                        host_state: Arc::clone(&host_state),
                        alert_sink: runtime.alert_sink.clone(),
                        response_engine: runtime.response_engine.clone(),
                        state: Arc::clone(&state),
                    }),
                )
            }
            None => (None, None),
        };
        Self {
            ingress: ArtifactEventHandler {
                resolve_tx,
                admission_tx,
                deferred_tx,
                pending: Arc::clone(&pending),
                downstream: Arc::clone(&downstream),
                runtime: runtime.clone(),
                state: Arc::clone(&state),
            },
            admission: Admission {
                rx: admission_rx,
                pending,
                downstream,
                state: Arc::clone(&state),
            },
            deferred,
            resolver: ArtifactResolver::new(host_state, runtime, state),
            resolve_rx,
        }
    }
}

struct ArtifactEventHandler {
    resolve_tx: mpsc::Sender<ArtifactJob>,
    admission_tx: std::sync::mpsc::SyncSender<AdmissionEntry>,
    /// Present when a detecting runtime can defer rules to after resolution.
    deferred_tx: Option<std::sync::mpsc::SyncSender<DeferredEntry>>,
    /// Admission entries not yet routed. Ingress is the only producer, so a
    /// zero here means every earlier event has already reached downstream.
    pending: Arc<AtomicUsize>,
    downstream: Arc<SensorEventRouter>,
    runtime: ArtifactRuntime,
    state: Arc<ResolverState>,
}

impl ArtifactEventHandler {
    /// Admit `event` in ingest order. Without an outstanding admission it is
    /// routed inline; otherwise it queues behind the events already waiting.
    /// A `deferred` event reaches admission marked so its deferred-pass rules
    /// are left to the deferred stage.
    fn admit(&self, event: &CanonicalEvent, pe: Option<PeReceiver>, deferred: bool) {
        let marked;
        let event = if deferred {
            let mut copy = event.clone();
            copy.set_deferred_pass_pending(true);
            marked = copy;
            &marked
        } else {
            event
        };
        if pe.is_none() && self.pending.load(Ordering::Acquire) == 0 {
            self.downstream.route_event(event);
            return;
        }
        let entry = AdmissionEntry {
            event: event.clone(),
            pe,
            admit_by: Instant::now()
                .checked_add(ADMISSION_BUDGET)
                .unwrap_or_else(Instant::now),
        };
        self.pending.fetch_add(1, Ordering::AcqRel);
        let entry = match self.admission_tx.try_send(entry) {
            Ok(()) => return,
            Err(std::sync::mpsc::TrySendError::Full(entry)) => {
                // Every queued entry is released within its budget, so this
                // wait is bounded; the sensor channel absorbs it meanwhile.
                self.state
                    .counters
                    .admission_backpressure
                    .fetch_add(1, Ordering::Relaxed);
                entry
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(entry)) => entry,
        };
        if let Err(std::sync::mpsc::SendError(entry)) = self.admission_tx.send(entry) {
            self.pending.fetch_sub(1, Ordering::AcqRel);
            self.downstream.route_event(&entry.event);
        }
    }

    /// Hand the event's deferred-pass rules to the deferred stage. Returns
    /// false when that stage cannot take it, so admission keeps every rule.
    fn defer(
        &self,
        event: &CanonicalEvent,
        needs: ArtifactFieldNeeds,
        fields: DeferredReceiver,
    ) -> bool {
        let Some(deferred_tx) = &self.deferred_tx else {
            return false;
        };
        let entry = DeferredEntry {
            event: event.clone(),
            needs,
            fields,
            evaluate_by: Instant::now()
                .checked_add(DEFERRED_DETECTION_BUDGET)
                .unwrap_or_else(Instant::now),
        };
        match deferred_tx.try_send(entry) {
            Ok(()) => {
                self.state
                    .counters
                    .deferred_queued
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.state
                    .counters
                    .deferred_queue_saturated
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
        }
    }
}

impl CanonicalEventHandler for ArtifactEventHandler {
    fn handle_event(&self, event: &CanonicalEvent) {
        let Some(target) = ArtifactTarget::from_event(event, self.runtime.written_files.as_ref())
        else {
            self.admit(event, None, false);
            return;
        };
        let plan = ResolvePlan::snapshot(&self.runtime, event, &target);
        if plan.needs.is_empty() {
            self.admit(event, None, false);
            return;
        }
        if target.kind == ArtifactKind::WrittenFile && target.expected.is_none() {
            // Without an event-time identity the resolver could scan whatever
            // replaced the file and report it as the file this event wrote.
            self.state
                .counters
                .identity_unavailable
                .fetch_add(1, Ordering::Relaxed);
            self.admit(event, None, false);
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
            if plan.deferred.is_empty() || self.deferred_tx.is_none() {
                (None, None)
            } else {
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                (Some(tx), Some(rx))
            };
        let deferred_needs = plan.deferred;
        let written_file = (target.kind == ArtifactKind::WrittenFile)
            .then(|| Box::new(event.normalized().clone()));
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
            crate::telemetry::ChannelId::ArtifactResolution,
            &self.resolve_tx,
            job,
        ) {
            Ok(()) => {
                self.state.counters.queued.fetch_add(1, Ordering::Relaxed);
                let deferred =
                    deferred_fields.is_some_and(|fields| self.defer(event, deferred_needs, fields));
                self.admit(event, pe, deferred);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.state
                    .counters
                    .queue_saturated
                    .fetch_add(1, Ordering::Relaxed);
                debug!("Artifact resolver queue full; admitting base event");
                self.admit(event, None, false);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                debug!("Artifact resolver stopped; admitting base event");
                self.admit(event, None, false);
            }
        }
    }
}

type PeReceiver = std::sync::mpsc::Receiver<Option<PeMetadata>>;
type PeSender = std::sync::mpsc::SyncSender<Option<PeMetadata>>;

struct AdmissionEntry {
    event: CanonicalEvent,
    /// Resolved PE metadata, or `None` when the artifact has none. A dropped
    /// sender means resolution ended without it.
    pe: Option<PeReceiver>,
    admit_by: Instant,
}

/// Routes events downstream in exactly the order ingress accepted them.
struct Admission {
    rx: std::sync::mpsc::Receiver<AdmissionEntry>,
    pending: Arc<AtomicUsize>,
    downstream: Arc<SensorEventRouter>,
    state: Arc<ResolverState>,
}

impl Admission {
    fn run(self) {
        while let Ok(mut entry) = self.rx.recv() {
            if let Some(pe) = entry.pe.take() {
                let metadata = match pe.try_recv() {
                    Ok(metadata) => metadata,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        let remaining = entry.admit_by.saturating_duration_since(Instant::now());
                        match pe.recv_timeout(remaining) {
                            Ok(metadata) => metadata,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                self.state
                                    .counters
                                    .admission_budget_exceeded
                                    .fetch_add(1, Ordering::Relaxed);
                                None
                            }
                        }
                    }
                };
                if let Some(metadata) = metadata {
                    apply_pe_metadata(&mut entry.event, &metadata);
                }
            }
            self.downstream.route_event(&entry.event);
            self.pending.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

type DeferredReceiver = std::sync::mpsc::Receiver<DeferredFields>;
type DeferredSender = std::sync::mpsc::SyncSender<DeferredFields>;

/// What resolution learned for a deferred pass: the artifact fields, and PE
/// metadata so the deferred event is no poorer than the admitted one.
#[derive(Debug, Default)]
struct DeferredFields {
    hashes: Option<ComputedHashes>,
    imphash: Option<String>,
    pe_metadata: Option<PeMetadata>,
}

struct DeferredEntry {
    /// The event as ingress accepted it, before admission-time enrichment.
    event: CanonicalEvent,
    needs: ArtifactFieldNeeds,
    /// A dropped sender means resolution ended without artifact fields.
    fields: DeferredReceiver,
    evaluate_by: Instant,
}

/// Evaluates deferred-pass rules exactly once per deferred event, in the
/// order ingress deferred them, each no later than its own budget.
struct DeferredDetection {
    rx: std::sync::mpsc::Receiver<DeferredEntry>,
    detectors: Arc<DetectorStore>,
    host_state: Arc<HostState>,
    alert_sink: Option<AlertSink>,
    response_engine: Option<ResponseEngine>,
    state: Arc<ResolverState>,
}

impl DeferredDetection {
    fn run(self) {
        while let Ok(mut entry) = self.rx.recv() {
            let fields = match entry.fields.try_recv() {
                Ok(fields) => Some(fields),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    let remaining = entry.evaluate_by.saturating_duration_since(Instant::now());
                    match entry.fields.recv_timeout(remaining) {
                        Ok(fields) => Some(fields),
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            self.state
                                .counters
                                .deferred_budget_exceeded
                                .fetch_add(1, Ordering::Relaxed);
                            None
                        }
                    }
                }
            };
            let enriched = fields.is_some_and(|fields| {
                if let Some(metadata) = &fields.pe_metadata {
                    apply_pe_metadata(&mut entry.event, metadata);
                }
                apply_artifact_fields(
                    &mut entry.event,
                    entry.needs,
                    fields.hashes.as_ref(),
                    fields.imphash.as_deref(),
                )
            });
            let counter = if enriched {
                &self.state.counters.deferred_enriched
            } else {
                &self.state.counters.deferred_unenriched
            };
            counter.fetch_add(1, Ordering::Relaxed);
            self.evaluate(&entry.event);
        }
    }

    fn evaluate(&self, event: &CanonicalEvent) {
        let detectors = EventDetectors::snapshot(&self.detectors);
        for result in detectors.evaluate_pass_with_origins(event, DetectionPass::Deferred) {
            let mut alert = result.alert;
            self.host_state
                .enrich_process_context(&mut alert.event, result.process_start_key);
            if let Some(sink) = &self.alert_sink {
                sink.write_alert(&alert);
            }
            if let Some(response) = &self.response_engine {
                response.handle_alert(&alert);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactKind {
    /// The executable of a process start.
    ProcessImage,
    /// A module loaded into a process. PE metadata, and `Hashes`/`Imphash`
    /// when a deferred-pass rule selects on them, are resolved.
    LoadedImage,
    /// A file named by a canonical file event and chosen by the
    /// [`WrittenFileSelector`].
    WrittenFile,
}

/// What the opened file must still be for its bytes to belong to the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpectedIdentity {
    /// Object, size, and timestamps measured at exec. Any change rejects it.
    Exact(FileIdentity),
    /// The filesystem object a file event touched. Its content may have grown
    /// since the event, but a replacement at the same path is rejected.
    Object(FileObjectIdentity),
}

impl ExpectedIdentity {
    fn matches(&self, opened: &FileIdentity) -> bool {
        match self {
            Self::Exact(expected) => expected == opened,
            Self::Object(expected) => opened.matches_object(expected),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ArtifactTarget {
    pub kind: ArtifactKind,
    path: PathBuf,
    display_path: String,
    pid: u32,
    pub expected: Option<ExpectedIdentity>,
}

impl ArtifactTarget {
    pub(crate) fn from_event(
        event: &CanonicalEvent,
        written_files: Option<&WrittenFileSelector>,
    ) -> Option<Self> {
        let (kind, display_path, expected) = match &event.normalized().fields {
            EventFields::ProcessCreation(fields) if event.action == SensorAction::Start => (
                ArtifactKind::ProcessImage,
                fields.image.clone(),
                fields
                    .exec
                    .as_ref()
                    .and_then(|exec| exec.file_identity.clone())
                    .map(ExpectedIdentity::Exact),
            ),
            EventFields::ImageLoad(fields) => {
                (ArtifactKind::LoadedImage, fields.image_loaded.clone(), None)
            }
            EventFields::FileEvent(fields)
                if matches!(
                    event.action,
                    SensorAction::Create | SensorAction::Modify | SensorAction::Rename
                ) && written_files.is_some_and(|select| select(event, fields)) =>
            {
                (
                    ArtifactKind::WrittenFile,
                    fields.target_filename.clone(),
                    fields.file_identity.map(ExpectedIdentity::Object),
                )
            }
            _ => return None,
        };
        let display_path = display_path.filter(|path| !path.is_empty())?;
        Some(Self {
            kind,
            path: normalize_path(event.normalized().platform, &display_path),
            display_path,
            pid: event.pid.unwrap_or(0),
            expected,
        })
    }
}

fn normalize_path(platform: Platform, path: &str) -> PathBuf {
    #[cfg(windows)]
    if platform == Platform::Windows {
        let cleaned = path.strip_prefix("\\??\\").unwrap_or(path);
        return PathBuf::from(crate::utils::convert_nt_to_dos(cleaned));
    }
    let _ = platform;
    PathBuf::from(path)
}

#[derive(Clone)]
struct ResolvePlan {
    needs: ArtifactNeeds,
    /// Artifact fields the deferred pass needs for this event.
    deferred: ArtifactFieldNeeds,
    ioc: Option<Arc<crate::ioc::IocEngine>>,
    yara: Option<(u64, Arc<Scanner>)>,
    max_read_bytes: u64,
    hash_max_bytes: u64,
    yara_max_bytes: u64,
    deadline: Duration,
    match_debug: MatchDebugLevel,
}

impl ResolvePlan {
    fn snapshot(
        runtime: &ArtifactRuntime,
        event: &CanonicalEvent,
        target: &ArtifactTarget,
    ) -> Self {
        let path = &target.path;
        let scans_content = target.kind != ArtifactKind::LoadedImage;
        let pe_image = event.normalized().platform == Platform::Windows
            && matches!(
                event.normalized().fields,
                EventFields::ProcessCreation(_) | EventFields::ImageLoad(_)
            );
        let pe_metadata = runtime.pe_metadata && pe_image;

        let mut needs = ArtifactNeeds {
            pe_metadata,
            ..ArtifactNeeds::default()
        };
        let mut max_read_bytes = if pe_metadata { PE_MAX_READ_BYTES } else { 0 };
        let mut hash_max_bytes = 0;
        let mut yara_max_bytes = 0;
        let mut deadline = ARTIFACT_DEADLINE;
        let mut ioc = None;
        let mut yara = None;
        // Only Windows PE images carry Sysmon's `Hashes` and `Imphash`.
        let deferred = match &runtime.detectors {
            Some(detectors) if pe_image => {
                detectors.sigma().deferred_field_needs(event.normalized())
            }
            _ => ArtifactFieldNeeds::default(),
        };
        if !deferred.is_empty() {
            needs.hashes = HashRequirements {
                md5: deferred.md5,
                sha1: deferred.sha1,
                sha256: deferred.sha256,
            };
            needs.imphash = deferred.imphash;
            hash_max_bytes = PE_MAX_READ_BYTES;
            max_read_bytes = max_read_bytes.max(PE_MAX_READ_BYTES);
        }

        if scans_content {
            if let Some(detectors) = &runtime.detectors {
                let current_ioc = detectors.ioc().clone();
                if current_ioc.wants_hashing()
                    && !current_ioc.is_hash_allowlisted(&path.to_string_lossy())
                {
                    let ioc_hashes = current_ioc.hash_requirements();
                    needs.hashes = HashRequirements {
                        md5: needs.hashes.md5 || ioc_hashes.md5,
                        sha1: needs.hashes.sha1 || ioc_hashes.sha1,
                        sha256: needs.hashes.sha256 || ioc_hashes.sha256,
                    };
                    // One digest pass serves both consumers, so it covers the
                    // larger of their size limits.
                    hash_max_bytes =
                        hash_max_bytes.max(nonzero_limit(current_ioc.max_file_size_bytes()));
                    max_read_bytes = max_read_bytes.max(hash_max_bytes);
                    ioc = Some(current_ioc);
                }

                let (generation, current_yara) = detectors.yara_with_generation();
                if current_yara.compiled_files() > 0
                    && !scanner::is_path_allowlisted(
                        &path.to_string_lossy(),
                        &runtime.yara_allowlist_paths,
                    )
                {
                    needs.yara = true;
                    yara_max_bytes = nonzero_limit(current_yara.limits().max_file_bytes);
                    max_read_bytes = max_read_bytes.max(yara_max_bytes);
                    if !current_yara.limits().timeout.is_zero() {
                        deadline = deadline.min(current_yara.limits().timeout);
                    }
                    yara = Some((generation, current_yara));
                }
            }
        }

        Self {
            needs,
            deferred,
            ioc,
            yara,
            max_read_bytes: max_read_bytes.min(ARTIFACT_MAX_READ_BYTES),
            hash_max_bytes,
            yara_max_bytes,
            deadline,
            match_debug: runtime.match_debug,
        }
    }
}

fn nonzero_limit(limit: u64) -> u64 {
    if limit == 0 {
        ARTIFACT_MAX_READ_BYTES
    } else {
        limit
    }
}

struct ArtifactJob {
    target: ArtifactTarget,
    plan: ResolvePlan,
    enqueued_at: Instant,
    /// Present while admission waits on PE metadata for this artifact.
    pe_ready: Option<PeSender>,
    /// Present while the deferred stage waits on this artifact's fields.
    deferred_ready: Option<DeferredSender>,
    /// PE metadata published for this job, handed on to the deferred pass.
    resolved_pe: Option<PeMetadata>,
    /// Hashes published for this job, retained so IOC alerts survive a later
    /// consumer failure.
    resolved_hashes: Option<ComputedHashes>,
    process_start_key: Option<crate::sensor::ProcessStartKey>,
    /// Fidelity limitations on the image and PID the scan alerts report.
    provenance: crate::models::Provenance,
    platform: Platform,
    provider: String,
    /// The file event a written-file target came from, reported as the alert
    /// subject instead of a process image.
    written_file: Option<Box<NormalizedEvent>>,
}

impl ArtifactJob {
    /// Alerts on a written file describe that file and its writer, the way
    /// the file event did, rather than presenting it as a process image.
    fn describe_subject(&self, alert: &mut Alert) {
        if let Some(event) = &self.written_file {
            let mut subject = (**event).clone();
            subject.timestamp = std::mem::take(&mut alert.event.timestamp);
            subject.source_seq = None;
            subject.ingest_seq = 0;
            alert.event = subject;
        }
    }

    /// Release admission as soon as PE metadata is known, or known absent.
    fn publish_pe(&mut self, metadata: Option<PeMetadata>) {
        if self.deferred_ready.is_some() {
            self.resolved_pe = metadata.clone();
        }
        if let Some(ready) = self.pe_ready.take() {
            let _ = ready.try_send(metadata);
        }
    }

    /// Release the deferred pass once the artifact fields are known, or known
    /// unavailable. Only the first call sends.
    fn publish_deferred(&mut self, hashes: Option<ComputedHashes>, imphash: Option<String>) {
        self.resolved_hashes = hashes.clone();
        if let Some(ready) = self.deferred_ready.take() {
            let _ = ready.try_send(DeferredFields {
                hashes,
                imphash,
                pe_metadata: self.resolved_pe.take(),
            });
        }
    }
}

#[derive(Clone)]
struct ArtifactResolver {
    host_state: Arc<HostState>,
    runtime: ArtifactRuntime,
    state: Arc<ResolverState>,
}

impl ArtifactResolver {
    fn new(
        host_state: Arc<HostState>,
        runtime: ArtifactRuntime,
        state: Arc<ResolverState>,
    ) -> Self {
        Self {
            host_state,
            runtime,
            state,
        }
    }

    /// Resolve queued artifacts on up to [`ARTIFACT_IO_ISOLATION_LIMIT`] I/O
    /// threads. A thread blocked in the OS keeps its slot until the call
    /// returns; a job that cannot get a slot before its deadline is skipped.
    fn run(&self, rx: &mut mpsc::Receiver<ArtifactJob>, open: ArtifactOpener) {
        info!(target: "artifact", "Artifact resolver worker started");
        let active = Arc::new(AtomicUsize::new(0));
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let mut latest_deadline = Instant::now();
        let timer = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("artifact resolver timer runtime");
        let mut settling = Vec::<ArtifactJob>::new();
        let mut channel_closed = false;
        loop {
            let now = Instant::now();
            if let Some(index) = settling.iter().position(|job| {
                now.saturating_duration_since(job.enqueued_at) >= WRITTEN_FILE_SETTLE_DELAY
            }) {
                let job = settling.swap_remove(index);
                self.dispatch_job(
                    job,
                    &open,
                    &active,
                    &done_tx,
                    &done_rx,
                    &mut latest_deadline,
                );
                continue;
            }

            if channel_closed {
                if settling.is_empty() {
                    break;
                }
                let wait = settling
                    .iter()
                    .map(|job| {
                        job.enqueued_at
                            .checked_add(WRITTEN_FILE_SETTLE_DELAY)
                            .unwrap_or_else(Instant::now)
                            .saturating_duration_since(now)
                    })
                    .min()
                    .unwrap_or_default();
                std::thread::sleep(wait);
                continue;
            }

            if settling.len() >= ARTIFACT_QUEUE_CAPACITY {
                let wait = settling
                    .iter()
                    .map(|job| {
                        job.enqueued_at
                            .checked_add(WRITTEN_FILE_SETTLE_DELAY)
                            .unwrap_or_else(Instant::now)
                            .saturating_duration_since(now)
                    })
                    .min()
                    .unwrap_or_default();
                std::thread::sleep(wait);
                continue;
            }

            let wait = settling.iter().map(|job| {
                job.enqueued_at
                    .checked_add(WRITTEN_FILE_SETTLE_DELAY)
                    .unwrap_or_else(Instant::now)
                    .saturating_duration_since(now)
            });
            let received = match wait.min() {
                Some(wait) => timer
                    .block_on(async { tokio::time::timeout(wait, rx.recv()).await })
                    .ok()
                    .flatten(),
                None => timer.block_on(rx.recv()),
            };
            let Some(job) = received else {
                channel_closed = rx.is_closed();
                continue;
            };
            if job.target.kind == ArtifactKind::WrittenFile {
                if let Some(existing) = settling.iter_mut().find(|existing| {
                    existing.target.path == job.target.path
                        && existing.target.expected == job.target.expected
                }) {
                    *existing = job;
                } else {
                    settling.push(job);
                }
            } else {
                self.dispatch_job(
                    job,
                    &open,
                    &active,
                    &done_tx,
                    &done_rx,
                    &mut latest_deadline,
                );
            }
        }
        // In-flight work gets until its own deadline. A thread still blocked
        // in the OS after that is detached: a deadline cannot cancel it.
        while active.load(Ordering::Acquire) > 0 {
            let remaining = latest_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let _ = done_rx.recv_timeout(remaining);
        }
        info!(target: "artifact", "Artifact resolver worker stopped");
    }

    fn dispatch_job(
        &self,
        job: ArtifactJob,
        open: &ArtifactOpener,
        active: &Arc<AtomicUsize>,
        done_tx: &std::sync::mpsc::Sender<()>,
        done_rx: &std::sync::mpsc::Receiver<()>,
        latest_deadline: &mut Instant,
    ) {
        let deadline_at = job
            .enqueued_at
            .checked_add(job.plan.deadline)
            .unwrap_or_else(Instant::now);
        while active.load(Ordering::Acquire) >= ARTIFACT_IO_ISOLATION_LIMIT {
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let _ = done_rx.recv_timeout(remaining);
        }
        if Instant::now() >= deadline_at {
            self.state
                .counters
                .deadline_exceeded
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let resolver = self.clone();
        let open = Arc::clone(open);
        let slot = Arc::clone(active);
        let done = done_tx.clone();
        slot.fetch_add(1, Ordering::AcqRel);
        let spawned = std::thread::Builder::new()
            .name("artifact-io".to_string())
            .spawn(move || {
                resolver.resolve_job(job, deadline_at, |path| open(path));
                slot.fetch_sub(1, Ordering::AcqRel);
                let _ = done.send(());
            });
        match spawned {
            Ok(_detached) => *latest_deadline = (*latest_deadline).max(deadline_at),
            Err(error) => {
                active.fetch_sub(1, Ordering::AcqRel);
                self.state
                    .counters
                    .worker_saturated
                    .fetch_add(1, Ordering::Relaxed);
                debug!(target: "artifact", %error, "Could not isolate artifact I/O");
            }
        }
    }

    fn resolve_job<F>(&self, mut job: ArtifactJob, deadline_at: Instant, open: F)
    where
        F: FnOnce(&Path) -> io::Result<File>,
    {
        let target = job.target.clone();
        let plan = job.plan.clone();
        match self.resolve_until_with_opener(
            &target,
            &plan,
            deadline_at,
            &AtomicBool::new(false),
            &mut job,
            open,
        ) {
            Ok(artifact) => {
                job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
                self.apply(&job, &artifact);
                self.state.counters.resolved.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                if let Some(hashes) = &job.resolved_hashes {
                    self.apply_hash_iocs(&job, hashes);
                }
                // Evaluate the deferred pass now rather than at its budget.
                job.publish_deferred(None, None);
                debug!(
                    target: "artifact",
                    file = %target.path.display(),
                    outcome = error.kind(),
                    error = %error,
                    "Artifact resolution did not complete"
                );
            }
        }
    }

    #[cfg(test)]
    fn resolve_with_opener<F>(
        &self,
        target: &ArtifactTarget,
        plan: &ResolvePlan,
        open: F,
    ) -> Result<Artifact, ResolveError>
    where
        F: FnOnce(&Path) -> io::Result<File>,
    {
        let deadline_at = Instant::now()
            .checked_add(plan.deadline)
            .unwrap_or_else(Instant::now);
        let mut job = ArtifactJob {
            target: target.clone(),
            plan: plan.clone(),
            enqueued_at: Instant::now(),
            pe_ready: None,
            deferred_ready: None,
            resolved_pe: None,
            resolved_hashes: None,
            process_start_key: None,
            provenance: Default::default(),
            platform: Platform::Linux,
            provider: "test".to_string(),
            written_file: None,
        };
        self.resolve_until_with_opener(
            target,
            plan,
            deadline_at,
            &AtomicBool::new(false),
            &mut job,
            open,
        )
    }

    fn resolve_until_with_opener<F>(
        &self,
        target: &ArtifactTarget,
        plan: &ResolvePlan,
        deadline_at: Instant,
        deadline_recorded: &AtomicBool,
        job: &mut ArtifactJob,
        open: F,
    ) -> Result<Artifact, ResolveError>
    where
        F: FnOnce(&Path) -> io::Result<File>,
    {
        let mut file = open(&target.path).map_err(|error| {
            self.state
                .counters
                .open_failed
                .fetch_add(1, Ordering::Relaxed);
            ResolveError::Open(error)
        })?;
        let identity = file_identity::from_file(&file).ok_or_else(|| {
            self.state
                .counters
                .identity_mismatch
                .fetch_add(1, Ordering::Relaxed);
            ResolveError::Identity
        })?;
        if target
            .expected
            .as_ref()
            .is_some_and(|expected| !expected.matches(&identity))
        {
            self.state
                .counters
                .identity_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::Identity);
        }

        let mut artifact = Artifact {
            identity: Some(identity.clone()),
            ..Artifact::default()
        };
        let size = file
            .metadata()
            .map_err(|error| {
                self.state
                    .counters
                    .read_failed
                    .fetch_add(1, Ordering::Relaxed);
                ResolveError::Read(error)
            })?
            .len();
        if plan.max_read_bytes == 0 || size > plan.max_read_bytes {
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::TooLarge {
                size,
                limit: plan.max_read_bytes,
            });
        }
        if target.kind == ArtifactKind::WrittenFile
            && !written_file_qualifies(&target.path, &mut file, size).map_err(|error| {
                self.state
                    .counters
                    .read_failed
                    .fetch_add(1, Ordering::Relaxed);
                ResolveError::Read(error)
            })?
        {
            return Ok(artifact);
        }

        let mut missing = plan.needs;
        {
            let mut stores = self
                .state
                .stores
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            stores.load(&identity, plan, &mut artifact, &mut missing);
        }
        if plan.needs.pe_metadata && !missing.pe_metadata {
            self.publish_pe(job, artifact.pe_metadata.clone());
        }
        if !missing.pe_metadata && !missing.needs_digest_read() {
            job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
        }
        if Instant::now() >= deadline_at {
            self.record_deadline(deadline_recorded);
            return Err(ResolveError::Deadline(plan.deadline));
        }
        if missing.is_empty() {
            self.state
                .counters
                .cache_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(artifact);
        }
        self.state
            .counters
            .cache_misses
            .fetch_add(1, Ordering::Relaxed);

        if missing.pe_metadata && size > PE_MAX_READ_BYTES {
            missing.pe_metadata = false;
            self.publish_pe(job, None);
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if (missing.hashes.md5 || missing.hashes.sha1 || missing.hashes.sha256)
            && size > plan.hash_max_bytes
        {
            missing.hashes = HashRequirements::default();
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if missing.imphash && size > PE_MAX_READ_BYTES {
            missing.imphash = false;
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if missing.yara && size > plan.yara_max_bytes {
            missing.yara = false;
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if !missing.pe_metadata && !missing.needs_digest_read() {
            job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
        }
        if missing.is_empty() {
            return Ok(artifact);
        }

        let mut bytes = Vec::with_capacity(size.min(1024 * 1024) as usize);
        (&mut file)
            .take(plan.max_read_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                self.state
                    .counters
                    .read_failed
                    .fetch_add(1, Ordering::Relaxed);
                ResolveError::Read(error)
            })?;
        if bytes.len() as u64 > plan.max_read_bytes {
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::TooLarge {
                size: bytes.len() as u64,
                limit: plan.max_read_bytes,
            });
        }
        if file_identity::from_file(&file).as_ref() != Some(&identity) {
            self.state
                .counters
                .identity_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::Identity);
        }
        if Instant::now() >= deadline_at {
            self.record_deadline(deadline_recorded);
            return Err(ResolveError::Deadline(plan.deadline));
        }

        if missing.pe_metadata {
            artifact.pe_metadata = parse_pe_metadata_bytes(&bytes);
            // Cache and publish before the slower consumers run, so a missed
            // admission budget still warms the next start of this image.
            self.state
                .stores
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    identity.clone(),
                    plan,
                    &artifact,
                    StoredParts {
                        pe: true,
                        imphash: false,
                    },
                );
            self.publish_pe(job, artifact.pe_metadata.clone());
            if !missing.needs_digest_read() {
                job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
            }
            if Instant::now() >= deadline_at {
                self.record_deadline(deadline_recorded);
                return Err(ResolveError::Deadline(plan.deadline));
            }
        }
        if missing.hashes.md5 || missing.hashes.sha1 || missing.hashes.sha256 {
            let computed = crate::ioc::compute_hashes_from_bytes(&bytes, missing.hashes);
            // Keep digests the store already had for algorithms not missing.
            artifact.hashes = Some(match artifact.hashes.take() {
                Some(cached) => ComputedHashes {
                    md5: computed.md5.or(cached.md5),
                    sha1: computed.sha1.or(cached.sha1),
                    sha256: computed.sha256.or(cached.sha256),
                },
                None => computed,
            });
            if Instant::now() >= deadline_at {
                self.record_deadline(deadline_recorded);
                return Err(ResolveError::Deadline(plan.deadline));
            }
        }
        if missing.imphash {
            artifact.imphash = parse_imphash_bytes(&bytes);
        }
        if missing.needs_digest_read() {
            // Store and publish before YARA, so a slow scan neither delays the
            // deferred pass nor loses digests that are already known.
            self.state
                .stores
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    identity.clone(),
                    plan,
                    &artifact,
                    StoredParts {
                        pe: false,
                        imphash: missing.imphash,
                    },
                );
            job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
        }
        if missing.yara {
            if let Some((_, scanner)) = &plan.yara {
                let remaining = deadline_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    self.record_deadline(deadline_recorded);
                    return Err(ResolveError::Deadline(plan.deadline));
                }
                match scanner.scan_bytes_with_timeout(&bytes, self.runtime.match_debug, remaining) {
                    Ok(matches) => artifact.yara = Some(matches),
                    Err(error) => {
                        if matches!(
                            &error,
                            ScanError::TimedOut { .. } | ScanError::ProcessDeadline { .. }
                        ) {
                            self.record_deadline(deadline_recorded);
                            return Err(ResolveError::Deadline(plan.deadline));
                        } else {
                            self.state
                                .counters
                                .consumer_failed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        debug!(
                            target: "artifact",
                            file = %target.path.display(),
                            outcome = error.kind(),
                            error = %error,
                            "Artifact YARA consumer did not complete"
                        );
                        return Err(ResolveError::Consumer(error.to_string()));
                    }
                }
            }
        }

        if Instant::now() >= deadline_at {
            self.record_deadline(deadline_recorded);
            return Err(ResolveError::Deadline(plan.deadline));
        }

        let mut stores = self
            .state
            .stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stores.insert(
            identity,
            plan,
            &artifact,
            StoredParts {
                pe: false,
                imphash: false,
            },
        );
        Ok(artifact)
    }

    fn record_deadline(&self, recorded: &AtomicBool) {
        if !recorded.swap(true, Ordering::Relaxed) {
            self.state
                .counters
                .deadline_exceeded
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Hand PE metadata to admission and executable metadata to the process cache.
    fn publish_pe(&self, job: &mut ArtifactJob, metadata: Option<PeMetadata>) {
        if job.target.kind == ArtifactKind::ProcessImage {
            if let (Some(metadata), Some(key)) = (&metadata, job.process_start_key) {
                self.host_state
                    .processes
                    .enrich_pe_metadata(key.pid, key.start_time, metadata);
            }
        }
        job.publish_pe(metadata);
    }

    /// Raise the detections that consume artifact bytes directly. They run
    /// after admission and never feed Sigma.
    fn apply(&self, job: &ArtifactJob, artifact: &Artifact) {
        if let Some(hashes) = &artifact.hashes {
            self.apply_hash_iocs(job, hashes);
        }

        if let Some(matches) = &artifact.yara {
            for rule_match in matches {
                let details = crate::runtime::yara::build_yara_match_details(
                    self.runtime.match_debug,
                    rule_match,
                );
                let mut alert = crate::runtime::yara::build_yara_alert(
                    &rule_match.rule,
                    rule_match.metadata_id.clone(),
                    &job.target.display_path,
                    job.target.pid,
                    &job.provenance,
                    details,
                    job.platform,
                    &job.provider,
                );
                job.describe_subject(&mut alert);
                if let Some(sink) = &self.runtime.alert_sink {
                    sink.write_yara_alert(&alert, YaraScanSource::File);
                }
                if let Some(response) = &self.runtime.response_engine {
                    response.handle_alert(&alert);
                }
            }
        }
    }

    fn apply_hash_iocs(&self, job: &ArtifactJob, hashes: &ComputedHashes) {
        if let Some(ioc) = &job.plan.ioc {
            for ioc_match in ioc.match_hashes(hashes) {
                let mut alert = ioc.build_alert_for_hash_match(
                    &ioc_match,
                    &job.target.display_path,
                    job.target.pid,
                    &job.provenance,
                    job.platform,
                    &job.provider,
                );
                job.describe_subject(&mut alert);
                if let Some(sink) = &self.runtime.alert_sink {
                    sink.write_alert(&alert);
                }
                if let Some(response) = &self.runtime.response_engine {
                    response.handle_alert(&alert);
                }
            }
        }
    }
}

fn written_file_qualifies(path: &Path, file: &mut File, size: u64) -> io::Result<bool> {
    if size == 0 {
        return Ok(false);
    }
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(qualifying_written_file_extension)
    {
        return Ok(true);
    }

    let mut magic = [0u8; WRITTEN_FILE_MAGIC_BYTES];
    let read = file.read(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(qualifying_written_file_magic(&magic[..read]))
}

fn qualifying_written_file_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "com"
            | "cpl"
            | "msi"
            | "msp"
            | "ps1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "wsh"
            | "hta"
            | "jar"
            | "class"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "py"
            | "pyw"
            | "pl"
            | "rb"
            | "php"
            | "elf"
            | "so"
            | "dylib"
            | "dmg"
            | "pkg"
            | "deb"
            | "rpm"
            | "apk"
            | "zip"
            | "rar"
            | "7z"
            | "gz"
            | "bz2"
            | "xz"
            | "tar"
            | "cab"
            | "iso"
            | "img"
            | "pdf"
            | "doc"
            | "docx"
            | "docm"
            | "xls"
            | "xlsx"
            | "xlsm"
            | "ppt"
            | "pptx"
            | "pptm"
            | "rtf"
            | "lnk"
    )
}

fn qualifying_written_file_magic(bytes: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"MZ",
        b"\x7fELF",
        b"#!",
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"Rar!\x1a\x07",
        b"7z\xbc\xaf\x27\x1c",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"%PDF-",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ];
    PREFIXES.iter().any(|prefix| bytes.starts_with(prefix))
}

fn open_artifact(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path is not a regular file",
        ));
    }
    Ok(file)
}

fn apply_pe_metadata(event: &mut CanonicalEvent, metadata: &PeMetadata) {
    let fields = match &mut event.normalized_mut().fields {
        EventFields::ProcessCreation(fields) => Some((
            &mut fields.original_file_name,
            &mut fields.product,
            &mut fields.description,
            &mut fields.company,
            &mut fields.file_version,
        )),
        EventFields::ImageLoad(fields) => Some((
            &mut fields.original_file_name,
            &mut fields.product,
            &mut fields.description,
            &mut fields.company,
            &mut fields.file_version,
        )),
        _ => None,
    };
    if let Some((original, product, description, company, version)) = fields {
        *original = metadata.original_filename.clone();
        *product = metadata.product.clone();
        *description = metadata.description.clone();
        *company = metadata.company.clone();
        *version = metadata.file_version.clone();
    }
    for (field, present) in [
        ("OriginalFileName", metadata.original_filename.is_some()),
        ("Product", metadata.product.is_some()),
        ("Description", metadata.description.is_some()),
        ("Company", metadata.company.is_some()),
        ("FileVersion", metadata.file_version.is_some()),
    ] {
        if present {
            event.normalized_mut().provenance.mark_derived(field);
        }
    }
}

/// Fill `Hashes` and `Imphash` on a process-start or image-load event from
/// resolved values, limited to what the deferred rules asked for. Returns
/// whether either field was set.
fn apply_artifact_fields(
    event: &mut CanonicalEvent,
    needs: ArtifactFieldNeeds,
    hashes: Option<&ComputedHashes>,
    imphash: Option<&str>,
) -> bool {
    let imphash = imphash.filter(|_| needs.imphash);
    let formatted = sysmon_hashes(needs, hashes, imphash);
    let (hashes_field, imphash_field) = match &mut event.normalized_mut().fields {
        EventFields::ProcessCreation(fields) => (&mut fields.hashes, &mut fields.imphash),
        EventFields::ImageLoad(fields) => (&mut fields.hashes, &mut fields.imphash),
        _ => return false,
    };
    let has_hashes = formatted.is_some();
    let has_imphash = imphash.is_some();
    *hashes_field = formatted;
    *imphash_field = imphash.map(str::to_string);
    // Read from the file after the event, so not a kernel measurement.
    if has_hashes {
        event
            .normalized_mut()
            .provenance
            .mark_derived(crate::engine::HASHES_FIELD);
    }
    if has_imphash {
        event
            .normalized_mut()
            .provenance
            .mark_derived(crate::engine::IMPHASH_FIELD);
    }
    has_hashes || has_imphash
}

/// Sysmon's `Hashes` value: `SHA1=`, `MD5=`, `SHA256=`, `IMPHASH=` in that
/// order, uppercase hex, comma separated, listing only requested values that
/// resolved. `None` when none did, so absence is never an empty string.
fn sysmon_hashes(
    needs: ArtifactFieldNeeds,
    hashes: Option<&ComputedHashes>,
    imphash: Option<&str>,
) -> Option<String> {
    fn digest(wanted: bool, value: Option<&String>) -> Option<&str> {
        value.filter(|_| wanted).map(String::as_str)
    }
    let parts: Vec<String> = [
        (
            "SHA1",
            hashes.and_then(|h| digest(needs.sha1, h.sha1.as_ref())),
        ),
        (
            "MD5",
            hashes.and_then(|h| digest(needs.md5, h.md5.as_ref())),
        ),
        (
            "SHA256",
            hashes.and_then(|h| digest(needs.sha256, h.sha256.as_ref())),
        ),
        ("IMPHASH", imphash.filter(|_| needs.imphash)),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| format!("{name}={}", value.to_ascii_uppercase())))
    .collect();
    (!parts.is_empty()).then(|| parts.join(","))
}

#[derive(Debug, thiserror::Error)]
enum ResolveError {
    #[error("cannot open artifact: {0}")]
    Open(io::Error),
    #[error("artifact identity is unavailable or changed")]
    Identity,
    #[error("cannot read artifact: {0}")]
    Read(io::Error),
    #[error("artifact size {size} exceeds shared read limit {limit}")]
    TooLarge { size: u64, limit: u64 },
    #[error("artifact deadline exceeded after {} ms", .0.as_millis())]
    Deadline(Duration),
    #[error("artifact consumer failed: {0}")]
    Consumer(String),
}

impl ResolveError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Open(_) => "open_failed",
            Self::Identity => "identity_mismatch",
            Self::Read(_) => "read_failed",
            Self::TooLarge { .. } => "oversized",
            Self::Deadline(_) => "deadline_exceeded",
            Self::Consumer(_) => "consumer_failed",
        }
    }
}

struct Cached<T> {
    value: T,
}

/// Optional results a store insert records even when they are absent.
#[derive(Debug, Clone, Copy)]
struct StoredParts {
    pe: bool,
    imphash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct YaraCacheKey {
    identity: FileIdentity,
    generation: u64,
    match_debug: MatchDebugLevel,
}

struct ArtifactStores {
    pe: HashMap<FileIdentity, Cached<Option<PeMetadata>>>,
    hashes: HashMap<FileIdentity, Cached<ComputedHashes>>,
    /// `None` records that the file has no imphash, so it is not re-read.
    imphashes: HashMap<FileIdentity, Cached<Option<String>>>,
    signatures: HashMap<FileIdentity, Cached<ArtifactSignature>>,
    yara: HashMap<YaraCacheKey, Cached<Vec<YaraRuleMatch>>>,
    recency: HashMap<FileIdentity, u64>,
    capacity: usize,
    clock: u64,
    evicted: u64,
    yara_generation: Option<u64>,
}

impl ArtifactStores {
    fn new(capacity: usize) -> Self {
        Self {
            pe: HashMap::new(),
            hashes: HashMap::new(),
            imphashes: HashMap::new(),
            signatures: HashMap::new(),
            yara: HashMap::new(),
            recency: HashMap::new(),
            capacity,
            clock: 0,
            evicted: 0,
            yara_generation: None,
        }
    }

    fn touch(&mut self, identity: &FileIdentity) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.recency.insert(identity.clone(), self.clock);
        self.clock
    }

    fn load(
        &mut self,
        identity: &FileIdentity,
        plan: &ResolvePlan,
        artifact: &mut Artifact,
        missing: &mut ArtifactNeeds,
    ) {
        self.invalidate_yara(plan.yara.as_ref().map(|(generation, _)| *generation));
        self.touch(identity);
        self.evict();
        if missing.pe_metadata {
            if let Some(entry) = self.pe.get_mut(identity) {
                artifact.pe_metadata = entry.value.clone();
                missing.pe_metadata = false;
            }
        }
        if missing.hashes.md5 || missing.hashes.sha1 || missing.hashes.sha256 {
            if let Some(entry) = self.hashes.get_mut(identity) {
                let value = &entry.value;
                if (!missing.hashes.md5 || value.md5.is_some())
                    && (!missing.hashes.sha1 || value.sha1.is_some())
                    && (!missing.hashes.sha256 || value.sha256.is_some())
                {
                    artifact.hashes = Some(value.clone());
                    missing.hashes = HashRequirements {
                        md5: false,
                        sha1: false,
                        sha256: false,
                    };
                }
            }
        }
        if missing.imphash {
            if let Some(entry) = self.imphashes.get_mut(identity) {
                artifact.imphash = entry.value.clone();
                missing.imphash = false;
            }
        }
        if missing.signature {
            if let Some(entry) = self.signatures.get_mut(identity) {
                artifact.signature = Some(entry.value.clone());
                missing.signature = false;
            }
        }
        if missing.yara {
            if let Some((generation, _)) = &plan.yara {
                let key = YaraCacheKey {
                    identity: identity.clone(),
                    generation: *generation,
                    match_debug: plan.match_debug,
                };
                if let Some(entry) = self.yara.get_mut(&key) {
                    artifact.yara = Some(entry.value.clone());
                    missing.yara = false;
                }
            }
        }
    }

    fn insert(
        &mut self,
        identity: FileIdentity,
        plan: &ResolvePlan,
        artifact: &Artifact,
        stored: StoredParts,
    ) {
        self.touch(&identity);
        if stored.pe {
            self.pe.insert(
                identity.clone(),
                Cached {
                    value: artifact.pe_metadata.clone(),
                },
            );
        }
        if let Some(hashes) = &artifact.hashes {
            let merged = if let Some(existing) = self.hashes.remove(&identity) {
                ComputedHashes {
                    md5: hashes.md5.clone().or(existing.value.md5),
                    sha1: hashes.sha1.clone().or(existing.value.sha1),
                    sha256: hashes.sha256.clone().or(existing.value.sha256),
                }
            } else {
                hashes.clone()
            };
            self.hashes
                .insert(identity.clone(), Cached { value: merged });
        }
        if stored.imphash {
            self.imphashes.insert(
                identity.clone(),
                Cached {
                    value: artifact.imphash.clone(),
                },
            );
        }
        if let Some(signature) = &artifact.signature {
            self.signatures.insert(
                identity.clone(),
                Cached {
                    value: signature.clone(),
                },
            );
        }
        if let (Some(matches), Some((generation, _))) = (&artifact.yara, &plan.yara) {
            if self.yara_generation == Some(*generation) {
                self.yara.insert(
                    YaraCacheKey {
                        identity: identity.clone(),
                        generation: *generation,
                        match_debug: plan.match_debug,
                    },
                    Cached {
                        value: matches.clone(),
                    },
                );
            }
        }
        self.evict();
    }

    fn invalidate_yara(&mut self, generation: Option<u64>) {
        let Some(generation) = generation else {
            return;
        };
        match self.yara_generation {
            Some(active) if generation <= active => return,
            Some(_) => self.yara.clear(),
            None => {}
        }
        self.yara_generation = Some(generation);
    }

    /// Revocation freshness is independent from immutable file-derived data.
    #[allow(dead_code)] // Called by the Authenticode refresh path added in #320.
    fn invalidate_signatures(&mut self) {
        self.signatures.clear();
    }

    fn evict(&mut self) {
        while self.recency.len() > self.capacity {
            let Some(identity) = self
                .recency
                .iter()
                .min_by_key(|(_, used)| **used)
                .map(|(identity, _)| identity.clone())
            else {
                break;
            };
            self.recency.remove(&identity);
            self.pe.remove(&identity);
            self.hashes.remove(&identity);
            self.imphashes.remove(&identity);
            self.signatures.remove(&identity);
            self.yara.retain(|key, _| key.identity != identity);
            self.evicted = self.evicted.saturating_add(1);
        }
    }
}

#[cfg(windows)]
fn parse_pe_metadata_bytes(bytes: &[u8]) -> Option<PeMetadata> {
    crate::utils::pe::parse_metadata_bytes(bytes)
}

#[cfg(not(windows))]
fn parse_pe_metadata_bytes(_bytes: &[u8]) -> Option<PeMetadata> {
    None
}

#[cfg(windows)]
fn parse_imphash_bytes(bytes: &[u8]) -> Option<String> {
    crate::utils::imphash::imphash_bytes(bytes)
}

#[cfg(not(windows))]
fn parse_imphash_bytes(_bytes: &[u8]) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::engine::Engine;
    use crate::models::{
        ImageLoadFields, LinuxProcessIdentity, NormalizedEvent, ProcessCreationFields,
    };

    fn process_event(path: &Path, platform: Platform) -> CanonicalEvent {
        CanonicalEvent::from_normalized(NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            source_seq: None,
            ingest_seq: 1,
            platform,
            provider: "test".into(),
            category: crate::models::EventCategory::Process,
            event_id: 1,
            event_id_string: "1".into(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                hashes: None,
                imphash: None,
                container: Default::default(),
                exec: Default::default(),
                linux_identity: Box::<LinuxProcessIdentity>::default(),
                image: Some(path.to_string_lossy().into_owned()),
                image_source: None,
                image_truncated: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                command_line: None,
                process_id: Some("42".into()),
                process_start_time: None,
                cgroup_id: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                parent_user: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                parent_process_id_derived: false,
                windows: Default::default(),
            }),
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        })
    }

    fn image_event(path: &Path) -> CanonicalEvent {
        CanonicalEvent::from_normalized(NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            source_seq: None,
            ingest_seq: 1,
            platform: Platform::Windows,
            provider: "test".into(),
            category: crate::models::EventCategory::ImageLoad,
            event_id: 7,
            event_id_string: "7".into(),
            opcode: 3,
            fields: EventFields::ImageLoad(ImageLoadFields {
                hashes: None,
                imphash: None,
                image_loaded: Some(path.to_string_lossy().into_owned()),
                process_id: Some("42".into()),
                image: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                signed: None,
                signature: None,
                user: None,
            }),
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        })
    }

    fn runtime_with_consumers(root: &Path, bytes: &[u8]) -> ArtifactRuntime {
        use sha2::Digest;

        let rules = root.join("yara");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(
            rules.join("marker.yar"),
            r#"rule Marker { strings: $marker = "evil!!" condition: $marker }"#,
        )
        .unwrap();
        let scanner = Scanner::new(&rules).unwrap();

        let mut cfg = AppConfig::default();
        cfg.ioc.enabled = true;
        cfg.ioc.hashes_path = root.join("hashes.txt");
        cfg.ioc.ips_path = root.join("ips.txt");
        cfg.ioc.domains_path = root.join("domains.txt");
        cfg.ioc.paths_regex_path = root.join("paths.txt");
        cfg.ioc.max_file_size_mb = 1;
        std::fs::write(
            &cfg.ioc.hashes_path,
            hex::encode(sha2::Sha256::digest(bytes)),
        )
        .unwrap();
        for path in [
            &cfg.ioc.ips_path,
            &cfg.ioc.domains_path,
            &cfg.ioc.paths_regex_path,
        ] {
            std::fs::write(path, "").unwrap();
        }
        let detectors = DetectorStore::new(
            Arc::new(Engine::new_for_platform(Platform::Linux)),
            Arc::new(scanner),
            Arc::new(crate::ioc::IocEngine::load(&cfg.ioc)),
        );
        ArtifactRuntime {
            detectors: Some(detectors),
            alert_sink: None,
            response_engine: None,
            match_debug: MatchDebugLevel::Off,
            yara_allowlist_paths: Vec::new(),
            pe_metadata: false,
            written_files: None,
        }
    }

    #[test]
    fn one_open_supplies_hash_and_yara_and_reload_invalidates_only_yara() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let runtime = runtime_with_consumers(temp.path(), bytes);
        let event = process_event(&path, Platform::Linux);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let state = Arc::new(ResolverState::new());
        let worker = ArtifactResolver::new(
            Arc::new(HostState::default()),
            runtime.clone(),
            Arc::clone(&state),
        );
        let opens = AtomicUsize::new(0);

        let first_plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let first = worker
            .resolve_with_opener(&target, &first_plan, |path| {
                opens.fetch_add(1, Ordering::Relaxed);
                File::open(path)
            })
            .unwrap();
        assert!(first.hashes.unwrap().sha256.is_some());
        assert_eq!(first.yara.unwrap().len(), 1);
        assert_eq!(opens.load(Ordering::Relaxed), 1);

        let clean_rules = temp.path().join("clean-yara");
        std::fs::create_dir(&clean_rules).unwrap();
        std::fs::write(
            clean_rules.join("clean.yar"),
            r#"rule Clean { strings: $marker = "not-present" condition: $marker }"#,
        )
        .unwrap();
        runtime
            .detectors
            .as_ref()
            .unwrap()
            .swap_yara(Arc::new(Scanner::new(&clean_rules).unwrap()));
        let second_plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let second = worker
            .resolve_with_opener(&target, &second_plan, |path| {
                opens.fetch_add(1, Ordering::Relaxed);
                File::open(path)
            })
            .unwrap();
        assert!(second.hashes.unwrap().sha256.is_some());
        assert!(second.yara.unwrap().is_empty());
        let snapshot = state.snapshot();
        assert_eq!(snapshot.hash_entries, 1);
        assert_eq!(snapshot.yara_entries, 1);
        assert_eq!(opens.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn hash_ioc_alert_survives_yara_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let mut runtime = runtime_with_consumers(temp.path(), bytes);

        let slow_rules = temp.path().join("slow-yara");
        std::fs::create_dir(&slow_rules).unwrap();
        std::fs::write(
            slow_rules.join("slow.yar"),
            r#"rule Slow {
                condition:
                    for all i in (0..2000000000) : (uint8(i % 6) != 0xff)
            }"#,
        )
        .unwrap();
        let timeout = Duration::from_secs(1);
        let scanner = Scanner::new(&slow_rules)
            .unwrap()
            .with_limits(crate::scanner::ScanLimits {
                timeout,
                max_file_bytes: 1024,
            });
        runtime
            .detectors
            .as_ref()
            .unwrap()
            .swap_yara(Arc::new(scanner));

        let alerts_path = temp.path().join("alerts.ndjson");
        let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
        runtime.alert_sink = Some(AlertSink::new(writer));
        let event = process_event(&path, Platform::Linux);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let deadline_at = Instant::now() + plan.deadline;
        let state = Arc::new(ResolverState::new());
        let worker =
            ArtifactResolver::new(Arc::new(HostState::default()), runtime, Arc::clone(&state));
        worker.resolve_job(
            ArtifactJob {
                target,
                plan,
                enqueued_at: Instant::now(),
                pe_ready: None,
                deferred_ready: None,
                resolved_pe: None,
                resolved_hashes: None,
                process_start_key: None,
                provenance: scanner::scan_subject_provenance(event.provenance()),
                platform: event.normalized().platform,
                provider: event.normalized().provider.clone(),
                written_file: None,
            },
            deadline_at,
            open_artifact,
        );
        drop(guard);

        let alerts = read_alerts(&alerts_path);
        assert_eq!(alerts.len(), 1, "only the completed hash IOC may alert");
        assert_eq!(alerts[0]["edr.rule.engine"], "Ioc");
        let snapshot = state.snapshot();
        assert_eq!(snapshot.hash_entries, 1);
        assert_eq!(snapshot.yara_entries, 0, "a timeout is not a clean scan");
        assert_eq!(snapshot.deadline_exceeded, 1);
        assert_eq!(snapshot.resolved, 0);
    }

    #[test]
    fn successful_hash_and_yara_scan_emits_each_alert_once() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let mut runtime = runtime_with_consumers(temp.path(), bytes);
        let alerts_path = temp.path().join("alerts.ndjson");
        let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
        runtime.alert_sink = Some(AlertSink::new(writer));
        let harness = Harness::start(
            Arc::new(SensorEventRouter::new()),
            runtime,
            Arc::new(open_artifact),
            ARTIFACT_QUEUE_CAPACITY,
        );

        harness
            .ingress
            .handle_event(&process_event(&path, Platform::Linux));
        let state = harness.finish();
        drop(guard);

        let alerts = read_alerts(&alerts_path);
        let engines: Vec<&str> = alerts
            .iter()
            .map(|alert| alert["edr.rule.engine"].as_str().unwrap())
            .collect();
        assert_eq!(engines.len(), 2);
        assert_eq!(engines.iter().filter(|engine| **engine == "Ioc").count(), 1);
        assert_eq!(
            engines.iter().filter(|engine| **engine == "Yara").count(),
            1
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.resolved, 1);
        assert_eq!(snapshot.deadline_exceeded, 0);
    }

    /// Records what downstream saw, in the order it saw it.
    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<Vec<(u64, Instant)>>>);

    impl Seen {
        fn ingest_seqs(&self) -> Vec<u64> {
            self.0.lock().unwrap().iter().map(|(seq, _)| *seq).collect()
        }

        fn wait_for(&self, count: usize) {
            let give_up = Instant::now() + Duration::from_secs(10);
            while self.0.lock().unwrap().len() < count {
                assert!(
                    Instant::now() < give_up,
                    "downstream never saw {count} events"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl CanonicalEventHandler for Seen {
        fn handle_event(&self, event: &CanonicalEvent) {
            self.0
                .lock()
                .unwrap()
                .push((event.normalized().ingest_seq, Instant::now()));
        }
    }

    fn router_with(handler: impl CanonicalEventHandler + 'static) -> Arc<SensorEventRouter> {
        let mut router = SensorEventRouter::new();
        router.register_handler(Box::new(handler));
        Arc::new(router)
    }

    /// An opener that blocks every caller until the gate is released.
    #[derive(Clone)]
    struct Gate(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Gate {
        fn new() -> Self {
            Self(Arc::new((Mutex::new(false), std::sync::Condvar::new())))
        }

        fn opener(&self, entered: Option<std::sync::mpsc::Sender<()>>) -> ArtifactOpener {
            let gate = self.clone();
            Arc::new(move |path| {
                if let Some(entered) = &entered {
                    let _ = entered.send(());
                }
                let (released, wake) = &*gate.0;
                let released = released.lock().unwrap();
                let _released = wake.wait_while(released, |released| !*released).unwrap();
                File::open(path)
            })
        }

        fn release(&self) {
            let (released, wake) = &*self.0;
            *released.lock().unwrap() = true;
            wake.notify_all();
        }
    }

    /// Ingress plus both running stages, wired exactly as
    /// [`spawn_artifact_resolver`] wires them but with a controllable opener.
    struct Harness {
        ingress: ArtifactEventHandler,
        stages: std::thread::JoinHandle<()>,
        state: Arc<ResolverState>,
    }

    impl Harness {
        fn start(
            downstream: Arc<SensorEventRouter>,
            runtime: ArtifactRuntime,
            open: ArtifactOpener,
            resolve_capacity: usize,
        ) -> Self {
            let state = Arc::new(ResolverState::new());
            let ResolverParts {
                ingress,
                admission,
                deferred,
                resolver,
                resolve_rx,
            } = ResolverParts::new(
                downstream,
                Arc::new(HostState::default()),
                runtime,
                Arc::clone(&state),
                resolve_capacity,
            );
            let stages = std::thread::spawn(move || {
                run_resolver_stages(admission, deferred, resolver, resolve_rx, open)
            });
            Self {
                ingress,
                stages,
                state,
            }
        }

        fn finish(self) -> Arc<ResolverState> {
            drop(self.ingress);
            self.stages.join().unwrap();
            self.state
        }
    }

    fn with_ingest_seq(event: CanonicalEvent, ingest_seq: u64) -> CanonicalEvent {
        let mut normalized = event.into_normalized();
        normalized.ingest_seq = ingest_seq;
        CanonicalEvent::from_normalized(normalized)
    }

    fn windows_file_event(ingest_seq: u64) -> CanonicalEvent {
        CanonicalEvent::from_normalized(NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            source_seq: None,
            ingest_seq,
            platform: Platform::Windows,
            provider: "test".into(),
            category: crate::models::EventCategory::File,
            event_id: 11,
            event_id_string: "11".into(),
            opcode: 64,
            fields: EventFields::FileEvent(crate::models::FileEventFields {
                source_filename: None,
                target_filename: Some(r"C:\Temp\later.txt".into()),
                process_id: Some("43".into()),
                image: None,
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: None,
                file_identity: None,
                path_truncated: None,
            }),
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        })
    }

    /// A process start waiting on artifact I/O must not let a later event
    /// reach the recording first: replay rejects a payload whose `ingest_seq`
    /// goes backwards, so the whole Windows capture would be unreplayable.
    #[tokio::test(flavor = "multi_thread")]
    async fn held_artifact_event_keeps_the_recording_replayable() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("held.exe");
        std::fs::write(&image, b"not really a PE").unwrap();
        let payload = temp.path().join("captures").join("session.ndjson");
        let recorder = crate::capture::CaptureRecorder::start(payload.clone(), Platform::Windows)
            .expect("capture starts");
        let downstream = router_with(crate::engine::NormalizedEventHandler::recording(
            Arc::new(HostState::default()),
            recorder.sink(),
        ));

        let gate = Gate::new();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let harness = Harness::start(
            downstream,
            ArtifactRuntime::capture(Platform::Windows),
            gate.opener(Some(entered_tx)),
            ARTIFACT_QUEUE_CAPACITY,
        );

        let producer = tokio::task::spawn_blocking(move || {
            harness.ingress.handle_event(&with_ingest_seq(
                process_event(&image, Platform::Windows),
                1,
            ));
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            harness.ingress.handle_event(&windows_file_event(2));
            gate.release();
            harness.finish();
        });
        producer.await.unwrap();
        recorder.finish().await.expect("capture finalizes");

        let recording = crate::replay::Recording::open(&payload).expect("recording opens");
        let replayed: Vec<u64> = recording
            .events()
            .unwrap()
            .map(|event| {
                event
                    .expect("replay accepts every event")
                    .normalized()
                    .ingest_seq
            })
            .collect();
        assert_eq!(replayed, vec![1, 2]);
    }

    #[test]
    fn blocked_artifact_io_delays_later_events_by_at_most_the_budget() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("blocked.exe");
        std::fs::write(&image, b"artifact").unwrap();
        let seen = Seen::default();
        let gate = Gate::new();
        let harness = Harness::start(
            router_with(seen.clone()),
            ArtifactRuntime::capture(Platform::Windows),
            gate.opener(None),
            ARTIFACT_QUEUE_CAPACITY,
        );

        let submitted = Instant::now();
        harness
            .ingress
            .handle_event(&with_ingest_seq(image_event(&image), 1));
        harness.ingress.handle_event(&windows_file_event(2));
        seen.wait_for(2);

        assert_eq!(seen.ingest_seqs(), vec![1, 2]);
        let routed = seen.0.lock().unwrap()[1].1;
        let waited = routed.duration_since(submitted);
        assert!(
            waited >= ADMISSION_BUDGET,
            "admission released early: {waited:?}"
        );
        assert!(
            waited < ADMISSION_BUDGET + Duration::from_secs(2),
            "admission exceeded its budget: {waited:?}"
        );
        assert_eq!(state_of(&harness).admission_budget_exceeded, 1);

        gate.release();
        harness.finish();
    }

    fn state_of(harness: &Harness) -> ArtifactResolverSnapshot {
        harness.state.snapshot()
    }

    #[test]
    fn saturated_resolver_queue_still_admits_in_order_within_one_budget() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("burst.exe");
        std::fs::write(&image, b"artifact").unwrap();
        let seen = Seen::default();
        let gate = Gate::new();
        let harness = Harness::start(
            router_with(seen.clone()),
            ArtifactRuntime::capture(Platform::Windows),
            gate.opener(None),
            1,
        );

        let total = 64;
        let submitted = Instant::now();
        for seq in 1..=total {
            harness
                .ingress
                .handle_event(&with_ingest_seq(image_event(&image), seq));
        }
        seen.wait_for(total as usize);

        assert_eq!(seen.ingest_seqs(), (1..=total).collect::<Vec<_>>());
        let last = seen.0.lock().unwrap().last().unwrap().1;
        assert!(
            last.duration_since(submitted) < ADMISSION_BUDGET + Duration::from_secs(2),
            "queued budgets must not stack"
        );
        let snapshot = state_of(&harness);
        assert!(snapshot.queue_saturated > 0);
        assert_eq!(
            snapshot.queued + snapshot.queue_saturated,
            total,
            "every artifact event is either queued or counted as shed"
        );

        gate.release();
        harness.finish();
    }

    #[test]
    fn image_load_burst_with_slow_enrichment_keeps_order_and_bounded_delay() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("burst.dll");
        std::fs::write(&image, b"artifact").unwrap();
        let seen = Seen::default();
        let open: ArtifactOpener = Arc::new(|path| {
            std::thread::sleep(Duration::from_millis(2));
            File::open(path)
        });
        let harness = Harness::start(
            router_with(seen.clone()),
            ArtifactRuntime::capture(Platform::Windows),
            open,
            ARTIFACT_QUEUE_CAPACITY,
        );

        let total = 2_000u64;
        let mut submitted = Vec::with_capacity(total as usize);
        for seq in 1..=total {
            submitted.push(Instant::now());
            let event = if seq % 2 == 0 {
                with_ingest_seq(image_event(&image), seq)
            } else {
                windows_file_event(seq)
            };
            harness.ingress.handle_event(&event);
        }
        let state = harness.finish();

        let seen = seen.0.lock().unwrap();
        let order: Vec<u64> = seen.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(order, (1..=total).collect::<Vec<_>>());
        let worst = seen
            .iter()
            .map(|(seq, routed)| routed.duration_since(submitted[*seq as usize - 1]))
            .max()
            .unwrap();
        assert!(
            worst < ADMISSION_BUDGET + Duration::from_secs(2),
            "an event waited {worst:?}"
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.queued + snapshot.queue_saturated, total / 2);
    }

    #[test]
    fn expired_job_is_skipped_without_opening_the_file() {
        let state = Arc::new(ResolverState::new());
        let runtime = ArtifactRuntime::capture(Platform::Windows);
        let event = image_event(Path::new("definitely-missing.exe"));
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let (pe_tx, pe_rx) = std::sync::mpsc::sync_channel(1);
        let (tx, mut rx) = mpsc::channel(1);
        tx.blocking_send(ArtifactJob {
            target,
            plan,
            enqueued_at: Instant::now() - ARTIFACT_DEADLINE,
            pe_ready: Some(pe_tx),
            deferred_ready: None,
            resolved_pe: None,
            resolved_hashes: None,
            process_start_key: None,
            provenance: Default::default(),
            platform: Platform::Windows,
            provider: "test".into(),
            written_file: None,
        })
        .unwrap();
        drop(tx);

        let opens = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&opens);
        ArtifactResolver::new(Arc::new(HostState::default()), runtime, Arc::clone(&state)).run(
            &mut rx,
            Arc::new(move |path| {
                counted.fetch_add(1, Ordering::Relaxed);
                File::open(path)
            }),
        );

        assert_eq!(opens.load(Ordering::Relaxed), 0);
        assert_eq!(state.snapshot().deadline_exceeded, 1);
        assert!(
            matches!(
                pe_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Disconnected)
            ),
            "a skipped job must release admission immediately"
        );
    }

    #[test]
    fn blocked_io_keeps_its_slot_and_shutdown_detaches_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("blocked.exe");
        std::fs::write(&path, b"artifact").unwrap();
        let state = Arc::new(ResolverState::new());
        let runtime = ArtifactRuntime::capture(Platform::Windows);
        let event = image_event(&path);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let mut plan = ResolvePlan::snapshot(&runtime, &event, &target);
        plan.deadline = Duration::from_millis(50);
        let (tx, mut rx) = mpsc::channel(ARTIFACT_IO_ISOLATION_LIMIT + 1);
        for _ in 0..=ARTIFACT_IO_ISOLATION_LIMIT {
            tx.blocking_send(ArtifactJob {
                target: target.clone(),
                plan: plan.clone(),
                enqueued_at: Instant::now(),
                pe_ready: None,
                deferred_ready: None,
                resolved_pe: None,
                resolved_hashes: None,
                process_start_key: None,
                provenance: Default::default(),
                platform: Platform::Windows,
                provider: "test".into(),
                written_file: None,
            })
            .unwrap();
        }
        drop(tx);

        let gate = Gate::new();
        let started = Instant::now();
        ArtifactResolver::new(Arc::new(HostState::default()), runtime, Arc::clone(&state))
            .run(&mut rx, gate.opener(None));

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited on blocked I/O"
        );
        assert_eq!(
            state.snapshot().deadline_exceeded,
            1,
            "only the job that never got an I/O slot is skipped at dequeue"
        );
        gate.release();
    }

    #[test]
    fn pe_field_rule_fires_exactly_once_after_admission() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("signed.exe");
        std::fs::write(&image, b"artifact").unwrap();
        let rules = temp.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(
            rules.join("company.yml"),
            r#"
title: Company from PE metadata
id: 3d9c8e57-5a0f-4c1e-9b8f-4270000000a1
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Company: Rustinel Test Company
  condition: selection
level: high
"#,
        )
        .unwrap();
        let mut engine = Engine::new_for_platform(Platform::Windows);
        engine.load_rules(&rules).unwrap();

        struct Detect(Engine, Arc<Mutex<Vec<String>>>);
        impl CanonicalEventHandler for Detect {
            fn handle_event(&self, event: &CanonicalEvent) {
                for alert in self.0.evaluate_event(event.normalized()) {
                    self.1.lock().unwrap().push(alert.rule_name);
                }
            }
        }
        let alerts = Arc::new(Mutex::new(Vec::new()));
        let runtime = ArtifactRuntime::capture(Platform::Windows);
        let event = process_event(&image, Platform::Windows);
        let harness = Harness::start(
            router_with(Detect(engine, Arc::clone(&alerts))),
            runtime.clone(),
            Arc::new(open_artifact),
            ARTIFACT_QUEUE_CAPACITY,
        );
        // Seed the PE store so the rule does not depend on a Windows parser.
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        harness.state.stores.lock().unwrap().insert(
            file_identity::from_path(&image).unwrap(),
            &plan,
            &Artifact {
                pe_metadata: Some(PeMetadata {
                    original_filename: None,
                    product: None,
                    description: None,
                    company: Some("Rustinel Test Company".into()),
                    file_version: None,
                }),
                ..Artifact::default()
            },
            StoredParts {
                pe: true,
                imphash: false,
            },
        );

        harness.ingress.handle_event(&event);
        let state = harness.finish();

        assert_eq!(
            *alerts.lock().unwrap(),
            vec!["Company from PE metadata".to_string()]
        );
        assert_eq!(state.snapshot().cache_hits, 1);
        assert_eq!(state.snapshot().admission_budget_exceeded, 0);
    }

    #[test]
    fn loaded_image_pe_metadata_stays_out_of_the_process_cache() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("library.dll");
        std::fs::write(&image, b"artifact").unwrap();
        let runtime = ArtifactRuntime::capture(Platform::Windows);
        let mut event = image_event(&image);
        let process_key = crate::sensor::ProcessStartKey {
            pid: 42,
            start_time: 100,
        };
        event.process_start_key = Some(process_key);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let state = Arc::new(ResolverState::new());
        let host_state = Arc::new(HostState::default());
        let resolver = ArtifactResolver::new(Arc::clone(&host_state), runtime, Arc::clone(&state));
        let executable_metadata = PeMetadata {
            original_filename: Some("application.exe".into()),
            product: Some("Application".into()),
            description: Some("Application executable".into()),
            company: Some("Executable Company".into()),
            file_version: Some("1.0.0".into()),
        };
        let reused_process_metadata = PeMetadata {
            original_filename: Some("new-application.exe".into()),
            product: Some("New Application".into()),
            description: Some("Reused PID executable".into()),
            company: Some("New Executable Company".into()),
            file_version: Some("2.0.0".into()),
        };
        host_state.processes.add(
            process_key.pid,
            process_key.start_time,
            r"C:\Program Files\Application\application.exe".into(),
            None,
            None,
            None,
            None,
            None,
            executable_metadata.original_filename.clone(),
            executable_metadata.product.clone(),
            executable_metadata.description.clone(),
            executable_metadata.company.clone(),
            executable_metadata.file_version.clone(),
            None,
            None,
        );
        host_state.processes.add(
            process_key.pid,
            200,
            r"C:\Program Files\Application\new-application.exe".into(),
            None,
            None,
            None,
            None,
            None,
            reused_process_metadata.original_filename.clone(),
            reused_process_metadata.product.clone(),
            reused_process_metadata.description.clone(),
            reused_process_metadata.company.clone(),
            reused_process_metadata.file_version.clone(),
            None,
            None,
        );

        let dll_metadata = PeMetadata {
            original_filename: Some("library.dll".into()),
            product: Some("Shared Library".into()),
            description: Some("Loaded DLL".into()),
            company: Some("Library Company".into()),
            file_version: Some("9.9.9".into()),
        };
        state.stores.lock().unwrap().insert(
            file_identity::from_path(&image).unwrap(),
            &plan,
            &Artifact {
                pe_metadata: Some(dll_metadata.clone()),
                ..Artifact::default()
            },
            StoredParts {
                pe: true,
                imphash: false,
            },
        );

        for _ in 0..2 {
            let (pe_ready, pe) = std::sync::mpsc::sync_channel(1);
            resolver.resolve_job(
                ArtifactJob {
                    target: target.clone(),
                    plan: plan.clone(),
                    enqueued_at: Instant::now(),
                    pe_ready: Some(pe_ready),
                    deferred_ready: None,
                    resolved_pe: None,
                    resolved_hashes: None,
                    process_start_key: Some(process_key),
                    provenance: Default::default(),
                    platform: Platform::Windows,
                    provider: "test".into(),
                    written_file: None,
                },
                Instant::now() + ARTIFACT_DEADLINE,
                open_artifact,
            );
            assert_eq!(pe.recv().unwrap(), Some(dll_metadata.clone()));
            assert_eq!(
                host_state
                    .processes
                    .get_metadata_by_key(process_key.pid, process_key.start_time)
                    .unwrap()
                    .original_filename,
                executable_metadata.original_filename
            );
        }

        assert_eq!(state.snapshot().pe_entries, 1);
        assert_eq!(state.snapshot().cache_hits, 2);
        assert_eq!(
            host_state
                .processes
                .get_metadata_by_key(process_key.pid, 200)
                .unwrap()
                .original_filename,
            reused_process_metadata.original_filename
        );

        let mut subsequent = windows_file_event(2).into_normalized();
        host_state.enrich_process_context(&mut subsequent, Some(process_key));
        let context = subsequent.process_context.unwrap();
        assert_eq!(
            context.original_file_name,
            executable_metadata.original_filename
        );
        assert_eq!(context.product, executable_metadata.product);
        assert_eq!(context.description, executable_metadata.description);
        assert_eq!(context.company, executable_metadata.company);
        assert_eq!(context.file_version, executable_metadata.file_version);
    }

    /// Scan alerts are built on another thread from the job, not the event,
    /// so the job must carry the fidelity of the image and PID it reports.
    #[test]
    fn queued_jobs_carry_the_scan_subject_provenance() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("derived.exe");
        std::fs::write(&image, b"artifact").unwrap();
        let ResolverParts {
            ingress,
            admission,
            mut resolve_rx,
            ..
        } = ResolverParts::new(
            Arc::new(SensorEventRouter::new()),
            Arc::new(HostState::default()),
            ArtifactRuntime::capture(Platform::Windows),
            Arc::new(ResolverState::new()),
            ARTIFACT_QUEUE_CAPACITY,
        );
        let admitted = std::thread::spawn(move || admission.run());

        let mut normalized = process_event(&image, Platform::Windows).into_normalized();
        normalized.provenance.mark_derived("Image");
        normalized
            .provenance
            .mark("ProcessId", crate::models::Fidelity::BestEffort);
        normalized.provenance.mark_derived("OriginalFileName");
        ingress.handle_event(&CanonicalEvent::from_normalized(normalized));

        let job = resolve_rx.try_recv().expect("artifact job queued");
        let mut expected = crate::models::Provenance::default();
        expected.mark_derived("Image");
        expected.mark("ProcessId", crate::models::Fidelity::BestEffort);
        assert_eq!(job.provenance, expected);
        drop(job);
        drop(ingress);
        admitted.join().unwrap();
    }

    const FILE_CREATE_OPCODE: u8 = 64;
    const FILE_DELETE_OPCODE: u8 = 70;
    const WRITER_IMAGE: &str = "/usr/bin/curl";

    fn file_event(path: &Path, opcode: u8, identity: Option<FileObjectIdentity>) -> CanonicalEvent {
        let mut normalized = windows_file_event(1).into_normalized();
        normalized.platform = Platform::Linux;
        normalized.provider = "ebpf".into();
        normalized.opcode = opcode;
        normalized.fields = EventFields::FileEvent(crate::models::FileEventFields {
            source_filename: None,
            target_filename: Some(path.to_string_lossy().into_owned()),
            process_id: Some("43".into()),
            image: Some(WRITER_IMAGE.into()),
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: None,
            file_identity: identity,
            path_truncated: None,
        });
        CanonicalEvent::from_normalized(normalized)
    }

    fn select_all() -> WrittenFileSelector {
        Arc::new(|_, _| true)
    }

    #[test]
    fn written_file_selector_rejects_truncated_paths() {
        let selector = written_file_scan_selector();
        let complete = file_event(Path::new("/tmp/payload.exe"), FILE_CREATE_OPCODE, None);
        let EventFields::FileEvent(complete_fields) = &complete.normalized().fields else {
            unreachable!();
        };
        assert!(selector(&complete, complete_fields));

        let mut truncated = complete.clone().into_normalized();
        let EventFields::FileEvent(fields) = &mut truncated.fields else {
            unreachable!();
        };
        fields.path_truncated = Some("target".into());
        let truncated = CanonicalEvent::from_normalized(truncated);
        let EventFields::FileEvent(truncated_fields) = &truncated.normalized().fields else {
            unreachable!();
        };
        assert!(!selector(&truncated, truncated_fields));
    }

    #[test]
    fn written_file_gate_accepts_extension_or_magic_but_not_partial_content() {
        let temp = tempfile::tempdir().unwrap();

        let extension = temp.path().join("payload.EXE");
        std::fs::write(&extension, b"plain bytes").unwrap();
        let mut extension_file = File::open(&extension).unwrap();
        let extension_size = extension_file.metadata().unwrap().len();
        assert!(written_file_qualifies(&extension, &mut extension_file, extension_size).unwrap());

        let magic = temp.path().join("payload.unknown");
        std::fs::write(&magic, b"\x7fELFmore bytes").unwrap();
        let mut magic_file = File::open(&magic).unwrap();
        let magic_size = magic_file.metadata().unwrap().len();
        assert!(written_file_qualifies(&magic, &mut magic_file, magic_size).unwrap());

        for (name, bytes) in [("empty", &b""[..]), ("partial", &b"M"[..])] {
            let path = temp.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            let mut file = File::open(&path).unwrap();
            let size = file.metadata().unwrap().len();
            assert!(!written_file_qualifies(&path, &mut file, size).unwrap());
        }
    }

    #[cfg(unix)]
    fn object_identity(path: &Path) -> FileObjectIdentity {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).unwrap();
        FileObjectIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[test]
    fn file_events_become_targets_only_through_the_selector() {
        let path = Path::new("/tmp/dropped.bin");
        let created = file_event(path, FILE_CREATE_OPCODE, None);
        assert!(ArtifactTarget::from_event(&created, None).is_none());
        let reject: WrittenFileSelector = Arc::new(|_, _| false);
        assert!(ArtifactTarget::from_event(&created, Some(&reject)).is_none());

        let target = ArtifactTarget::from_event(&created, Some(&select_all())).unwrap();
        assert_eq!(target.kind, ArtifactKind::WrittenFile);
        assert_eq!(target.display_path, "/tmp/dropped.bin");
        assert_eq!(target.pid, 43);

        let deleted = file_event(path, FILE_DELETE_OPCODE, None);
        assert!(ArtifactTarget::from_event(&deleted, Some(&select_all())).is_none());
    }

    #[test]
    fn selected_written_file_without_event_identity_is_skipped_and_counted() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("dropped.bin");
        std::fs::write(&path, b"evil!!").unwrap();
        let mut runtime = runtime_with_consumers(temp.path(), b"evil!!");
        runtime.written_files = Some(select_all());
        let seen = Seen::default();
        let opens = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&opens);
        let harness = Harness::start(
            router_with(seen.clone()),
            runtime,
            Arc::new(move |path| {
                counted.fetch_add(1, Ordering::Relaxed);
                File::open(path)
            }),
            ARTIFACT_QUEUE_CAPACITY,
        );

        harness
            .ingress
            .handle_event(&file_event(&path, FILE_CREATE_OPCODE, None));
        let state = harness.finish();

        assert_eq!(seen.ingest_seqs(), vec![1], "the event is still admitted");
        assert_eq!(opens.load(Ordering::Relaxed), 0);
        let snapshot = state.snapshot();
        assert_eq!(snapshot.identity_unavailable, 1);
        assert_eq!(snapshot.queued, 0);
    }

    #[cfg(unix)]
    #[test]
    fn repeated_written_file_events_debounce_to_one_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("dropped.exe");
        std::fs::write(&path, bytes).unwrap();
        let mut runtime = runtime_with_consumers(temp.path(), bytes);
        runtime.written_files = Some(select_all());
        let opens = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&opens);
        let harness = Harness::start(
            Arc::new(SensorEventRouter::new()),
            runtime,
            Arc::new(move |path| {
                counted.fetch_add(1, Ordering::Relaxed);
                open_artifact(path)
            }),
            ARTIFACT_QUEUE_CAPACITY,
        );
        let identity = Some(object_identity(&path));

        harness
            .ingress
            .handle_event(&file_event(&path, FILE_CREATE_OPCODE, identity));
        harness
            .ingress
            .handle_event(&file_event(&path, FILE_CREATE_OPCODE, identity));
        let state = harness.finish();

        assert_eq!(opens.load(Ordering::Relaxed), 1);
        let snapshot = state.snapshot();
        assert_eq!(snapshot.queued, 2);
        assert_eq!(snapshot.resolved, 1);
    }

    #[cfg(unix)]
    #[test]
    fn written_file_scans_its_validated_handle_and_rejects_a_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("dropped.exe");
        std::fs::write(&path, bytes).unwrap();
        let mut runtime = runtime_with_consumers(temp.path(), bytes);
        runtime.written_files = Some(select_all());
        let event = file_event(&path, FILE_CREATE_OPCODE, Some(object_identity(&path)));
        let target = ArtifactTarget::from_event(&event, runtime.written_files.as_ref()).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        assert!(plan.needs.yara && plan.needs.hashes.sha256 && !plan.needs.pe_metadata);
        let state = Arc::new(ResolverState::new());
        let worker = ArtifactResolver::new(
            Arc::new(HostState::default()),
            runtime.clone(),
            Arc::clone(&state),
        );

        let artifact = worker
            .resolve_with_opener(&target, &plan, open_artifact)
            .unwrap();
        assert_eq!(artifact.yara.unwrap().len(), 1);
        assert!(artifact.hashes.unwrap().sha256.is_some());

        let replacement = temp.path().join("replacement.bin");
        std::fs::write(&replacement, bytes).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let error = worker
            .resolve_with_opener(&target, &plan, open_artifact)
            .expect_err("a replacement must not be scanned as the written file");
        assert!(matches!(error, ResolveError::Identity));
        assert_eq!(state.snapshot().identity_mismatch, 1);
    }

    #[test]
    fn process_image_replaced_after_exec_is_an_identity_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let runtime = runtime_with_consumers(temp.path(), bytes);
        let mut normalized = process_event(&path, Platform::Linux).into_normalized();
        let EventFields::ProcessCreation(fields) = &mut normalized.fields else {
            unreachable!();
        };
        fields.exec = Some(Box::new(crate::models::ExecMetadata {
            file_identity: file_identity::from_path(&path),
            ..Default::default()
        }));
        let event = CanonicalEvent::from_normalized(normalized);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let state = Arc::new(ResolverState::new());
        let worker = ArtifactResolver::new(
            Arc::new(HostState::default()),
            runtime.clone(),
            Arc::clone(&state),
        );
        assert_eq!(
            worker
                .resolve_with_opener(&target, &plan, open_artifact)
                .unwrap()
                .yara
                .unwrap()
                .len(),
            1
        );

        let replacement = temp.path().join("replacement.bin");
        std::fs::write(&replacement, b"clean!").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(matches!(
            worker.resolve_with_opener(&target, &plan, open_artifact),
            Err(ResolveError::Identity)
        ));
        assert_eq!(state.snapshot().identity_mismatch, 1);
    }

    /// A written file is reported as the file its event named, with the
    /// writing process, never as a process image of that path.
    #[cfg(unix)]
    #[test]
    fn written_file_alerts_describe_the_file_and_its_writer() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("dropped.exe");
        std::fs::write(&path, bytes).unwrap();
        let alerts_path = temp.path().join("alerts.ndjson");
        let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
        let mut runtime = runtime_with_consumers(temp.path(), bytes);
        runtime.written_files = Some(select_all());
        runtime.alert_sink = Some(AlertSink::new(writer));
        let harness = Harness::start(
            Arc::new(SensorEventRouter::new()),
            runtime,
            Arc::new(open_artifact),
            ARTIFACT_QUEUE_CAPACITY,
        );

        harness.ingress.handle_event(&file_event(
            &path,
            FILE_CREATE_OPCODE,
            Some(object_identity(&path)),
        ));
        let state = harness.finish();
        drop(guard);

        assert_eq!(state.snapshot().resolved, 1);
        let alerts: Vec<serde_json::Value> = std::fs::read_to_string(&alerts_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let engines: Vec<&str> = alerts
            .iter()
            .map(|alert| alert["edr.rule.engine"].as_str().unwrap())
            .collect();
        assert_eq!(
            engines.len(),
            2,
            "one IOC hash and one YARA alert: {alerts:?}"
        );
        assert!(engines.contains(&"Ioc") && engines.contains(&"Yara"));
        for alert in &alerts {
            assert_eq!(alert["file.path"], path.to_string_lossy().as_ref());
            assert_eq!(alert["process.executable"], WRITER_IMAGE);
            assert_eq!(alert["process.pid"], 43);
        }
    }

    fn windows_rule(title: &str, category: &str, detection: &str) -> String {
        format!(
            "title: {title}\nlevel: high\nlogsource:\n  product: windows\n  category: {category}\ndetection:\n{detection}"
        )
    }

    /// A detecting runtime over the given Sigma rules, with alerts written to
    /// `alerts.ndjson` under `root`. No IOC or YARA consumer is loaded, so any
    /// hashing comes from the deferred pass alone.
    fn detecting_runtime(
        root: &Path,
        rules: &[String],
    ) -> (
        ArtifactRuntime,
        Arc<DetectorStore>,
        PathBuf,
        tracing_appender::non_blocking::WorkerGuard,
    ) {
        let rules_dir = root.join("sigma");
        std::fs::create_dir(&rules_dir).unwrap();
        for (index, rule) in rules.iter().enumerate() {
            std::fs::write(rules_dir.join(format!("rule{index}.yml")), rule).unwrap();
        }
        let mut engine = Engine::new_for_platform(Platform::Windows);
        engine.load_rules(&rules_dir).unwrap();
        assert!(engine.stats().failed_rules.is_empty());
        let detectors = DetectorStore::new(
            Arc::new(engine),
            Arc::new(Scanner::empty()),
            Arc::new(crate::ioc::IocEngine::disabled()),
        );
        let alerts_path = root.join("alerts.ndjson");
        let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
        let runtime = ArtifactRuntime {
            detectors: Some(Arc::clone(&detectors)),
            alert_sink: Some(AlertSink::new(writer)),
            response_engine: None,
            match_debug: MatchDebugLevel::Off,
            yara_allowlist_paths: Vec::new(),
            pe_metadata: false,
            written_files: None,
        };
        (runtime, detectors, alerts_path, guard)
    }

    /// Admission-side detection exactly as the live pipeline runs it.
    struct AdmissionDetection {
        detectors: Arc<DetectorStore>,
        sink: AlertSink,
    }

    impl CanonicalEventHandler for AdmissionDetection {
        fn handle_event(&self, event: &CanonicalEvent) {
            let pass = if event.deferred_pass_pending() {
                DetectionPass::Admission
            } else {
                DetectionPass::All
            };
            for alert in EventDetectors::snapshot(&self.detectors).evaluate_pass(event, pass) {
                self.sink.write_alert(&alert);
            }
        }
    }

    fn read_alerts(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn rule_names(alerts: &[serde_json::Value]) -> Vec<String> {
        let mut names: Vec<String> = alerts
            .iter()
            .map(|alert| alert["rule.name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_hash_rule_fires_once_in_the_deferred_pass_and_never_at_admission() {
        use sha2::Digest;

        let temp = tempfile::tempdir().unwrap();
        let bytes = b"deferred sample image";
        let image = temp.path().join("sample.exe");
        std::fs::write(&image, bytes).unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(bytes));
        let (runtime, detectors, alerts_path, guard) = detecting_runtime(
            temp.path(),
            &[
                windows_rule(
                    "By image",
                    "process_creation",
                    "  selection:\n    Image|endswith: sample.exe\n  condition: selection\n",
                ),
                windows_rule(
                    "By hash",
                    "process_creation",
                    &format!(
                        "  selection:\n    Hashes|contains: SHA256={}\n  condition: selection\n",
                        sha256.to_ascii_uppercase()
                    ),
                ),
            ],
        );
        let sink = runtime.alert_sink.clone().unwrap();
        let harness = Harness::start(
            router_with(AdmissionDetection { detectors, sink }),
            runtime,
            Arc::new(open_artifact),
            ARTIFACT_QUEUE_CAPACITY,
        );

        harness
            .ingress
            .handle_event(&process_event(&image, Platform::Windows));
        let state = harness.finish();
        drop(guard);

        let alerts = read_alerts(&alerts_path);
        assert_eq!(rule_names(&alerts), vec!["By hash", "By image"]);
        let by_hash = alerts
            .iter()
            .find(|alert| alert["rule.name"] == "By hash")
            .unwrap();
        assert_eq!(by_hash["process.hash.sha256"], sha256.as_str());
        assert!(
            by_hash.get("process.hash.md5").is_none(),
            "only SHA256 was requested"
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.deferred_queued, 1);
        assert_eq!(snapshot.deferred_enriched, 1);
        assert_eq!(snapshot.deferred_unenriched, 0);
        assert_eq!(
            snapshot.correlation_lateness_ms,
            DEFERRED_DETECTION_BUDGET.as_millis() as u64
        );
        assert_eq!(snapshot.hash_entries, 1);
    }

    #[test]
    fn deferred_rules_evaluate_once_without_hashes_when_the_image_cannot_be_read() {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, detectors, alerts_path, guard) = detecting_runtime(
            temp.path(),
            &[windows_rule(
                "Hash or image",
                "process_creation",
                "  hash:\n    Hashes|contains: IMPHASH=00\n  image:\n    Image|endswith: gone.exe\n  condition: hash or image\n",
            )],
        );
        let sink = runtime.alert_sink.clone().unwrap();
        let harness = Harness::start(
            router_with(AdmissionDetection { detectors, sink }),
            runtime,
            Arc::new(open_artifact),
            ARTIFACT_QUEUE_CAPACITY,
        );

        harness.ingress.handle_event(&process_event(
            &temp.path().join("gone.exe"),
            Platform::Windows,
        ));
        let state = harness.finish();
        drop(guard);

        assert_eq!(
            rule_names(&read_alerts(&alerts_path)),
            vec!["Hash or image"]
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.open_failed, 1);
        assert_eq!(snapshot.deferred_unenriched, 1);
        assert_eq!(
            snapshot.deferred_budget_exceeded, 0,
            "a failed read releases the pass at once"
        );
    }

    #[test]
    fn a_blocked_resolution_releases_the_deferred_pass_at_its_budget() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("blocked.exe");
        std::fs::write(&image, b"artifact").unwrap();
        let (runtime, detectors, alerts_path, guard) = detecting_runtime(
            temp.path(),
            &[windows_rule(
                "Hash or image",
                "process_creation",
                "  hash:\n    Hashes|contains: MD5=00\n  image:\n    Image|endswith: blocked.exe\n  condition: hash or image\n",
            )],
        );
        let sink = runtime.alert_sink.clone().unwrap();
        let gate = Gate::new();
        let harness = Harness::start(
            router_with(AdmissionDetection { detectors, sink }),
            runtime,
            gate.opener(None),
            ARTIFACT_QUEUE_CAPACITY,
        );

        let submitted = Instant::now();
        harness
            .ingress
            .handle_event(&process_event(&image, Platform::Windows));
        let give_up = submitted + DEFERRED_DETECTION_BUDGET + Duration::from_secs(5);
        while state_of(&harness).deferred_budget_exceeded == 0 {
            assert!(
                Instant::now() < give_up,
                "the deferred pass was never released"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let waited = submitted.elapsed();
        assert!(
            waited >= DEFERRED_DETECTION_BUDGET,
            "released early: {waited:?}"
        );
        gate.release();
        harness.finish();
        drop(guard);

        assert_eq!(
            rule_names(&read_alerts(&alerts_path)),
            vec!["Hash or image"]
        );
    }

    #[test]
    fn nothing_is_hashed_unless_a_loaded_consumer_needs_it() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("tool.exe");
        let (runtime, _, _, _guard) = detecting_runtime(
            temp.path(),
            &[
                windows_rule(
                    "By image",
                    "process_creation",
                    "  selection:\n    Image|endswith: tool.exe\n  condition: selection\n",
                ),
                windows_rule(
                    "Loaded imphash",
                    "image_load",
                    "  selection:\n    Imphash: 0123\n  condition: selection\n",
                ),
            ],
        );

        let process = process_event(&image, Platform::Windows);
        let process_plan = ResolvePlan::snapshot(
            &runtime,
            &process,
            &ArtifactTarget::from_event(&process, None).unwrap(),
        );
        assert!(!process_plan.needs.needs_digest_read());
        assert!(process_plan.deferred.is_empty());

        let loaded = image_event(&image);
        let loaded_plan = ResolvePlan::snapshot(
            &runtime,
            &loaded,
            &ArtifactTarget::from_event(&loaded, None).unwrap(),
        );
        assert!(loaded_plan.needs.imphash);
        assert_eq!(loaded_plan.needs.hashes, HashRequirements::default());

        let linux = process_event(&image, Platform::Linux);
        let linux_plan = ResolvePlan::snapshot(
            &runtime,
            &linux,
            &ArtifactTarget::from_event(&linux, None).unwrap(),
        );
        assert!(
            linux_plan.deferred.is_empty(),
            "only Windows PE images carry these fields"
        );
    }

    #[test]
    fn sysmon_hashes_lists_requested_values_in_sysmon_order() {
        let hashes = ComputedHashes {
            md5: Some("aa".into()),
            sha1: Some("bb".into()),
            sha256: Some("cc".into()),
        };
        assert_eq!(
            sysmon_hashes(ArtifactFieldNeeds::ALL, Some(&hashes), Some("dd")).as_deref(),
            Some("SHA1=BB,MD5=AA,SHA256=CC,IMPHASH=DD")
        );
        let md5_and_imphash = ArtifactFieldNeeds {
            md5: true,
            imphash: true,
            ..ArtifactFieldNeeds::default()
        };
        assert_eq!(
            sysmon_hashes(md5_and_imphash, Some(&hashes), None).as_deref(),
            Some("MD5=AA"),
            "an image without imports leaves IMPHASH out rather than inventing one"
        );
        assert_eq!(sysmon_hashes(md5_and_imphash, None, None), None);
    }

    #[test]
    fn an_absent_imphash_is_cached_so_the_file_is_not_read_again() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("plain.dll");
        std::fs::write(&path, b"no imports here").unwrap();
        let identity = file_identity::from_path(&path).unwrap();
        let (runtime, _, _, _guard) = detecting_runtime(
            temp.path(),
            &[windows_rule(
                "Loaded imphash",
                "image_load",
                "  selection:\n    Imphash: 0123\n  condition: selection\n",
            )],
        );
        let event = image_event(&path);
        let plan = ResolvePlan::snapshot(
            &runtime,
            &event,
            &ArtifactTarget::from_event(&event, None).unwrap(),
        );
        let mut stores = ArtifactStores::new(10);
        stores.insert(
            identity.clone(),
            &plan,
            &Artifact::default(),
            StoredParts {
                pe: false,
                imphash: true,
            },
        );

        let mut artifact = Artifact::default();
        let mut missing = plan.needs;
        stores.load(&identity, &plan, &mut artifact, &mut missing);
        assert!(!missing.imphash);
        assert_eq!(artifact.imphash, None);
    }

    #[test]
    fn stale_yara_generation_cannot_move_the_store_backward() {
        let mut stores = ArtifactStores::new(10);
        stores.invalidate_yara(Some(2));
        stores.invalidate_yara(Some(0));
        assert_eq!(stores.yara_generation, Some(2));
    }
}
