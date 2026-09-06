//! Pipeline telemetry accounting.
//!
//! Every bounded channel between a sensor and the detectors sheds load by
//! dropping events rather than blocking the producer — an ETW callback or an
//! eBPF poll loop that blocks stalls the kernel-side buffer behind it. Load
//! shedding is the right trade, but it is only safe to rely on if the size of
//! the gap is measurable: a warning in a rotated log file cannot tell an
//! operator whether a detection failed to fire or never had the event.
//!
//! This module gives each channel a set of atomic counters — accepted,
//! dropped, and the peak queue depth reached — that the runtime periodically
//! writes to a snapshot file. `rustinel doctor` reads that snapshot, so the
//! answer to "did we lose telemetry?" is a command, not a log search.

mod snapshot;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::utils::LogRateLimiter;

pub use snapshot::{
    snapshot_path, spawn_reporter, write_final_snapshot, ChannelSnapshot, EtwDecodeFailureSnapshot,
    EtwDecodeSnapshot, FileAttributionSnapshot, ProcessCommandLineSnapshot, RegistrySnapshot,
    SensorEventCategorySnapshot, TelemetrySnapshot, SNAPSHOT_FILE_NAME,
};

use crate::models::EventCategory;
use crate::sensor::SensorEvent;

/// Tracing target for pipeline telemetry accounting.
pub const TARGET_TELEMETRY: &str = "telemetry";

/// Minimum spacing between cumulative drop warnings for one channel.
///
/// The first drop on a channel always warns; after that the warning carries
/// the running total, so a burst produces one line rather than one per event.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Keyed by channel, so a burst on one channel cannot swallow the first drop
/// reported on another.
static DROP_WARNINGS: LazyLock<Mutex<LogRateLimiter>> =
    LazyLock::new(|| Mutex::new(LogRateLimiter::new(DROP_WARN_INTERVAL)));

/// Process start, used for the snapshot's uptime.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// A bounded channel in the event pipeline that can shed load.
///
/// Counters are keyed by channel rather than by sensor: on macOS the ESF and
/// BPF sensors feed one channel, and what an operator needs to know is how
/// much that channel lost, not which producer lost it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelId {
    /// Sensor decode threads to the detection router.
    SensorEvents,
    /// Process/file events queued for on-disk YARA scanning.
    YaraFileScan,
    /// Processes queued for YARA memory scanning.
    YaraMemoryScan,
    /// Process images queued for IOC hash lookup.
    IocHash,
    /// Alerts queued for active response.
    ActiveResponse,
    /// Normalized events queued for the capture recording writer.
    CaptureWriter,
}

impl ChannelId {
    /// Every channel, in the order snapshots report them.
    pub const ALL: [ChannelId; 6] = [
        ChannelId::SensorEvents,
        ChannelId::YaraFileScan,
        ChannelId::YaraMemoryScan,
        ChannelId::IocHash,
        ChannelId::ActiveResponse,
        ChannelId::CaptureWriter,
    ];

    /// Stable identifier used in snapshots, log fields, and doctor output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelId::SensorEvents => "sensor_events",
            ChannelId::YaraFileScan => "yara_file_scan",
            ChannelId::YaraMemoryScan => "yara_memory_scan",
            ChannelId::IocHash => "ioc_hash",
            ChannelId::ActiveResponse => "active_response",
            ChannelId::CaptureWriter => "capture_writer",
        }
    }

    const fn index(self) -> usize {
        match self {
            ChannelId::SensorEvents => 0,
            ChannelId::YaraFileScan => 1,
            ChannelId::YaraMemoryScan => 2,
            ChannelId::IocHash => 3,
            ChannelId::ActiveResponse => 4,
            ChannelId::CaptureWriter => 5,
        }
    }

    /// The process-wide counters for this channel.
    pub fn counters(self) -> &'static ChannelCounters {
        &CHANNELS[self.index()]
    }
}

/// Process-wide counters, one set per [`ChannelId`].
///
/// A static array rather than a registry map: the set of channels is fixed at
/// compile time, so lookups need no lock and no allocation on the send path.
static CHANNELS: [ChannelCounters; 6] = [
    ChannelCounters::new(ChannelId::SensorEvents),
    ChannelCounters::new(ChannelId::YaraFileScan),
    ChannelCounters::new(ChannelId::YaraMemoryScan),
    ChannelCounters::new(ChannelId::IocHash),
    ChannelCounters::new(ChannelId::ActiveResponse),
    ChannelCounters::new(ChannelId::CaptureWriter),
];

/// Which tier of the sensor's key-path index answered a lookup.
///
/// Mirrors the sensor's own enum so the platform-neutral telemetry module does
/// not depend on a Windows-only type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryPathSource {
    /// A naming event seen inside this session.
    Session,
    /// The startup handle-table snapshot of keys that were already open.
    StartupSnapshot,
    /// A key already closed by the time its write was decoded.
    RecentlyClosed,
}

/// Windows registry key-path resolution accounting.
///
/// The registry sensor is the one place where an event can be lost *after* it
/// reached the agent: `SetValueKey` carries no key path, so a write whose
/// `KeyObject` resolves to nothing is dropped rather than emitted (#341). That
/// gap was previously visible only as a `debug!` line the log rate limiter
/// suppressed after the first occurrence, which meant nobody could tell a
/// quiet endpoint from a blind one.
///
/// These counters make the gap a number. `resolution_rate_pct` is the figure
/// that decides whether the classic kernel provider and its KCB rundown are
/// worth the second trace session.
///
/// There is deliberately no `naming_query` counter: `QueryKey` declares a
/// `KeyName` and delivers it empty on 100% of events (measured on Windows 11
/// 26200), so it is not subscribed and could never contribute a name.
#[derive(Debug, Default)]
pub struct RegistryCounters {
    /// Write events routed to registry telemetry: set, delete value, delete key.
    events_received: AtomicU64,
    /// Of those, the ones that got a key path.
    events_resolved: AtomicU64,
    /// Of those, the ones dropped for want of one.
    events_unresolved: AtomicU64,
    /// Resolved only because the startup handle-table snapshot knew the key.
    resolved_from_snapshot: AtomicU64,
    /// Resolved only because the key's `CloseKey` was decoded before its write.
    resolved_after_close: AtomicU64,
    /// `CreateKey` events that named a key.
    naming_create: AtomicU64,
    /// `OpenKey` events that named a key.
    naming_open: AtomicU64,
    /// Naming events skipped because the open failed and carried no key object.
    naming_failed: AtomicU64,
    /// Keys the startup snapshot covered.
    snapshot_keys: AtomicUsize,
    /// Whether the Windows sensor attempted its startup key rundown.
    rundown_attempted: AtomicBool,
}

/// Process-wide registry accounting.
pub static REGISTRY: RegistryCounters = RegistryCounters::new();

impl RegistryCounters {
    const fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            events_resolved: AtomicU64::new(0),
            events_unresolved: AtomicU64::new(0),
            resolved_from_snapshot: AtomicU64::new(0),
            resolved_after_close: AtomicU64::new(0),
            naming_create: AtomicU64::new(0),
            naming_open: AtomicU64::new(0),
            naming_failed: AtomicU64::new(0),
            snapshot_keys: AtomicUsize::new(0),
            rundown_attempted: AtomicBool::new(false),
        }
    }

    /// A write event resolved to a key path, and which tier of the index
    /// answered. The two non-default tiers are each a class of event that
    /// used to be dropped, so they are what the fix is measured by.
    pub fn record_resolved(&self, source: RegistryPathSource) {
        self.events_received.fetch_add(1, Ordering::Relaxed);
        self.events_resolved.fetch_add(1, Ordering::Relaxed);
        match source {
            RegistryPathSource::Session => {}
            RegistryPathSource::StartupSnapshot => {
                self.resolved_from_snapshot.fetch_add(1, Ordering::Relaxed);
            }
            RegistryPathSource::RecentlyClosed => {
                self.resolved_after_close.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A write event was dropped because its key had no known path. Returns
    /// the running total, which the caller uses to space its log line.
    pub fn record_unresolved(&self) -> u64 {
        self.events_received.fetch_add(1, Ordering::Relaxed);
        self.events_unresolved.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// A naming event indexed a key path.
    pub fn record_naming(&self, creates: bool) {
        if creates {
            self.naming_create.fetch_add(1, Ordering::Relaxed);
        } else {
            self.naming_open.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A naming event that named nothing: the open failed, so it carries no
    /// key object to index against.
    pub fn record_naming_failed(&self) {
        self.naming_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish the size of the startup handle-table snapshot.
    pub fn set_snapshot_keys(&self, keys: usize) {
        self.snapshot_keys.store(keys, Ordering::Relaxed);
        self.rundown_attempted.store(true, Ordering::Release);
    }

    /// Point-in-time view, or `None` when the registry sensor never ran.
    pub fn snapshot(&self) -> Option<RegistrySnapshot> {
        let received = self.events_received.load(Ordering::Relaxed);
        let rundown_attempted = self.rundown_attempted.load(Ordering::Acquire);
        if received == 0 && !rundown_attempted {
            return None;
        }
        let snapshot_keys = self.snapshot_keys.load(Ordering::Relaxed);
        Some(RegistrySnapshot {
            events_received: received,
            events_resolved: self.events_resolved.load(Ordering::Relaxed),
            events_unresolved: self.events_unresolved.load(Ordering::Relaxed),
            resolved_from_snapshot: self.resolved_from_snapshot.load(Ordering::Relaxed),
            resolved_after_close: self.resolved_after_close.load(Ordering::Relaxed),
            naming_create: self.naming_create.load(Ordering::Relaxed),
            naming_open: self.naming_open.load(Ordering::Relaxed),
            naming_failed: self.naming_failed.load(Ordering::Relaxed),
            snapshot_keys,
            rundown_attempted,
        })
    }

    /// Reset every counter. Test-only, for the same reason as
    /// [`ChannelCounters::reset`].
    #[cfg(test)]
    pub fn reset(&self) {
        self.events_received.store(0, Ordering::Relaxed);
        self.events_resolved.store(0, Ordering::Relaxed);
        self.events_unresolved.store(0, Ordering::Relaxed);
        self.resolved_from_snapshot.store(0, Ordering::Relaxed);
        self.resolved_after_close.store(0, Ordering::Relaxed);
        self.naming_create.store(0, Ordering::Relaxed);
        self.naming_open.store(0, Ordering::Relaxed);
        self.naming_failed.store(0, Ordering::Relaxed);
        self.snapshot_keys.store(0, Ordering::Relaxed);
        self.rundown_attempted.store(false, Ordering::Relaxed);
    }
}

/// Windows process command-line collection after every available fallback.
#[derive(Debug, Default)]
pub struct ProcessCommandLineCounters {
    attempted: AtomicU64,
    captured: AtomicU64,
    missed: AtomicU64,
}

/// Process-wide command-line accounting. It remains idle outside Windows.
pub static WINDOWS_PROCESS_COMMAND_LINE: ProcessCommandLineCounters =
    ProcessCommandLineCounters::new();

impl ProcessCommandLineCounters {
    const fn new() -> Self {
        Self {
            attempted: AtomicU64::new(0),
            captured: AtomicU64::new(0),
            missed: AtomicU64::new(0),
        }
    }

    pub fn record(&self, captured: bool) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
        if captured {
            self.captured.fetch_add(1, Ordering::Relaxed);
        } else {
            self.missed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> Option<ProcessCommandLineSnapshot> {
        let attempted = self.attempted.load(Ordering::Relaxed);
        if attempted == 0 {
            return None;
        }
        Some(ProcessCommandLineSnapshot {
            attempted,
            captured: self.captured.load(Ordering::Relaxed),
            missed: self.missed.load(Ordering::Relaxed),
        })
    }
}

/// Windows Kernel-File path attribution accounting.
///
/// The Kernel-File events that carry write semantics name their target only by
/// kernel pointer, so the sensor joins them to an earlier naming event through
/// a bounded index. A write whose pointer the index cannot answer is discarded
/// inside the ETW callback, before any channel sees it - exactly the shape of
/// the registry gap #341 measured, and previously visible only as a private
/// `AtomicU64` and a rate-limited `debug!` line.
///
/// Splitting the two resolved tiers matters: an event that carried its own
/// name never depended on the index, so a fall in `resolved_from_index`
/// against a steady `resolved_from_event` points at the index rather than at
/// the provider. `index_capacity_evictions` is the index's own failure mode -
/// handles held open past [`crate::sensor`]'s per-index cap - and stays apart
/// from `unresolved`, which is the resulting detection gap.
#[derive(Debug, Default)]
pub struct FileAttributionCounters {
    resolved_from_event: AtomicU64,
    resolved_from_index: AtomicU64,
    unresolved: AtomicU64,
    index_capacity_evictions: AtomicU64,
}

/// Process-wide file attribution accounting. Idle outside Windows.
pub static WINDOWS_FILE_ATTRIBUTION: FileAttributionCounters = FileAttributionCounters::new();

impl FileAttributionCounters {
    const fn new() -> Self {
        Self {
            resolved_from_event: AtomicU64::new(0),
            resolved_from_index: AtomicU64::new(0),
            unresolved: AtomicU64::new(0),
            index_capacity_evictions: AtomicU64::new(0),
        }
    }

    /// A file event reached the detectors with a path. `from_index` separates
    /// the events that needed the pointer index from the ones that carried
    /// their own name.
    pub fn record_resolved(&self, from_index: bool) {
        if from_index {
            self.resolved_from_index.fetch_add(1, Ordering::Relaxed);
        } else {
            self.resolved_from_event.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A file event was dropped because neither identifier resolved to a path.
    /// Returns the running total, which the caller uses to space its log line.
    pub fn record_unresolved(&self) -> u64 {
        self.unresolved.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Publish the index's cumulative capacity evictions.
    ///
    /// A store rather than an increment: the index owns the count and this is
    /// a republication of it, which keeps the eviction path free of atomics
    /// and keeps the index unit-testable without process-wide state.
    pub fn set_index_capacity_evictions(&self, evictions: u64) {
        self.index_capacity_evictions
            .store(evictions, Ordering::Relaxed);
    }

    /// Point-in-time view, or `None` when no file event has been attributed.
    pub fn snapshot(&self) -> Option<FileAttributionSnapshot> {
        let resolved_from_event = self.resolved_from_event.load(Ordering::Relaxed);
        let resolved_from_index = self.resolved_from_index.load(Ordering::Relaxed);
        let unresolved = self.unresolved.load(Ordering::Relaxed);
        let attempted = resolved_from_event
            .saturating_add(resolved_from_index)
            .saturating_add(unresolved);
        if attempted == 0 {
            return None;
        }
        Some(FileAttributionSnapshot {
            attempted,
            resolved_from_event,
            resolved_from_index,
            unresolved,
            index_capacity_evictions: self.index_capacity_evictions.load(Ordering::Relaxed),
        })
    }

    /// Reset every counter. Test-only, for the same reason as
    /// [`ChannelCounters::reset`].
    #[cfg(test)]
    pub fn reset(&self) {
        self.resolved_from_event.store(0, Ordering::Relaxed);
        self.resolved_from_index.store(0, Ordering::Relaxed);
        self.unresolved.store(0, Ordering::Relaxed);
        self.index_capacity_evictions.store(0, Ordering::Relaxed);
    }
}

/// Why a routed ETW record produced no sensor event.
///
/// Only failures are named here. A record the router declined, or one whose
/// whole job was to feed a path index, is not a failure and is counted apart -
/// see [`EtwDecodeCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EtwDecodeFailure {
    /// `SchemaLocator` could not describe the record, so no property of it is
    /// readable. Provider manifests are per-build, so this is what a provider
    /// that changed under an agent looks like.
    Schema,
    /// The record was described but a property the payload requires was
    /// absent: the template this build knows is not the one that arrived.
    UnsupportedLayout,
    /// A payload was built and every field a rule could select on was empty.
    Fieldless,
}

impl EtwDecodeFailure {
    /// Stable identifier used in snapshots and doctor output.
    pub const fn as_str(self) -> &'static str {
        match self {
            EtwDecodeFailure::Schema => "schema",
            EtwDecodeFailure::UnsupportedLayout => "unsupported_layout",
            EtwDecodeFailure::Fieldless => "fieldless",
        }
    }
}

/// What a decode failure is attributed to.
///
/// `provider` is a `&'static str` from the subscription table rather than a
/// rendered GUID, and the event ID and version come from the record header, so
/// the label space is bounded by the providers this build subscribes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EtwDecodeFailureKey {
    pub provider: &'static str,
    pub event_id: u16,
    pub version: u8,
    pub failure: EtwDecodeFailure,
}

/// Distinct failure keys retained before attribution stops.
///
/// The keys are already bounded by the provider allowlist, so this is a second
/// bound rather than the only one: it caps the memory a provider that starts
/// emitting a wide spread of event IDs can take, and caps the size of the
/// snapshot an operator has to read. Failures past the cap are still counted,
/// just not attributed - `unkeyed_failures` says how many.
const ETW_DECODE_FAILURE_KEYS: usize = 32;

/// Failure keys and their counts, capped at [`ETW_DECODE_FAILURE_KEYS`].
#[derive(Debug, Default)]
struct BoundedFailureKeys {
    counts: HashMap<EtwDecodeFailureKey, u64>,
    unkeyed: u64,
}

impl BoundedFailureKeys {
    fn record(&mut self, key: EtwDecodeFailureKey) {
        if let Some(count) = self.counts.get_mut(&key) {
            *count = count.saturating_add(1);
            return;
        }
        if self.counts.len() >= ETW_DECODE_FAILURE_KEYS {
            self.unkeyed = self.unkeyed.saturating_add(1);
            return;
        }
        self.counts.insert(key, 1);
    }

    /// Worst first, then by key, so the snapshot is stable across writes.
    fn snapshot(&self) -> Vec<EtwDecodeFailureSnapshot> {
        let mut failures: Vec<(EtwDecodeFailureKey, u64)> = self
            .counts
            .iter()
            .map(|(key, count)| (*key, *count))
            .collect();
        failures.sort_by_key(|(key, count)| (std::cmp::Reverse(*count), *key));
        failures
            .into_iter()
            .map(|(key, count)| EtwDecodeFailureSnapshot {
                provider: key.provider.to_string(),
                event_id: key.event_id,
                version: key.version,
                failure: key.failure.as_str().to_string(),
                count,
            })
            .collect()
    }
}

/// Windows ETW decoder accounting.
///
/// Every record the callback sees is classified into exactly one outcome, so
/// the totals reconcile against `records_received` and a silent decoder
/// regression cannot hide behind healthy channel counters. The outcomes are
/// deliberately not all losses:
///
/// - `records_filtered` is intentional - the router declined the record, or a
///   disposition said an open was not a creation. Volume here is the design
///   working, not a gap.
/// - `records_indexed` is a record whose job was to teach or evict a path, or
///   a registry write held for a naming event that has not arrived yet.
/// - `records_decoded` produced at least one event; `events_emitted` counts
///   the events, which is larger whenever a naming event replays writes.
/// - `records_unattributed` is the file and registry attribution gap: the
///   record was understood and dropped for want of a path.
/// - the three failure totals are decoder degradation, and each is attributed
///   to a bounded provider/event/version key.
///
/// This is deliberately separate from ETW's own `EventsLost`, which counts
/// records the kernel discarded before the callback ran, and from the channel
/// counters, which count events shed after it. The three losses have different
/// causes and different fixes, so nothing here folds them together.
#[derive(Debug, Default)]
pub struct EtwDecodeCounters {
    records_received: AtomicU64,
    records_filtered: AtomicU64,
    records_indexed: AtomicU64,
    records_decoded: AtomicU64,
    records_unattributed: AtomicU64,
    schema_errors: AtomicU64,
    unsupported_layouts: AtomicU64,
    fieldless_payloads: AtomicU64,
    events_emitted: AtomicU64,
    failures: Mutex<Option<BoundedFailureKeys>>,
}

/// Process-wide ETW decoder accounting. Idle outside Windows.
pub static ETW_DECODE: EtwDecodeCounters = EtwDecodeCounters::new();

impl EtwDecodeCounters {
    const fn new() -> Self {
        Self {
            records_received: AtomicU64::new(0),
            records_filtered: AtomicU64::new(0),
            records_indexed: AtomicU64::new(0),
            records_decoded: AtomicU64::new(0),
            records_unattributed: AtomicU64::new(0),
            schema_errors: AtomicU64::new(0),
            unsupported_layouts: AtomicU64::new(0),
            fieldless_payloads: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
            failures: Mutex::new(None),
        }
    }

    /// A record reached the ETW callback.
    pub fn record_received(&self) {
        self.records_received.fetch_add(1, Ordering::Relaxed);
    }

    /// A record was intentionally not turned into an event.
    pub fn record_filtered(&self) {
        self.records_filtered.fetch_add(1, Ordering::Relaxed);
    }

    /// A record maintained a path index or was held for a late naming event.
    pub fn record_indexed(&self) {
        self.records_indexed.fetch_add(1, Ordering::Relaxed);
    }

    /// A record produced `events` sensor events.
    pub fn record_decoded(&self, events: usize) {
        self.records_decoded.fetch_add(1, Ordering::Relaxed);
        self.events_emitted
            .fetch_add(events as u64, Ordering::Relaxed);
    }

    /// A record was understood but dropped for want of a resolvable path.
    pub fn record_unattributed(&self) {
        self.records_unattributed.fetch_add(1, Ordering::Relaxed);
    }

    /// A record failed to decode, attributed to a bounded key.
    pub fn record_failure(&self, key: EtwDecodeFailureKey) {
        let total = match key.failure {
            EtwDecodeFailure::Schema => &self.schema_errors,
            EtwDecodeFailure::UnsupportedLayout => &self.unsupported_layouts,
            EtwDecodeFailure::Fieldless => &self.fieldless_payloads,
        };
        total.fetch_add(1, Ordering::Relaxed);

        // Recovered rather than propagated: this runs inside an OS-invoked ETW
        // callback, where unwinding would take the sensor down, and the
        // attribution table is reporting state the decoder does not read back.
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        failures
            .get_or_insert_with(BoundedFailureKeys::default)
            .record(key);
    }

    /// Point-in-time view, or `None` when no record has been decoded.
    pub fn snapshot(&self) -> Option<EtwDecodeSnapshot> {
        let records_received = self.records_received.load(Ordering::Relaxed);
        if records_received == 0 {
            return None;
        }
        let failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (attributed, unkeyed) = match failures.as_ref() {
            Some(keys) => (keys.snapshot(), keys.unkeyed),
            None => (Vec::new(), 0),
        };
        Some(EtwDecodeSnapshot {
            records_received,
            records_filtered: self.records_filtered.load(Ordering::Relaxed),
            records_indexed: self.records_indexed.load(Ordering::Relaxed),
            records_decoded: self.records_decoded.load(Ordering::Relaxed),
            records_unattributed: self.records_unattributed.load(Ordering::Relaxed),
            schema_errors: self.schema_errors.load(Ordering::Relaxed),
            unsupported_layouts: self.unsupported_layouts.load(Ordering::Relaxed),
            fieldless_payloads: self.fieldless_payloads.load(Ordering::Relaxed),
            events_emitted: self.events_emitted.load(Ordering::Relaxed),
            failures: attributed,
            unkeyed_failures: unkeyed,
        })
    }

    /// Reset every counter. Test-only, for the same reason as
    /// [`ChannelCounters::reset`].
    #[cfg(test)]
    pub fn reset(&self) {
        for counter in [
            &self.records_received,
            &self.records_filtered,
            &self.records_indexed,
            &self.records_decoded,
            &self.records_unattributed,
            &self.schema_errors,
            &self.unsupported_layouts,
            &self.fieldless_payloads,
            &self.events_emitted,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        *self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

#[derive(Debug)]
struct SensorEventCategoryCounters {
    accepted: AtomicU64,
    dropped: AtomicU64,
}

impl SensorEventCategoryCounters {
    const fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    fn record_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

static SENSOR_EVENT_CATEGORIES: [SensorEventCategoryCounters; 12] = [
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
    SensorEventCategoryCounters::new(),
];

fn sensor_event_category(category: EventCategory) -> (usize, &'static str) {
    match category {
        EventCategory::Process => (0, "process"),
        EventCategory::Network => (1, "network"),
        EventCategory::File => (2, "file"),
        EventCategory::Registry => (3, "registry"),
        EventCategory::Dns => (4, "dns"),
        EventCategory::ImageLoad => (5, "image_load"),
        EventCategory::Scripting => (6, "scripting"),
        EventCategory::PowerShellModule => (7, "powershell_module"),
        EventCategory::Wmi => (8, "wmi"),
        EventCategory::Service => (9, "service"),
        EventCategory::Task => (10, "task"),
        EventCategory::Security => (11, "security"),
    }
}

fn sensor_event_category_snapshots() -> Vec<SensorEventCategorySnapshot> {
    [
        EventCategory::Process,
        EventCategory::Network,
        EventCategory::File,
        EventCategory::Registry,
        EventCategory::Dns,
        EventCategory::ImageLoad,
        EventCategory::Scripting,
        EventCategory::PowerShellModule,
        EventCategory::Wmi,
        EventCategory::Service,
        EventCategory::Task,
        EventCategory::Security,
    ]
    .into_iter()
    .filter_map(|category| {
        let (index, name) = sensor_event_category(category);
        let counters = &SENSOR_EVENT_CATEGORIES[index];
        let accepted = counters.accepted.load(Ordering::Relaxed);
        let dropped = counters.dropped.load(Ordering::Relaxed);
        (accepted > 0 || dropped > 0).then(|| SensorEventCategorySnapshot {
            category: name.to_string(),
            accepted,
            dropped,
        })
    })
    .collect()
}

/// Atomic accounting for one bounded channel.
///
/// All counters are `Relaxed`: they are independent totals read for reporting,
/// never used to order other memory.
#[derive(Debug)]
pub struct ChannelCounters {
    id: ChannelId,
    /// Configured channel capacity, learned from the first send.
    capacity: AtomicUsize,
    /// Items accepted by the channel.
    accepted: AtomicU64,
    /// Items dropped because the channel was full — this is the detection gap.
    dropped: AtomicU64,
    /// Items dropped because the consumer was gone, which is shutdown, not loss.
    dropped_closed: AtomicU64,
    /// Deepest queue depth observed after a successful send.
    high_water_mark: AtomicUsize,
}

impl ChannelCounters {
    const fn new(id: ChannelId) -> Self {
        Self {
            id,
            capacity: AtomicUsize::new(0),
            accepted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            dropped_closed: AtomicU64::new(0),
            high_water_mark: AtomicUsize::new(0),
        }
    }

    pub fn id(&self) -> ChannelId {
        self.id
    }

    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn dropped_closed(&self) -> u64 {
        self.dropped_closed.load(Ordering::Relaxed)
    }

    pub fn high_water_mark(&self) -> usize {
        self.high_water_mark.load(Ordering::Relaxed)
    }

    /// Point-in-time view of this channel.
    pub fn snapshot(&self) -> ChannelSnapshot {
        ChannelSnapshot {
            channel: self.id.as_str().to_string(),
            capacity: self.capacity(),
            accepted: self.accepted(),
            dropped: self.dropped(),
            dropped_channel_closed: self.dropped_closed(),
            high_water_mark: self.high_water_mark(),
        }
    }

    /// Reset every counter. Test-only: the statics outlive individual tests, so
    /// a test that asserts on totals has to start from a known state.
    #[cfg(test)]
    pub fn reset(&self) {
        self.capacity.store(0, Ordering::Relaxed);
        self.accepted.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
        self.dropped_closed.store(0, Ordering::Relaxed);
        self.high_water_mark.store(0, Ordering::Relaxed);
    }

    /// Record the channel's shape, whatever the send's outcome was.
    fn observe(&self, capacity: usize, depth: usize) {
        if self.capacity.load(Ordering::Relaxed) != capacity {
            self.capacity.store(capacity, Ordering::Relaxed);
        }

        // Read before the read-modify-write so the steady state — a queue that
        // is not setting a new record — costs a load rather than a CAS loop.
        if depth > self.high_water_mark.load(Ordering::Relaxed) {
            self.high_water_mark.fetch_max(depth, Ordering::Relaxed);
        }
    }

    fn record_accepted(&self, capacity: usize, depth: usize) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.observe(capacity, depth);
    }

    fn record_dropped(&self, capacity: usize) {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        // A full channel is by definition at its deepest.
        self.observe(capacity, capacity);

        let decision = match DROP_WARNINGS.lock() {
            Ok(mut limiter) => limiter.should_emit(self.id.as_str()),
            // A poisoned limiter must not silence the loss report.
            Err(poisoned) => poisoned.into_inner().should_emit(self.id.as_str()),
        };
        if decision.should_emit {
            warn!(
                target: TARGET_TELEMETRY,
                channel = self.id.as_str(),
                capacity,
                dropped_total = dropped,
                accepted_total = self.accepted(),
                suppressed_warnings = decision.suppressed_since_last_emit,
                "Pipeline channel full; shedding telemetry"
            );
        }
    }

    fn record_dropped_closed(&self) {
        self.dropped_closed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Send on a bounded channel without blocking, accounting for the outcome.
///
/// Behaves exactly like [`Sender::try_send`] — the caller still decides what a
/// failure means — but records the send against `channel` so the loss shows up
/// in the snapshot and in `rustinel doctor` instead of only in the log.
pub fn try_send<T>(channel: ChannelId, tx: &Sender<T>, value: T) -> Result<(), TrySendError<T>> {
    let counters = channel.counters();
    let capacity = tx.max_capacity();

    match tx.try_send(value) {
        Ok(()) => {
            // Remaining capacity is sampled after the send, so the depth
            // includes the item just queued. Another producer can push between
            // the two calls, which makes this a close estimate rather than an
            // exact reading — the high-water mark is a saturation signal, not
            // an accounting figure.
            let depth = capacity.saturating_sub(tx.capacity());
            counters.record_accepted(capacity, depth);
            Ok(())
        }
        Err(TrySendError::Full(value)) => {
            counters.record_dropped(capacity);
            Err(TrySendError::Full(value))
        }
        Err(TrySendError::Closed(value)) => {
            counters.record_dropped_closed();
            Err(TrySendError::Closed(value))
        }
    }
}

/// Send one sensor event while retaining accepted and dropped counts by category.
#[allow(clippy::result_large_err)]
pub fn try_send_sensor_event(
    tx: &Sender<SensorEvent>,
    value: SensorEvent,
) -> Result<(), TrySendError<SensorEvent>> {
    let (index, _) = sensor_event_category(value.category());
    match try_send(ChannelId::SensorEvents, tx, value) {
        Ok(()) => {
            SENSOR_EVENT_CATEGORIES[index].record_accepted();
            Ok(())
        }
        Err(err @ TrySendError::Full(_)) => {
            SENSOR_EVENT_CATEGORIES[index].record_dropped();
            Err(err)
        }
        Err(err @ TrySendError::Closed(_)) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn process_command_line_fidelity_counts_hits_and_misses() {
        let counters = ProcessCommandLineCounters::new();
        assert!(counters.snapshot().is_none());

        counters.record(true);
        counters.record(false);
        counters.record(true);

        assert_eq!(
            counters.snapshot(),
            Some(ProcessCommandLineSnapshot {
                attempted: 3,
                captured: 2,
                missed: 1,
            })
        );
    }

    #[test]
    fn an_attempted_empty_registry_rundown_is_still_visible() {
        let counters = RegistryCounters::new();
        assert!(counters.snapshot().is_none());

        counters.set_snapshot_keys(0);

        let snapshot = counters.snapshot().expect("attempted rundown");
        assert!(snapshot.rundown_attempted);
        assert_eq!(snapshot.snapshot_keys, 0);
    }

    /// A decoder driven by injected faults, without an ETW session.
    ///
    /// `EventRecord` and `SchemaLocator` are opaque OS-owned handles that
    /// cannot be constructed in a unit test, so the decoder's *classification*
    /// is exercised here through the same counter API the ETW callback calls,
    /// with the faults chosen by the caller. What this pins down is the part a
    /// live capture cannot check by inspection: that every record lands in
    /// exactly one outcome and that the totals reconcile.
    struct DecoderHarness {
        decode: EtwDecodeCounters,
        files: FileAttributionCounters,
        queued: u64,
    }

    /// What the provider is doing to one record.
    enum InjectedFault {
        None,
        /// The router declined it.
        Filtered,
        /// It only fed a path index.
        Indexed,
        /// Its path could not be recovered, so it was dropped.
        Unattributed,
        Failure(EtwDecodeFailure),
    }

    impl DecoderHarness {
        fn new() -> Self {
            Self {
                decode: EtwDecodeCounters::new(),
                files: FileAttributionCounters::new(),
                queued: 0,
            }
        }

        /// Feed one record whose decode hits `fault`, emitting `events` on the
        /// clean path.
        fn feed(
            &mut self,
            provider: &'static str,
            event_id: u16,
            version: u8,
            fault: InjectedFault,
            events: usize,
        ) {
            self.decode.record_received();
            match fault {
                InjectedFault::Filtered => self.decode.record_filtered(),
                InjectedFault::Indexed => self.decode.record_indexed(),
                InjectedFault::Unattributed => {
                    self.decode.record_unattributed();
                    self.files.record_unresolved();
                }
                InjectedFault::None if provider == "Microsoft-Windows-Kernel-File" => {
                    self.files.record_resolved(true);
                    self.decode.record_decoded(events);
                    self.queued += events as u64;
                }
                InjectedFault::Failure(failure) => {
                    self.decode.record_failure(EtwDecodeFailureKey {
                        provider,
                        event_id,
                        version,
                        failure,
                    })
                }
                InjectedFault::None => {
                    self.decode.record_decoded(events);
                    self.queued += events as u64;
                }
            }
        }
    }

    /// The counters exist to answer "is the decoder still producing events?",
    /// and that answer is only trustworthy if every record is accounted for.
    #[test]
    fn injected_decode_faults_reconcile_with_received_and_queued_records() {
        let mut harness = DecoderHarness::new();

        // A healthy provider, a naming event that replays two held writes, and
        // one of each degradation the decoder can suffer.
        harness.feed(
            "Microsoft-Windows-Kernel-Process",
            1,
            3,
            InjectedFault::None,
            1,
        );
        harness.feed(
            "Microsoft-Windows-Kernel-Registry",
            1,
            0,
            InjectedFault::None,
            3,
        );
        harness.feed(
            "Microsoft-Windows-Kernel-File",
            15,
            0,
            InjectedFault::Filtered,
            0,
        );
        harness.feed(
            "Microsoft-Windows-Kernel-File",
            10,
            0,
            InjectedFault::Indexed,
            0,
        );
        harness.feed(
            "Microsoft-Windows-Kernel-File",
            16,
            0,
            InjectedFault::Unattributed,
            0,
        );
        harness.feed(
            "Microsoft-Windows-DNS-Client",
            3020,
            0,
            InjectedFault::Failure(EtwDecodeFailure::Schema),
            0,
        );
        harness.feed(
            "Microsoft-Windows-Kernel-Process",
            1,
            9,
            InjectedFault::Failure(EtwDecodeFailure::UnsupportedLayout),
            0,
        );
        harness.feed(
            "Microsoft-Windows-PowerShell",
            4104,
            1,
            InjectedFault::Failure(EtwDecodeFailure::Fieldless),
            0,
        );

        let snapshot = harness.decode.snapshot().expect("records were received");

        assert_eq!(snapshot.records_received, 8);
        assert_eq!(snapshot.records_filtered, 1);
        assert_eq!(snapshot.records_indexed, 1);
        assert_eq!(snapshot.records_decoded, 2);
        assert_eq!(snapshot.records_unattributed, 1);
        assert_eq!(snapshot.schema_errors, 1);
        assert_eq!(snapshot.unsupported_layouts, 1);
        assert_eq!(snapshot.fieldless_payloads, 1);
        assert!(
            snapshot.is_reconciled(),
            "every record must land in exactly one outcome: {snapshot:?}"
        );
        // A naming event replays the writes that were waiting on it, so more
        // events reach the queue than there were decoded records.
        assert_eq!(snapshot.events_emitted, 4);
        assert_eq!(snapshot.events_emitted, harness.queued);

        // Intentional filtering is not loss, and does not inflate the rate an
        // operator reads as decoder degradation.
        assert_eq!(snapshot.failed(), 3);
        assert!((snapshot.failure_rate_pct() - 37.5).abs() < f64::EPSILON);

        // Only the Kernel-File records touch path attribution, and the write
        // that could not be named is the one gap no channel counter can show.
        let files = harness
            .files
            .snapshot()
            .expect("file events were attributed");
        assert_eq!(files.attempted, 1);
        assert_eq!(files.unresolved, 1);
        assert_eq!(files.resolution_rate_pct(), 0.0);
    }

    /// The events a decoded record produces have to reach the queue, and the
    /// two counters are kept by different modules - so reconcile them.
    #[tokio::test]
    async fn emitted_events_reconcile_with_the_sensor_queue() {
        let _guard = counter_guard();
        let mut harness = DecoderHarness::new();
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(2);

        for _ in 0..5 {
            harness.feed(
                "Microsoft-Windows-Kernel-Process",
                1,
                3,
                InjectedFault::None,
                1,
            );
            let _ = try_send(ChannelId::SensorEvents, &tx, 1);
        }

        let snapshot = harness.decode.snapshot().expect("records were received");
        let channel = ChannelId::SensorEvents.counters();

        assert_eq!(snapshot.events_emitted, 5);
        assert_eq!(
            snapshot.events_emitted,
            channel.accepted() + channel.dropped(),
            "every emitted event is either queued or shed, never neither"
        );
        // The queue shed three of them, and that is a different gap from any
        // of the decoder's: the record decoded fine.
        assert_eq!(channel.dropped(), 3);
        assert_eq!(snapshot.failed(), 0);
    }

    /// A provider that starts failing across a wide spread of event IDs must
    /// not be able to grow the snapshot without bound.
    #[test]
    fn decode_failure_keys_are_bounded_and_ranked() {
        let counters = EtwDecodeCounters::new();

        for event_id in 0..(ETW_DECODE_FAILURE_KEYS as u16 * 4) {
            counters.record_received();
            counters.record_failure(EtwDecodeFailureKey {
                provider: "Microsoft-Windows-Kernel-File",
                event_id,
                version: 0,
                failure: EtwDecodeFailure::Schema,
            });
        }
        // One key fails far more often than the rest, and must lead.
        for _ in 0..100 {
            counters.record_received();
            counters.record_failure(EtwDecodeFailureKey {
                provider: "Microsoft-Windows-Kernel-File",
                event_id: 0,
                version: 0,
                failure: EtwDecodeFailure::Schema,
            });
        }

        let snapshot = counters.snapshot().expect("records were received");

        assert_eq!(snapshot.failures.len(), ETW_DECODE_FAILURE_KEYS);
        assert_eq!(snapshot.failures[0].event_id, 0);
        assert_eq!(snapshot.failures[0].count, 101);
        assert_eq!(
            snapshot.failures[0].provider,
            "Microsoft-Windows-Kernel-File"
        );
        // Nothing is lost by the cap: the failures past it are still counted,
        // just not attributed.
        assert_eq!(snapshot.unkeyed_failures, 96);
        assert_eq!(
            snapshot.failed(),
            snapshot.failures.iter().map(|f| f.count).sum::<u64>() + snapshot.unkeyed_failures
        );
    }

    /// Absent counters must stay absent rather than reporting a perfect run:
    /// Linux and macOS have no ETW decoder at all.
    #[test]
    fn idle_windows_counters_report_nothing() {
        assert!(EtwDecodeCounters::new().snapshot().is_none());
        assert!(FileAttributionCounters::new().snapshot().is_none());
    }

    /// The index owns the eviction count; telemetry republishes it. A store
    /// rather than an increment means a republication cannot double-count.
    #[test]
    fn index_capacity_evictions_are_republished_not_accumulated() {
        let counters = FileAttributionCounters::new();
        counters.record_resolved(true);

        counters.set_index_capacity_evictions(12);
        counters.set_index_capacity_evictions(12);
        counters.set_index_capacity_evictions(30);

        let snapshot = counters.snapshot().expect("a file event was attributed");
        assert_eq!(snapshot.attempted, 1);
        assert_eq!(snapshot.index_capacity_evictions, 30);
        // Evictions are the mechanism, not the gap: they must not be mistaken
        // for events that failed to resolve.
        assert_eq!(snapshot.unresolved, 0);
        assert_eq!(snapshot.resolution_rate_pct(), 100.0);
    }

    /// Serializes tests that assert on the process-wide statics.
    fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for channel in ChannelId::ALL {
            channel.counters().reset();
        }
        ETW_DECODE.reset();
        WINDOWS_FILE_ATTRIBUTION.reset();
        // The warning limiter is process-wide too. Reset it alongside the
        // counters so tests cannot inherit a channel's rate-limit window.
        let mut limiter = DROP_WARNINGS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *limiter = LogRateLimiter::new(DROP_WARN_INTERVAL);
        guard
    }

    #[test]
    fn channel_identifiers_are_unique_and_indexed_consistently() {
        for (index, channel) in ChannelId::ALL.iter().enumerate() {
            assert_eq!(channel.index(), index, "{} is misindexed", channel.as_str());
            assert_eq!(channel.counters().id(), *channel);
        }
    }

    #[tokio::test]
    async fn accepted_sends_are_counted_with_queue_depth() {
        let _guard = counter_guard();
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(4);

        for value in 0..3u8 {
            try_send(ChannelId::IocHash, &tx, value).expect("channel has room");
        }

        let counters = ChannelId::IocHash.counters();
        assert_eq!(counters.accepted(), 3);
        assert_eq!(counters.dropped(), 0);
        assert_eq!(counters.capacity(), 4);
        assert_eq!(counters.high_water_mark(), 3);
    }

    #[tokio::test]
    async fn a_full_channel_counts_drops_and_pins_the_high_water_mark() {
        let _guard = counter_guard();
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(2);

        try_send(ChannelId::YaraFileScan, &tx, 1).expect("channel has room");
        try_send(ChannelId::YaraFileScan, &tx, 2).expect("channel has room");
        for value in 3..8u8 {
            let err = try_send(ChannelId::YaraFileScan, &tx, value).expect_err("channel is full");
            assert!(matches!(err, TrySendError::Full(_)));
        }

        let counters = ChannelId::YaraFileScan.counters();
        assert_eq!(counters.accepted(), 2);
        assert_eq!(counters.dropped(), 5);
        assert_eq!(counters.dropped_closed(), 0);
        assert_eq!(counters.high_water_mark(), 2);
    }

    /// A dropped value has to come back to the caller intact: the sensors rely
    /// on it to fall back to a less-enriched send rather than lose the event.
    #[tokio::test]
    async fn a_dropped_value_is_returned_to_the_caller() {
        let _guard = counter_guard();
        let (tx, _rx) = tokio::sync::mpsc::channel::<String>(1);

        try_send(ChannelId::SensorEvents, &tx, "queued".to_string()).expect("channel has room");
        let err = try_send(ChannelId::SensorEvents, &tx, "shed".to_string())
            .expect_err("channel is full");

        match err {
            TrySendError::Full(value) => assert_eq!(value, "shed"),
            TrySendError::Closed(_) => panic!("channel is full, not closed"),
        }
    }

    /// Shutdown is not a detection gap, so a closed channel must not inflate
    /// the drop count an operator reads as lost telemetry.
    #[tokio::test]
    async fn a_closed_channel_is_counted_apart_from_load_shedding() {
        let _guard = counter_guard();
        let (tx, rx) = tokio::sync::mpsc::channel::<u8>(4);
        drop(rx);

        let err = try_send(ChannelId::ActiveResponse, &tx, 1).expect_err("channel is closed");
        assert!(matches!(err, TrySendError::Closed(_)));

        let counters = ChannelId::ActiveResponse.counters();
        assert_eq!(counters.dropped(), 0);
        assert_eq!(counters.dropped_closed(), 1);
        assert_eq!(counters.accepted(), 0);
    }

    #[tokio::test]
    async fn channels_are_counted_independently() {
        let _guard = counter_guard();
        let (full_tx, _full_rx) = tokio::sync::mpsc::channel::<u8>(1);
        let (open_tx, _open_rx) = tokio::sync::mpsc::channel::<u8>(4);

        try_send(ChannelId::CaptureWriter, &full_tx, 1).expect("channel has room");
        let _ = try_send(ChannelId::CaptureWriter, &full_tx, 2);
        try_send(ChannelId::IocHash, &open_tx, 3).expect("channel has room");

        assert_eq!(ChannelId::CaptureWriter.counters().dropped(), 1);
        assert_eq!(ChannelId::IocHash.counters().dropped(), 0);
        assert_eq!(ChannelId::IocHash.counters().accepted(), 1);
    }

    /// The warning is the only live signal while a channel is shedding, so
    /// both its rate limiting and its field names are part of the contract.
    #[tokio::test]
    async fn a_burst_of_drops_emits_one_cumulative_warning() {
        let _guard = counter_guard();
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(1);
        let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        let collector = tracing_subscriber::fmt()
            .with_writer(CollectingWriter(Arc::clone(&lines)))
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(collector, || {
            for value in 0..6u8 {
                let _ = try_send(ChannelId::SensorEvents, &tx, value);
            }
        });

        let lines = lines.lock().expect("collected lines");
        let warnings: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("shedding telemetry"))
            .collect();

        assert_eq!(
            warnings.len(),
            1,
            "five drops fold into one line: {lines:?}"
        );
        for field in [
            "channel=\"sensor_events\"",
            "capacity=1",
            "dropped_total=1",
            "accepted_total=1",
            "suppressed_warnings=0",
        ] {
            assert!(
                warnings[0].contains(field),
                "missing {field}: {}",
                warnings[0]
            );
        }
    }

    /// Captures rendered log output so the warning can be asserted on as an
    /// operator would read it.
    #[derive(Clone)]
    struct CollectingWriter(Arc<std::sync::Mutex<Vec<String>>>);

    impl std::io::Write for CollectingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut lines = self.0.lock().unwrap_or_else(|e| e.into_inner());
            lines.push(String::from_utf8_lossy(buf).into_owned());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CollectingWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
}
