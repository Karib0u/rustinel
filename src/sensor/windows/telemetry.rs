//! Windows ETW sensor accounting.
//!
//! Owned by [`super::WindowsHostExtension`], so each runtime counts its own
//! registry resolution, file attribution and decoder outcomes.
//! The snapshot types live in `crate::telemetry` and are shared by every
//! platform, because `rustinel doctor` reads them on any host.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use super::registry_paths::PathSource;
use crate::telemetry::{
    EtwDecodeFailureSnapshot, EtwDecodeSnapshot, FileAttributionSnapshot, FileRundownSnapshot,
    RegistrySnapshot, SensorTelemetry,
};

/// Every Windows counter set, one per runtime.
#[derive(Debug, Default)]
pub(crate) struct WindowsCounters {
    pub(crate) registry: RegistryCounters,
    pub(crate) file_attribution: FileAttributionCounters,
    pub(crate) etw_decode: EtwDecodeCounters,
    pub(crate) event_log: std::sync::Arc<crate::telemetry::EventLogHealth>,
}

impl WindowsCounters {
    pub(crate) fn report(&self, out: &mut SensorTelemetry) {
        out.registry = self.registry.snapshot();
        out.file_attribution = self.file_attribution.snapshot();
        out.etw_decode = self.etw_decode.snapshot();
        out.windows_event_log = self.event_log.snapshot();
    }
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

impl RegistryCounters {
    /// A write event resolved to a key path, and which tier of the index
    /// answered. The two non-default tiers are each a class of event that
    /// used to be dropped, so they are what the fix is measured by.
    pub(super) fn record_resolved(&self, source: PathSource) {
        self.events_received.fetch_add(1, Ordering::Relaxed);
        self.events_resolved.fetch_add(1, Ordering::Relaxed);
        match source {
            PathSource::Session => {}
            PathSource::StartupSnapshot => {
                self.resolved_from_snapshot.fetch_add(1, Ordering::Relaxed);
            }
            PathSource::RecentlyClosed => {
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
    rundown: Mutex<Option<FileRundownSnapshot>>,
}

impl FileAttributionCounters {
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

    /// Publish the complete startup result, including rejected snapshots.
    pub fn set_rundown(&self, result: FileRundownSnapshot) {
        *self.rundown.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
    }

    /// Point-in-time view, including a startup attempt with no live events.
    pub fn snapshot(&self) -> Option<FileAttributionSnapshot> {
        let resolved_from_event = self.resolved_from_event.load(Ordering::Relaxed);
        let resolved_from_index = self.resolved_from_index.load(Ordering::Relaxed);
        let unresolved = self.unresolved.load(Ordering::Relaxed);
        let attempted = resolved_from_event
            .saturating_add(resolved_from_index)
            .saturating_add(unresolved);
        let rundown = self
            .rundown
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if attempted == 0 && rundown.is_none() {
            return None;
        }
        Some(FileAttributionSnapshot {
            attempted,
            resolved_from_event,
            resolved_from_index,
            unresolved,
            index_capacity_evictions: self.index_capacity_evictions.load(Ordering::Relaxed),
            rundown,
        })
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

impl EtwDecodeCounters {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attempted_empty_registry_rundown_is_still_visible() {
        let counters = RegistryCounters::default();
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
                decode: EtwDecodeCounters::default(),
                files: FileAttributionCounters::default(),
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
        let mut harness = DecoderHarness::new();
        let channel =
            crate::telemetry::ChannelCounters::new(crate::telemetry::ChannelId::SensorEvents);
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(2);

        for _ in 0..5 {
            harness.feed(
                "Microsoft-Windows-Kernel-Process",
                1,
                3,
                InjectedFault::None,
                1,
            );
            let _ = crate::telemetry::try_send_counted(&channel, &tx, 1);
        }

        let snapshot = harness.decode.snapshot().expect("records were received");

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
        let counters = EtwDecodeCounters::default();

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
        assert!(EtwDecodeCounters::default().snapshot().is_none());
        assert!(FileAttributionCounters::default().snapshot().is_none());
    }

    /// The index owns the eviction count; telemetry republishes it. A store
    /// rather than an increment means a republication cannot double-count.
    #[test]
    fn index_capacity_evictions_are_republished_not_accumulated() {
        let counters = FileAttributionCounters::default();
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
}
