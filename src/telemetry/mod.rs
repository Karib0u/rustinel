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

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::utils::LogRateLimiter;

pub use snapshot::{
    snapshot_path, spawn_reporter, write_final_snapshot, ChannelSnapshot, RegistrySnapshot,
    TelemetrySnapshot, SNAPSHOT_FILE_NAME,
};

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn an_attempted_empty_registry_rundown_is_still_visible() {
        let counters = RegistryCounters::new();
        assert!(counters.snapshot().is_none());

        counters.set_snapshot_keys(0);

        let snapshot = counters.snapshot().expect("attempted rundown");
        assert!(snapshot.rundown_attempted);
        assert_eq!(snapshot.snapshot_keys, 0);
    }

    /// Serializes tests that assert on the process-wide statics.
    fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for channel in ChannelId::ALL {
            channel.counters().reset();
        }
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
