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

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::warn;

pub use snapshot::{
    snapshot_path, spawn_reporter, write_final_snapshot, ChannelSnapshot, TelemetrySnapshot,
    SNAPSHOT_FILE_NAME,
};

/// Tracing target for pipeline telemetry accounting.
pub const TARGET_TELEMETRY: &str = "telemetry";

/// Minimum spacing between cumulative drop warnings for one channel.
///
/// The first drop on a channel always warns; after that the warning carries
/// the running total, so a burst produces one line rather than one per event.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Process start, used as the epoch for the lock-free warning rate limiter.
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

    /// What is lost when this channel drops, for operator-facing output.
    pub const fn loss_description(self) -> &'static str {
        match self {
            ChannelId::SensorEvents => "raw sensor events never reached the detectors",
            ChannelId::YaraFileScan => "files were never YARA scanned",
            ChannelId::YaraMemoryScan => "processes were never memory scanned",
            ChannelId::IocHash => "process images were never hashed for IOC matching",
            ChannelId::ActiveResponse => "response actions were never executed",
            ChannelId::CaptureWriter => "events never reached the recording",
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
    /// Milliseconds since [`PROCESS_START`] at the last emitted drop warning.
    last_warn_millis: AtomicU64,
    /// Cumulative drop total at the last emitted drop warning.
    warned_at_total: AtomicU64,
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
            last_warn_millis: AtomicU64::new(0),
            warned_at_total: AtomicU64::new(0),
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
        self.last_warn_millis.store(0, Ordering::Relaxed);
        self.warned_at_total.store(0, Ordering::Relaxed);
    }

    fn record_accepted(&self, capacity: usize, depth: usize) {
        self.accepted.fetch_add(1, Ordering::Relaxed);

        if self.capacity.load(Ordering::Relaxed) != capacity {
            self.capacity.store(capacity, Ordering::Relaxed);
        }

        // Read before the read-modify-write so the steady state — a queue that
        // is not setting a new record — costs a load rather than a CAS loop.
        if depth > self.high_water_mark.load(Ordering::Relaxed) {
            self.high_water_mark.fetch_max(depth, Ordering::Relaxed);
        }
    }

    fn record_dropped(&self, capacity: usize) {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;

        if self.capacity.load(Ordering::Relaxed) != capacity {
            self.capacity.store(capacity, Ordering::Relaxed);
        }
        // A full channel is by definition at its deepest.
        if capacity > self.high_water_mark.load(Ordering::Relaxed) {
            self.high_water_mark.fetch_max(capacity, Ordering::Relaxed);
        }

        if let Some(since_last_warning) =
            self.claim_warning(dropped, DROP_WARN_INTERVAL.as_millis() as u64)
        {
            warn!(
                target: TARGET_TELEMETRY,
                channel = self.id.as_str(),
                capacity,
                dropped_total = dropped,
                dropped_since_last_warning = since_last_warning,
                accepted_total = self.accepted(),
                "Pipeline channel full; shedding telemetry"
            );
        }
    }

    fn record_dropped_closed(&self) {
        self.dropped_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Decide whether this drop should warn, returning how many drops the
    /// warning covers.
    ///
    /// Lock-free on purpose: drops happen exactly when the pipeline is already
    /// saturated, which is the worst moment to add a contended mutex. Losing a
    /// race here costs at most one suppressed warning line.
    fn claim_warning(&self, dropped: u64, interval_millis: u64) -> Option<u64> {
        let now_millis = PROCESS_START.elapsed().as_millis() as u64;
        let last_millis = self.last_warn_millis.load(Ordering::Relaxed);
        let is_first_drop = dropped == 1;

        if !is_first_drop && now_millis.saturating_sub(last_millis) < interval_millis {
            return None;
        }

        self.last_warn_millis
            .compare_exchange(
                last_millis,
                now_millis,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .ok()?;

        let previous_total = self.warned_at_total.swap(dropped, Ordering::Relaxed);
        Some(dropped.saturating_sub(previous_total))
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
    use super::*;

    /// Serializes tests that assert on the process-wide statics.
    fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for channel in ChannelId::ALL {
            channel.counters().reset();
        }
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

    /// The first drop must always warn; the rest of a burst folds into the
    /// next interval so a saturated channel cannot flood the log it is trying
    /// to make legible.
    #[tokio::test]
    async fn cumulative_drop_warnings_are_rate_limited() {
        let _guard = counter_guard();
        let counters = ChannelId::YaraMemoryScan.counters();

        let interval = DROP_WARN_INTERVAL.as_millis() as u64;

        assert_eq!(
            counters.claim_warning(1, interval),
            Some(1),
            "first drop always warns"
        );
        assert_eq!(
            counters.claim_warning(2, interval),
            None,
            "burst is suppressed"
        );
        assert_eq!(
            counters.claim_warning(3, interval),
            None,
            "burst is suppressed"
        );

        // A zero interval stands in for the wait, so the test never sleeps.
        assert_eq!(
            counters.claim_warning(9, 0),
            Some(8),
            "the next warning covers every drop since the last one"
        );
    }
}
