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

pub(crate) mod event_log;
pub(crate) mod macos;
#[cfg(windows)]
pub use event_log::EventLogHealth;
pub use event_log::EventLogSnapshot;
mod probes;
mod process_correlation;
pub(crate) mod provenance;
pub use provenance::{FieldFidelitySnapshot, ProvenanceCounters};
mod snapshot;
pub use macos::{
    BpfInterfaceSnapshot, BpfSnapshot, EsfSnapshot, MacosCollectorSnapshot, MacosCollectors,
};
pub use probes::PipelineProbes;
pub use process_correlation::{
    ProcessCommandLineCounters, ProcessCorrelationCounters, ProcessCorrelationSnapshot,
};
pub(crate) mod webhook;
pub use webhook::{WebhookCounters, WebhookSnapshot};

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::utils::LogRateLimiter;

pub use snapshot::{
    snapshot_path, ChannelSnapshot, EtwDecodeFailureSnapshot, EtwDecodeSnapshot,
    FileAttributionSnapshot, FileRundownSnapshot, LinuxEbpfFamilySnapshot,
    LinuxEbpfFeatureSnapshot, LinuxEbpfSnapshot, ProcessCommandLineSnapshot, RegistrySnapshot,
    SensorEventCategorySnapshot, SensorTelemetry, SnapshotRead, TelemetrySnapshot,
    SNAPSHOT_FILE_NAME,
};
pub(crate) use snapshot::{spawn_reporter, write_final_snapshot};

use crate::models::EventCategory;
use crate::sensor::RawEvent;

/// Tracing target for pipeline telemetry accounting.
pub const TARGET_TELEMETRY: &str = "telemetry";

/// Minimum spacing between cumulative drop warnings for one channel.
///
/// The first drop on a channel always warns; after that the warning carries
/// the running total, so a burst produces one line rather than one per event.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(60);

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
    /// Canonical events queued for single-open artifact resolution.
    ArtifactResolution,
    /// Written files queued separately from process and loaded images.
    ArtifactWrittenFiles,
    /// Processes queued for YARA memory scanning.
    YaraMemoryScan,
    /// Alerts queued for active response.
    ActiveResponse,
    /// Normalized events queued for the capture recording writer.
    CaptureWriter,
}

impl ChannelId {
    /// Every channel, in the order snapshots report them.
    pub const ALL: [ChannelId; 6] = [
        ChannelId::SensorEvents,
        ChannelId::ArtifactResolution,
        ChannelId::ArtifactWrittenFiles,
        ChannelId::YaraMemoryScan,
        ChannelId::ActiveResponse,
        ChannelId::CaptureWriter,
    ];

    /// Stable identifier used in snapshots, log fields, and doctor output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelId::SensorEvents => "sensor_events",
            ChannelId::ArtifactResolution => "artifact_resolution",
            ChannelId::ArtifactWrittenFiles => "artifact_written_files",
            ChannelId::YaraMemoryScan => "yara_memory_scan",
            ChannelId::ActiveResponse => "active_response",
            ChannelId::CaptureWriter => "capture_writer",
        }
    }

    const fn index(self) -> usize {
        match self {
            ChannelId::SensorEvents => 0,
            ChannelId::ArtifactResolution => 1,
            ChannelId::ArtifactWrittenFiles => 2,
            ChannelId::YaraMemoryScan => 3,
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
///
/// Kept static on purpose (#662): `try_send` is called from sensor callbacks
/// and workers that hold no pipeline handle, and threading one through every
/// send site would cost more than it buys on the hot path.
static CHANNELS: [ChannelCounters; 6] = [
    ChannelCounters::new(ChannelId::SensorEvents),
    ChannelCounters::new(ChannelId::ArtifactResolution),
    ChannelCounters::new(ChannelId::ArtifactWrittenFiles),
    ChannelCounters::new(ChannelId::YaraMemoryScan),
    ChannelCounters::new(ChannelId::ActiveResponse),
    ChannelCounters::new(ChannelId::CaptureWriter),
];

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

/// Static for the same reason as [`CHANNELS`]: `try_send_sensor_event` is
/// called from sensor callbacks that hold no pipeline handle.
static SENSOR_EVENT_CATEGORIES: [SensorEventCategoryCounters; 14] = [
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
        EventCategory::PowerShellClassicStart => (12, "powershell_classic_start"),
        EventCategory::Defender => (13, "windefend"),
        EventCategory::Application => (13, "application"),
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
        EventCategory::PowerShellClassicStart,
        EventCategory::Defender,
        EventCategory::Application,
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
    /// Spaces the drop warning, built on the first drop.
    warnings: Mutex<Option<LogRateLimiter>>,
}

impl ChannelCounters {
    pub(crate) const fn new(id: ChannelId) -> Self {
        Self {
            warnings: Mutex::new(None),
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

        // A poisoned limiter must not silence the loss report.
        let decision = self
            .warnings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_or_insert_with(|| LogRateLimiter::new(DROP_WARN_INTERVAL))
            .should_emit(self.id.as_str());
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
    try_send_counted(channel.counters(), tx, value)
}

/// [`try_send`] against an explicit counter set, so tests can account a send
/// without touching the process-wide channel statics.
pub(crate) fn try_send_counted<T>(
    counters: &ChannelCounters,
    tx: &Sender<T>,
    value: T,
) -> Result<(), TrySendError<T>> {
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
    tx: &Sender<RawEvent>,
    value: RawEvent,
) -> Result<(), TrySendError<RawEvent>> {
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
    fn channel_identifiers_are_unique_and_indexed_consistently() {
        for (index, channel) in ChannelId::ALL.iter().enumerate() {
            assert_eq!(channel.index(), index, "{} is misindexed", channel.as_str());
            assert_eq!(channel.counters().id(), *channel);
        }
    }

    #[tokio::test]
    async fn accepted_sends_are_counted_with_queue_depth() {
        let counters = ChannelCounters::new(ChannelId::YaraMemoryScan);
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(4);

        for value in 0..3u8 {
            try_send_counted(&counters, &tx, value).expect("channel has room");
        }

        assert_eq!(counters.accepted(), 3);
        assert_eq!(counters.dropped(), 0);
        assert_eq!(counters.capacity(), 4);
        assert_eq!(counters.high_water_mark(), 3);
    }

    #[tokio::test]
    async fn a_full_channel_counts_drops_and_pins_the_high_water_mark() {
        let counters = ChannelCounters::new(ChannelId::ArtifactResolution);
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(2);

        try_send_counted(&counters, &tx, 1).expect("channel has room");
        try_send_counted(&counters, &tx, 2).expect("channel has room");
        for value in 3..8u8 {
            let err = try_send_counted(&counters, &tx, value).expect_err("channel is full");
            assert!(matches!(err, TrySendError::Full(_)));
        }

        assert_eq!(counters.accepted(), 2);
        assert_eq!(counters.dropped(), 5);
        assert_eq!(counters.dropped_closed(), 0);
        assert_eq!(counters.high_water_mark(), 2);
    }

    /// A dropped value has to come back to the caller intact: the sensors rely
    /// on it to fall back to a less-enriched send rather than lose the event.
    #[tokio::test]
    async fn a_dropped_value_is_returned_to_the_caller() {
        let counters = ChannelCounters::new(ChannelId::SensorEvents);
        let (tx, _rx) = tokio::sync::mpsc::channel::<String>(1);

        try_send_counted(&counters, &tx, "queued".to_string()).expect("channel has room");
        let err =
            try_send_counted(&counters, &tx, "shed".to_string()).expect_err("channel is full");

        match err {
            TrySendError::Full(value) => assert_eq!(value, "shed"),
            TrySendError::Closed(_) => panic!("channel is full, not closed"),
        }
    }

    /// Shutdown is not a detection gap, so a closed channel must not inflate
    /// the drop count an operator reads as lost telemetry.
    #[tokio::test]
    async fn a_closed_channel_is_counted_apart_from_load_shedding() {
        let counters = ChannelCounters::new(ChannelId::ActiveResponse);
        let (tx, rx) = tokio::sync::mpsc::channel::<u8>(4);
        drop(rx);

        let err = try_send_counted(&counters, &tx, 1).expect_err("channel is closed");
        assert!(matches!(err, TrySendError::Closed(_)));

        assert_eq!(counters.dropped(), 0);
        assert_eq!(counters.dropped_closed(), 1);
        assert_eq!(counters.accepted(), 0);
    }

    #[tokio::test]
    async fn channels_are_counted_independently() {
        let writer = ChannelCounters::new(ChannelId::CaptureWriter);
        let scan = ChannelCounters::new(ChannelId::YaraMemoryScan);
        let (full_tx, _full_rx) = tokio::sync::mpsc::channel::<u8>(1);
        let (open_tx, _open_rx) = tokio::sync::mpsc::channel::<u8>(4);

        try_send_counted(&writer, &full_tx, 1).expect("channel has room");
        let _ = try_send_counted(&writer, &full_tx, 2);
        try_send_counted(&scan, &open_tx, 3).expect("channel has room");

        assert_eq!(writer.dropped(), 1);
        assert_eq!(scan.dropped(), 0);
        assert_eq!(scan.accepted(), 1);
    }

    /// The warning is the only live signal while a channel is shedding, so
    /// both its rate limiting and its field names are part of the contract.
    #[tokio::test]
    async fn a_burst_of_drops_emits_one_cumulative_warning() {
        let counters = ChannelCounters::new(ChannelId::SensorEvents);
        let (tx, _rx) = tokio::sync::mpsc::channel::<u8>(1);
        let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        let collector = tracing_subscriber::fmt()
            .with_writer(CollectingWriter(Arc::clone(&lines)))
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(collector, || {
            // Another test thread can hit this callsite first with no
            // subscriber installed and cache "disabled" for it.
            tracing::callsite::rebuild_interest_cache();
            for value in 0..6u8 {
                let _ = try_send_counted(&counters, &tx, value);
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
