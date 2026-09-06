//! Persisted view of the pipeline telemetry counters.
//!
//! The running agent and `rustinel doctor` are separate processes, so the
//! counters have to cross a process boundary to be useful. The runtime writes
//! a snapshot next to the logs on a fixed interval and once more at shutdown;
//! doctor reads the last one written. That makes the drop totals answerable
//! after the fact, including for an agent that has since stopped.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::{ChannelId, PROCESS_START, TARGET_TELEMETRY};
use crate::runtime::logging::TARGET_CONSOLE;
use crate::utils::fs::restrict_file_permissions;

/// File name of the snapshot, written inside the configured log directory.
pub const SNAPSHOT_FILE_NAME: &str = "telemetry.json";

/// Where the snapshot for `logs_dir` lives.
pub fn snapshot_path(logs_dir: &Path) -> PathBuf {
    logs_dir.join(SNAPSHOT_FILE_NAME)
}

/// Counters for one bounded channel at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSnapshot {
    pub channel: String,
    /// Configured channel capacity; 0 until the channel is first used.
    pub capacity: usize,
    /// Items the channel accepted.
    pub accepted: u64,
    /// Items shed because the channel was full — the detection gap.
    pub dropped: u64,
    /// Items dropped because the consumer had already stopped, which is
    /// shutdown rather than telemetry loss.
    pub dropped_channel_closed: u64,
    /// Deepest queue depth observed.
    pub high_water_mark: usize,
}

impl ChannelSnapshot {
    /// Whether the channel was ever used. Unused channels are the norm —
    /// YARA memory scanning is opt-in, capture only runs under `rustinel
    /// capture` — so reporting suppresses them rather than printing zeros.
    pub fn is_idle(&self) -> bool {
        self.accepted == 0 && self.dropped == 0 && self.dropped_channel_closed == 0
    }

    /// Share of offered items that were shed, as a percentage.
    pub fn drop_rate_pct(&self) -> f64 {
        let offered = self.accepted.saturating_add(self.dropped);
        if offered == 0 {
            return 0.0;
        }
        (self.dropped as f64 / offered as f64) * 100.0
    }

    /// One-line operator summary of this channel.
    pub fn describe(&self) -> String {
        format!(
            "{}: {} dropped of {} offered ({:.2}%), peak depth {}/{}",
            self.channel,
            self.dropped,
            self.accepted.saturating_add(self.dropped),
            self.drop_rate_pct(),
            self.high_water_mark,
            self.capacity
        )
    }
}

/// Registry key-path resolution at a point in time.
///
/// Windows only, and absent from the snapshot on other platforms and before
/// the registry sensor has started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    /// Whether the Windows sensor attempted its startup key rundown.
    #[serde(default)]
    pub rundown_attempted: bool,
    /// Registry write events the sensor decoded.
    pub events_received: u64,
    /// Those that reached the detectors with a key path.
    pub events_resolved: u64,
    /// Those dropped because their `KeyObject` matched no known path.
    pub events_unresolved: u64,
    /// Resolved only because the startup handle-table snapshot knew the key:
    /// writes through a handle older than the trace session, which were
    /// dropped outright before #341.
    pub resolved_from_snapshot: u64,
    /// Resolved only because the key's `CloseKey` was decoded before the write
    /// itself for a key that is opened, written and closed in one burst.
    pub resolved_after_close: u64,
    /// `CreateKey` events that contributed a name.
    pub naming_create: u64,
    /// `OpenKey` events that contributed a name.
    pub naming_open: u64,
    /// Naming events skipped because the open failed and named nothing.
    pub naming_failed: u64,
    /// Keys covered by the startup handle-table snapshot.
    pub snapshot_keys: usize,
}

/// Windows Kernel-File path attribution at a point in time.
///
/// Windows only, and absent from the snapshot on other platforms and before a
/// file event has been decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAttributionSnapshot {
    /// File events that needed a target path.
    pub attempted: u64,
    /// Those the event named itself, without consulting the pointer index.
    pub resolved_from_event: u64,
    /// Those the `FileObject`/`FileKey` index resolved.
    pub resolved_from_index: u64,
    /// Those dropped because neither identifier resolved to a path.
    pub unresolved: u64,
    /// Index entries evicted because a handle was held past the per-index cap.
    /// Not itself a gap - the evicted handle may never be written to again -
    /// but it is the mechanism that produces one, so it is reported apart.
    pub index_capacity_evictions: u64,
}

impl FileAttributionSnapshot {
    /// File events that reached the detectors with a path.
    pub fn resolved(&self) -> u64 {
        self.resolved_from_event
            .saturating_add(self.resolved_from_index)
    }

    /// Share of file events that reached the detectors with a path.
    pub fn resolution_rate_pct(&self) -> f64 {
        let seen = self.resolved().saturating_add(self.unresolved);
        if seen == 0 {
            return 100.0;
        }
        (self.resolved() as f64 / seen as f64) * 100.0
    }

    /// One-line operator summary.
    pub fn describe(&self) -> String {
        format!(
            "file paths: {} of {} events resolved ({:.2}%), {} from the handle index, {} index entries evicted at capacity",
            self.resolved(),
            self.resolved().saturating_add(self.unresolved),
            self.resolution_rate_pct(),
            self.resolved_from_index,
            self.index_capacity_evictions,
        )
    }
}

/// Linux network-event local-address attribution at a point in time.
///
/// Linux only, and absent from the snapshot on other platforms and before a
/// network event has been attributed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketLookupSnapshot {
    /// Network events that needed a local address, transport, or both.
    pub attempted: u64,
    /// Those the socket snapshot answered for the peer the probe saw.
    pub resolved: u64,
    /// Those whose snapshot entry described a different peer, i.e. the
    /// descriptor was recycled between the syscall and the drain.
    pub mismatched: u64,
    /// Those no snapshot listed at all.
    pub unresolved: u64,
    /// Passes over `/proc/net/{tcp,tcp6,udp,udp6}` paid for the above. Bounded
    /// by the inventory's refresh floor rather than by the event rate.
    pub table_scans: u64,
}

impl SocketLookupSnapshot {
    /// Share of network events whose local address was measured.
    pub fn resolution_rate_pct(&self) -> f64 {
        if self.attempted == 0 {
            return 100.0;
        }
        (self.resolved as f64 / self.attempted as f64) * 100.0
    }

    /// Table scans per thousand attributed events. The ratio the per-event
    /// scan pinned at 1000 and the inventory exists to drive down.
    pub fn scans_per_thousand(&self) -> f64 {
        if self.attempted == 0 {
            return 0.0;
        }
        (self.table_scans as f64 / self.attempted as f64) * 1000.0
    }

    /// One-line operator summary.
    pub fn describe(&self) -> String {
        format!(
            "socket lookups: {} of {} events resolved ({:.2}%), {} peer mismatches, {} table scans ({:.2} per 1000 events)",
            self.resolved,
            self.attempted,
            self.resolution_rate_pct(),
            self.mismatched,
            self.table_scans,
            self.scans_per_thousand(),
        )
    }
}

/// One decode failure key and how often it fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtwDecodeFailureSnapshot {
    /// Provider name from the subscription table, never a rendered GUID.
    pub provider: String,
    pub event_id: u16,
    /// Event template version from the record header. A version this build has
    /// no template for is the usual cause of `unsupported_layout`.
    pub version: u8,
    /// `schema`, `unsupported_layout`, or `fieldless`.
    pub failure: String,
    pub count: u64,
}

/// Windows ETW decoder accounting at a point in time.
///
/// Windows only, and absent from the snapshot on other platforms and before
/// the ETW sensor has decoded a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtwDecodeSnapshot {
    /// Records delivered to the ETW callback.
    pub records_received: u64,
    /// Records the router intentionally declined. Not loss.
    pub records_filtered: u64,
    /// Records that maintained a path index or were held for a naming event.
    pub records_indexed: u64,
    /// Records that produced at least one sensor event.
    pub records_decoded: u64,
    /// Records dropped for want of a resolvable path.
    pub records_unattributed: u64,
    /// Records whose provider schema could not be located.
    pub schema_errors: u64,
    /// Records missing a property their payload requires.
    pub unsupported_layouts: u64,
    /// Payloads built with no field a rule could select on.
    pub fieldless_payloads: u64,
    /// Sensor events offered to the queue. Exceeds `records_decoded` whenever
    /// a naming event replays writes that were waiting on it.
    pub events_emitted: u64,
    /// Failures by bounded provider/event/version key, worst first.
    #[serde(default)]
    pub failures: Vec<EtwDecodeFailureSnapshot>,
    /// Failures that arrived after the key table was full, so they are counted
    /// in the totals but attributed to no key.
    #[serde(default)]
    pub unkeyed_failures: u64,
}

impl EtwDecodeSnapshot {
    /// Records that failed to decode, across all three failure modes.
    pub fn failed(&self) -> u64 {
        self.schema_errors
            .saturating_add(self.unsupported_layouts)
            .saturating_add(self.fieldless_payloads)
    }

    /// Share of received records that failed to decode.
    pub fn failure_rate_pct(&self) -> f64 {
        if self.records_received == 0 {
            return 0.0;
        }
        (self.failed() as f64 / self.records_received as f64) * 100.0
    }

    /// Whether every received record is accounted for by exactly one outcome.
    ///
    /// The counters are incremented independently on a hot path, so a snapshot
    /// taken mid-record can be off by one; a persistent mismatch means an
    /// outcome the decoder does not classify, which is the state this whole
    /// section exists to make impossible.
    pub fn is_reconciled(&self) -> bool {
        self.classified() == self.records_received
    }

    /// Records attributed to an outcome.
    pub fn classified(&self) -> u64 {
        [
            self.records_filtered,
            self.records_indexed,
            self.records_decoded,
            self.records_unattributed,
            self.schema_errors,
            self.unsupported_layouts,
            self.fieldless_payloads,
        ]
        .into_iter()
        .fold(0u64, u64::saturating_add)
    }

    /// One-line operator summary.
    pub fn describe(&self) -> String {
        let worst = self
            .failures
            .first()
            .map(|failure| {
                format!(
                    ", worst {} event {} v{} {} x{}",
                    failure.provider,
                    failure.event_id,
                    failure.version,
                    failure.failure,
                    failure.count
                )
            })
            .unwrap_or_default();
        format!(
            "etw decode: {} records received, {} decoded into {} events, {} filtered, {} indexed, {} unattributed, {} failed ({:.4}%){}",
            self.records_received,
            self.records_decoded,
            self.events_emitted,
            self.records_filtered,
            self.records_indexed,
            self.records_unattributed,
            self.failed(),
            self.failure_rate_pct(),
            worst,
        )
    }
}

/// Sensor queue traffic for one normalized event category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorEventCategorySnapshot {
    pub category: String,
    pub accepted: u64,
    pub dropped: u64,
}

/// Fidelity of the best-effort Windows process command-line back-fill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCommandLineSnapshot {
    pub attempted: u64,
    pub captured: u64,
    pub missed: u64,
}

impl ProcessCommandLineSnapshot {
    pub fn capture_rate_pct(&self) -> f64 {
        if self.attempted == 0 {
            return 100.0;
        }
        (self.captured as f64 / self.attempted as f64) * 100.0
    }
}

impl RegistrySnapshot {
    /// Share of registry write events that reached the detectors with a path.
    ///
    /// This is the number the #341 follow-up hangs on: below 99.9% and the
    /// classic kernel provider's KCB rundown is worth a second trace session.
    pub fn resolution_rate_pct(&self) -> f64 {
        let seen = self.events_resolved.saturating_add(self.events_unresolved);
        if seen == 0 {
            return 100.0;
        }
        (self.events_resolved as f64 / seen as f64) * 100.0
    }

    /// One-line operator summary.
    pub fn describe(&self) -> String {
        format!(
            "registry: {} of {} events resolved ({:.2}%), {} rescued by the startup snapshot of {} keys, {} by the close grace",
            self.events_resolved,
            self.events_resolved.saturating_add(self.events_unresolved),
            self.resolution_rate_pct(),
            self.resolved_from_snapshot,
            self.snapshot_keys,
            self.resolved_after_close,
        )
    }
}

/// Every channel's counters, plus enough context to know how old they are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Agent version that produced the snapshot.
    pub version: String,
    /// PID of the agent that produced it, to spot a snapshot from a prior run.
    pub pid: u32,
    /// RFC 3339 timestamp of the snapshot.
    pub captured_at: String,
    /// How long that agent had been running.
    pub uptime_secs: u64,
    pub channels: Vec<ChannelSnapshot>,
    /// Sensor ingress volume and loss split by event category.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensor_events_by_category: Vec<SensorEventCategorySnapshot>,
    /// Final command-line availability for accepted Windows process starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_process_command_line: Option<ProcessCommandLineSnapshot>,
    /// Registry key-path resolution. Absent on platforms without the ETW
    /// registry sensor, and on snapshots written before #341.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistrySnapshot>,
    /// Kernel-File path attribution. Absent on platforms without the ETW file
    /// sensor, and on snapshots written before #394.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_attribution: Option<FileAttributionSnapshot>,
    /// ETW decoder outcomes. Absent on platforms without the ETW sensor, and
    /// on snapshots written before #394.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etw_decode: Option<EtwDecodeSnapshot>,
    /// Linux network local-address attribution and its procfs scan cost.
    /// Absent on platforms without the eBPF sensor, and on snapshots written
    /// before #375.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_lookup: Option<SocketLookupSnapshot>,
}

impl TelemetrySnapshot {
    /// Read the live counters.
    pub fn capture() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            captured_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            uptime_secs: PROCESS_START.elapsed().as_secs(),
            channels: ChannelId::ALL
                .iter()
                .map(|channel| channel.counters().snapshot())
                .collect(),
            sensor_events_by_category: super::sensor_event_category_snapshots(),
            windows_process_command_line: super::WINDOWS_PROCESS_COMMAND_LINE.snapshot(),
            registry: super::REGISTRY.snapshot(),
            file_attribution: super::WINDOWS_FILE_ATTRIBUTION.snapshot(),
            etw_decode: super::ETW_DECODE.snapshot(),
            socket_lookup: super::LINUX_SOCKET_LOOKUP.snapshot(),
        }
    }

    /// Total items shed across every channel.
    pub fn total_dropped(&self) -> u64 {
        self.channels
            .iter()
            .map(|channel| channel.dropped)
            .fold(0u64, u64::saturating_add)
    }

    /// Total items accepted across every channel.
    pub fn total_accepted(&self) -> u64 {
        self.channels
            .iter()
            .map(|channel| channel.accepted)
            .fold(0u64, u64::saturating_add)
    }

    /// Channels that shed at least one item, worst first.
    pub fn dropping_channels(&self) -> Vec<&ChannelSnapshot> {
        let mut dropping: Vec<&ChannelSnapshot> = self
            .channels
            .iter()
            .filter(|channel| channel.dropped > 0)
            .collect();
        dropping.sort_by_key(|channel| std::cmp::Reverse(channel.dropped));
        dropping
    }

    /// Channels that saw traffic, in declaration order.
    pub fn active_channels(&self) -> Vec<&ChannelSnapshot> {
        self.channels
            .iter()
            .filter(|channel| !channel.is_idle())
            .collect()
    }

    /// Write the snapshot to `path`, replacing any previous one.
    ///
    /// Written to a sibling temporary file and renamed, so a reader never sees
    /// a half-written snapshot and a crash mid-write cannot leave a truncated
    /// file that parses as "no drops".
    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temporary = path.with_extension("json.tmp");
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        fs::write(&temporary, encoded)?;
        // Best-effort: the snapshot holds no endpoint detail, only counts.
        let _ = restrict_file_permissions(&temporary);
        fs::rename(&temporary, path)
    }

    /// Read a snapshot previously written by a running agent.
    ///
    /// A missing or unreadable snapshot is not an error: the agent may never
    /// have run, or may be running as a user whose files this process cannot
    /// read.
    pub fn read_from(path: &Path) -> Option<Self> {
        let bytes = fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// Periodically publish the pipeline counters for `rustinel doctor`.
///
/// Publishing only writes the snapshot: drops already warn as they happen, so
/// logging the same numbers every interval would add noise to the log this is
/// meant to save an operator from reading.
///
/// The returned task runs until it is aborted; the runtime writes one final
/// snapshot on shutdown so the last interval's drops are not lost with it.
pub fn spawn_reporter(path: PathBuf, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Never busy-loop, however the interval was configured.
        let interval = interval.max(Duration::from_secs(1));
        info!(
            target: TARGET_TELEMETRY,
            path = %path.display(),
            interval_secs = interval.as_secs(),
            "Publishing pipeline channel counters"
        );

        loop {
            tokio::time::sleep(interval).await;
            persist(&TelemetrySnapshot::capture(), &path);
        }
    })
}

/// Log and publish the counters one last time, at shutdown.
///
/// The summary goes to the log here — and only here — so the totals survive
/// even if the snapshot cannot be written.
pub fn write_final_snapshot(path: &Path) {
    let snapshot = TelemetrySnapshot::capture();
    let active_channels = snapshot.active_channels();

    if !active_channels.is_empty() {
        info!(
            target: TARGET_CONSOLE,
            channels = active_channels.len(),
            accepted = snapshot.total_accepted(),
            dropped = snapshot.total_dropped(),
            "Pipeline summary"
        );
    }

    for channel in active_channels {
        info!(
            target: TARGET_TELEMETRY,
            channel = %channel.channel,
            capacity = channel.capacity,
            accepted = channel.accepted,
            dropped = channel.dropped,
            high_water_mark = channel.high_water_mark,
            "Pipeline channel statistics"
        );
    }

    persist(&snapshot, path);
}

fn persist(snapshot: &TelemetrySnapshot, path: &Path) {
    match snapshot.write_to(path) {
        Ok(()) => debug!(
            target: TARGET_TELEMETRY,
            path = %path.display(),
            "Wrote pipeline telemetry snapshot"
        ),
        Err(err) => warn!(
            target: TARGET_TELEMETRY,
            path = %path.display(),
            error = %err,
            "Failed to write pipeline telemetry snapshot; drop counters remain visible in logs only"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(name: &str, accepted: u64, dropped: u64) -> ChannelSnapshot {
        ChannelSnapshot {
            channel: name.to_string(),
            capacity: 100,
            accepted,
            dropped,
            dropped_channel_closed: 0,
            high_water_mark: 100,
        }
    }

    fn snapshot(channels: Vec<ChannelSnapshot>) -> TelemetrySnapshot {
        TelemetrySnapshot {
            version: "1.3.0".to_string(),
            pid: 42,
            captured_at: "2026-08-24T00:00:00Z".to_string(),
            uptime_secs: 60,
            channels,
            sensor_events_by_category: Vec::new(),
            windows_process_command_line: None,
            registry: None,
            file_attribution: None,
            etw_decode: None,
            socket_lookup: None,
        }
    }

    #[test]
    fn capture_reports_every_channel() {
        let snapshot = TelemetrySnapshot::capture();

        assert_eq!(snapshot.channels.len(), ChannelId::ALL.len());
        for (channel, expected) in snapshot.channels.iter().zip(ChannelId::ALL) {
            assert_eq!(channel.channel, expected.as_str());
        }
    }

    #[test]
    fn dropping_channels_are_ranked_worst_first() {
        let snapshot = snapshot(vec![
            channel("yara_file_scan", 10, 5),
            channel("sensor_events", 1000, 900),
            channel("ioc_hash", 10, 0),
        ]);

        let dropping: Vec<&str> = snapshot
            .dropping_channels()
            .iter()
            .map(|channel| channel.channel.as_str())
            .collect();

        assert_eq!(dropping, vec!["sensor_events", "yara_file_scan"]);
        assert_eq!(snapshot.total_dropped(), 905);
        assert_eq!(snapshot.total_accepted(), 1020);
    }

    #[test]
    fn drop_rate_is_a_share_of_offered_items() {
        let channel = channel("sensor_events", 750, 250);

        assert!((channel.drop_rate_pct() - 25.0).abs() < f64::EPSILON);
        assert!(channel.describe().contains("250 dropped of 1000 offered"));
    }

    #[test]
    fn an_unused_channel_reports_no_drop_rate() {
        let idle = channel("capture_writer", 0, 0);

        assert!(idle.is_idle());
        assert_eq!(idle.drop_rate_pct(), 0.0);
    }

    #[test]
    fn process_command_line_capture_rate_uses_all_attempts() {
        let fidelity = ProcessCommandLineSnapshot {
            attempted: 4,
            captured: 3,
            missed: 1,
        };

        assert_eq!(fidelity.capture_rate_pct(), 75.0);
    }

    fn file_attribution(resolved_from_index: u64, unresolved: u64) -> FileAttributionSnapshot {
        FileAttributionSnapshot {
            attempted: resolved_from_index + unresolved + 10,
            resolved_from_event: 10,
            resolved_from_index,
            unresolved,
            index_capacity_evictions: 4,
        }
    }

    #[test]
    fn file_resolution_rate_counts_both_resolved_tiers() {
        let files = file_attribution(80, 10);

        assert_eq!(files.resolved(), 90);
        assert_eq!(files.resolution_rate_pct(), 90.0);
        assert!(files
            .describe()
            .contains("90 of 100 events resolved (90.00%)"));
        assert!(files.describe().contains("4 index entries evicted"));
    }

    /// An idle file sensor must read as "nothing to attribute", not as a gap.
    #[test]
    fn a_file_sensor_that_saw_nothing_reports_full_resolution() {
        let idle = FileAttributionSnapshot {
            attempted: 0,
            resolved_from_event: 0,
            resolved_from_index: 0,
            unresolved: 0,
            index_capacity_evictions: 0,
        };

        assert_eq!(idle.resolution_rate_pct(), 100.0);
    }

    /// Intentional filtering is the bulk of ETW traffic, so it must not count
    /// against the decoder the way a schema failure does.
    #[test]
    fn filtered_records_do_not_inflate_the_decode_failure_rate() {
        let decode = EtwDecodeSnapshot {
            records_received: 1_000,
            records_filtered: 800,
            records_indexed: 100,
            records_decoded: 90,
            records_unattributed: 5,
            schema_errors: 3,
            unsupported_layouts: 1,
            fieldless_payloads: 1,
            events_emitted: 120,
            failures: Vec::new(),
            unkeyed_failures: 0,
        };

        assert_eq!(decode.failed(), 5);
        assert!((decode.failure_rate_pct() - 0.5).abs() < f64::EPSILON);
        assert!(decode.is_reconciled());
        assert!(decode.describe().contains("800 filtered"));
    }

    /// A decoder path that reports no outcome is exactly the hidden
    /// degradation this section exists to surface, so the mismatch is visible
    /// in the snapshot rather than needing to be derived by hand.
    #[test]
    fn an_unclassified_record_fails_reconciliation() {
        let decode = EtwDecodeSnapshot {
            records_received: 10,
            records_filtered: 4,
            records_indexed: 0,
            records_decoded: 5,
            records_unattributed: 0,
            schema_errors: 0,
            unsupported_layouts: 0,
            fieldless_payloads: 0,
            events_emitted: 5,
            failures: Vec::new(),
            unkeyed_failures: 0,
        };

        assert_eq!(decode.classified(), 9);
        assert!(!decode.is_reconciled());
    }

    #[test]
    fn a_snapshot_round_trips_through_the_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = snapshot_path(temp.path());
        let mut written = snapshot(vec![channel("sensor_events", 5, 2)]);
        written.file_attribution = Some(file_attribution(80, 10));
        written.etw_decode = Some(EtwDecodeSnapshot {
            records_received: 10,
            records_filtered: 4,
            records_indexed: 1,
            records_decoded: 3,
            records_unattributed: 1,
            schema_errors: 1,
            unsupported_layouts: 0,
            fieldless_payloads: 0,
            events_emitted: 5,
            failures: vec![EtwDecodeFailureSnapshot {
                provider: "Microsoft-Windows-DNS-Client".to_string(),
                event_id: 3020,
                version: 0,
                failure: "schema".to_string(),
                count: 1,
            }],
            unkeyed_failures: 0,
        });

        written.write_to(&path).expect("write snapshot");
        let read = TelemetrySnapshot::read_from(&path).expect("read snapshot");

        assert_eq!(read, written);
        assert_eq!(path.file_name().unwrap(), SNAPSHOT_FILE_NAME);
    }

    /// The rename leaves nothing behind, so repeated writes cannot accumulate
    /// stale temporary files in the log directory.
    #[test]
    fn writing_a_snapshot_leaves_no_temporary_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = snapshot_path(temp.path());

        snapshot(vec![]).write_to(&path).expect("first write");
        snapshot(vec![channel("ioc_hash", 1, 0)])
            .write_to(&path)
            .expect("second write");

        let entries: Vec<String> = fs::read_dir(temp.path())
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        assert_eq!(entries, vec![SNAPSHOT_FILE_NAME.to_string()]);
    }

    #[test]
    fn a_missing_or_corrupt_snapshot_reads_as_none() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = snapshot_path(temp.path());

        assert!(TelemetrySnapshot::read_from(&path).is_none());

        fs::write(&path, b"{ not json").expect("write garbage");
        assert!(TelemetrySnapshot::read_from(&path).is_none());
    }

    /// The snapshot is created if the log directory does not exist yet, which
    /// is the state of a fresh portable install on its first run.
    #[test]
    fn writing_creates_the_log_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let logs_dir = temp.path().join("logs");
        let path = snapshot_path(&logs_dir);

        snapshot(vec![]).write_to(&path).expect("write snapshot");

        assert!(path.exists());
    }
}
