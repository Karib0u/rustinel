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
    fn a_snapshot_round_trips_through_the_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = snapshot_path(temp.path());
        let written = snapshot(vec![channel("sensor_events", 5, 2)]);

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
