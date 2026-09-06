//! Pipeline backpressure accounting, from a saturated channel through to the
//! numbers an operator reads in `rustinel doctor`.
//!
//! The counters are process-wide statics shared by every test in this binary,
//! so the assertions here are on deltas taken under a lock rather than on
//! absolute totals.

#[cfg(test)]
mod common;

use std::process::Command;
use std::sync::{Mutex, MutexGuard};

use common::process_start_event;
use rustinel::config::AppConfig;
use rustinel::runtime::telemetry::TelemetryReporter;
use rustinel::scanner::YaraEventHandler;
use rustinel::sensor::{Platform, SensorEventRouter};
use rustinel::telemetry::{snapshot_path, ChannelId, ChannelSnapshot, TelemetrySnapshot};

/// Serializes the tests that read the shared counters.
static COUNTERS: Mutex<()> = Mutex::new(());

fn counters_guard() -> MutexGuard<'static, ()> {
    COUNTERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Accepted and dropped totals for one channel.
fn totals(channel: ChannelId) -> (u64, u64) {
    let counters = channel.counters();
    (counters.accepted(), counters.dropped())
}

/// A YARA scan queue is bounded, so a burst of process starts beyond its
/// capacity is shed. Every shed event is a file that is never scanned, and the
/// count is the only way to know how many.
#[test]
fn a_saturated_scan_queue_counts_every_shed_event() {
    let _guard = counters_guard();
    let (accepted_before, dropped_before) = totals(ChannelId::YaraFileScan);

    let (tx, _rx) = tokio::sync::mpsc::channel::<(String, u32)>(2);
    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(YaraEventHandler {
        tx,
        memory_tx: None,
        allowlist_paths: Vec::new(),
    }));

    let event = process_start_event(Platform::Linux);
    for _ in 0..10 {
        router.route_event(&event);
    }

    let (accepted_after, dropped_after) = totals(ChannelId::YaraFileScan);
    assert_eq!(
        accepted_after - accepted_before,
        2,
        "only the channel's capacity should be accepted"
    );
    assert_eq!(
        dropped_after - dropped_before,
        8,
        "every event past capacity is a scan that never happens"
    );

    let counters = ChannelId::YaraFileScan.counters();
    assert_eq!(counters.capacity(), 2);
    assert!(counters.high_water_mark() >= 2, "the queue filled up");
}

/// Draining the queue lets sends succeed again, so the counters track load
/// rather than latching after the first drop.
#[test]
fn accepted_events_are_counted_after_the_queue_drains() {
    let _guard = counters_guard();
    let (accepted_before, dropped_before) = totals(ChannelId::YaraFileScan);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, u32)>(1);
    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(YaraEventHandler {
        tx,
        memory_tx: None,
        allowlist_paths: Vec::new(),
    }));

    let event = process_start_event(Platform::Linux);
    router.route_event(&event);
    router.route_event(&event);
    rx.try_recv().expect("the queued job is readable");
    router.route_event(&event);

    let (accepted_after, dropped_after) = totals(ChannelId::YaraFileScan);
    assert_eq!(accepted_after - accepted_before, 2);
    assert_eq!(dropped_after - dropped_before, 1);
}

fn write_config(root: &std::path::Path) -> std::path::PathBuf {
    let config_path = root.join("config.toml");
    std::fs::create_dir_all(root.join("logs")).expect("create logs dir");
    std::fs::write(
        &config_path,
        format!(
            "[logging]\nlevel = \"info\"\ndirectory = \"{logs}\"\nfilename = \"rustinel.log\"\n\
             \n[telemetry]\nenabled = true\nsnapshot_interval_secs = 30\n",
            logs = toml_path(&root.join("logs")),
        ),
    )
    .expect("write config");
    config_path
}

/// A Windows path is full of backslashes, and every one of them is an escape
/// inside a TOML basic string — an unescaped temp path makes the config
/// unparseable and the check under test never runs.
fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "\\\\")
}

fn run_doctor_json(config_path: &std::path::Path) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_rustinel"))
        .arg("doctor")
        .arg("--json")
        .arg("--config")
        .arg(config_path)
        .output()
        .expect("doctor runs");

    serde_json::from_slice(&output.stdout).expect("doctor emits JSON")
}

fn pipeline_check(report: &serde_json::Value) -> &serde_json::Value {
    report["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|result| result["id"] == "pipeline_telemetry")
        .expect("doctor reports a pipeline_telemetry check")
}

fn snapshot_with(channels: Vec<ChannelSnapshot>) -> TelemetrySnapshot {
    TelemetrySnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: 4242,
        captured_at: "2026-08-24T09:30:00Z".to_string(),
        uptime_secs: 7200,
        channels,
        sensor_events_by_category: Vec::new(),
        windows_process_command_line: None,
        registry: None,
        file_attribution: None,
        etw_decode: None,
    }
}

fn channel(name: &str, accepted: u64, dropped: u64) -> ChannelSnapshot {
    ChannelSnapshot {
        channel: name.to_string(),
        capacity: 8192,
        accepted,
        dropped,
        dropped_channel_closed: 0,
        high_water_mark: 8192,
    }
}

/// The acceptance criterion: an operator can quantify telemetry loss from
/// `rustinel doctor` alone, without searching the agent log.
#[test]
fn doctor_quantifies_dropped_telemetry_without_reading_logs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    snapshot_with(vec![
        channel("sensor_events", 400_000, 12_500),
        channel("ioc_hash", 900, 100),
    ])
    .write_to(&snapshot_path(&temp.path().join("logs")))
    .expect("write snapshot");

    let report = run_doctor_json(&config_path);
    let check = pipeline_check(&report);

    assert_eq!(check["status"], "warn");
    let message = check["message"].as_str().expect("message");
    assert!(
        message.contains("12600 events were dropped"),
        "doctor should total the loss: {message}"
    );
    let detail = check["detail"].as_str().expect("detail");
    assert!(detail.contains("sensor_events: 12500 dropped of 412500 offered"));
    assert!(detail.contains("ioc_hash: 100 dropped of 1000 offered"));

    // The per-channel numbers travel in the report itself, not only in prose.
    let channels = report["telemetry"]["channels"]
        .as_array()
        .expect("telemetry channels");
    let sensor_events = channels
        .iter()
        .find(|channel| channel["channel"] == "sensor_events")
        .expect("sensor_events channel");
    assert_eq!(sensor_events["dropped"], 12_500);
    assert_eq!(sensor_events["high_water_mark"], 8192);
}

/// A snapshot with no drops is a clean bill of health, not a silent absence.
#[test]
fn doctor_confirms_when_no_telemetry_was_lost() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    snapshot_with(vec![channel("sensor_events", 250_000, 0)])
        .write_to(&snapshot_path(&temp.path().join("logs")))
        .expect("write snapshot");

    let report = run_doctor_json(&config_path);
    let check = pipeline_check(&report);

    assert_eq!(check["status"], "pass");
    assert!(check["message"]
        .as_str()
        .expect("message")
        .contains("No telemetry dropped across 250000 events"));
}

/// An endpoint where the agent has never run must not look like a failure.
#[test]
fn doctor_is_quiet_before_the_agent_has_ever_run() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());

    let report = run_doctor_json(&config_path);
    let check = pipeline_check(&report);

    assert_eq!(check["status"], "pass");
    assert!(report["telemetry"].is_null(), "there is nothing to report");
}

/// The counters are only useful to `doctor` once they leave the process, so the
/// runtime has to actually publish them — on its interval while running, and
/// once more at shutdown so the last interval's drops are not lost with it.
#[tokio::test]
async fn the_runtime_publishes_counters_while_running_and_at_shutdown() {
    let temp = tempfile::tempdir().expect("tempdir");
    let logs_dir = temp.path().join("logs");
    let path = snapshot_path(&logs_dir);

    let mut cfg = AppConfig::default();
    cfg.logging.directory = logs_dir.clone();
    cfg.telemetry.snapshot_interval_secs = 1;

    let reporter = TelemetryReporter::start(&cfg).expect("telemetry is enabled by default");

    // The reporter creates the log directory itself, as it must on a fresh
    // portable install whose first run has not written a log yet.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !path.exists() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let periodic = TelemetrySnapshot::read_from(&path).expect("a snapshot was published");
    assert_eq!(periodic.channels.len(), ChannelId::ALL.len());

    reporter.finish().await;

    let shutdown = TelemetrySnapshot::read_from(&path).expect("a final snapshot was published");
    assert_eq!(shutdown.pid, std::process::id());
    assert!(
        shutdown.uptime_secs >= periodic.uptime_secs,
        "the shutdown snapshot must be the newer of the two"
    );
}

/// Turning persistence off must leave nothing behind for `doctor` to read as a
/// stale clean bill of health.
#[tokio::test]
async fn disabling_telemetry_publishes_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut cfg = AppConfig::default();
    cfg.logging.directory = temp.path().to_path_buf();
    cfg.telemetry.enabled = false;

    assert!(TelemetryReporter::start(&cfg).is_none());
    assert!(!snapshot_path(temp.path()).exists());
}
