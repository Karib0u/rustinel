//! Agent heartbeat and start/stop alerts.
//!
//! When the agent stops, the alert stream just ends. These give a SIEM
//! something regular to miss (the heartbeat) and say why a run ended
//! (`stopping`) or that it never got to say (`unclean_shutdown`).
//!
//! Everything here is written straight to the alert sink or to its own file,
//! so it bypasses deduplication, active response, and the `sensor_events`
//! queue.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use tracing_appender::non_blocking::WorkerGuard;

use crate::alerts::{AlertSink, AlertWriterMetrics};
use crate::config::AppConfig;
use crate::identity::Identity;
use crate::models::ecs::{AgentLifecycle, EcsAlert, LifecycleKind};
use crate::runtime::logging::open_daily_appender;
use crate::runtime::telemetry::host_platform;
use crate::telemetry::{snapshot_path, PipelineProbes, TelemetrySnapshot, HEARTBEAT_FILE_NAME};
use crate::vocab::Platform;

/// Records whether the last run reached the end of its shutdown.
const RUN_STATE_FILE_NAME: &str = "run-state";
/// `running <pid>` while a run is in progress.
const STATE_RUNNING: &str = "running";
const STATE_STOPPED: &str = "stopped";

/// Why the agent is stopping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// SIGINT, SIGTERM, SIGHUP, or Ctrl+C.
    Signal,
    /// The Windows service manager asked the service to stop.
    ServiceStop,
    /// A sensor or critical worker failed.
    SensorFailure,
}

impl StopReason {
    pub fn from_signal(signal: &str) -> Self {
        if signal == "service stop" {
            Self::ServiceStop
        } else {
            Self::Signal
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signal => "signal",
            Self::ServiceStop => "service_stop",
            Self::SensorFailure => "sensor_failure",
        }
    }
}

/// One heartbeat line: identity and just enough to tell a live agent from a
/// struggling one. The full counters stay in `telemetry.json`.
#[derive(Serialize)]
struct HeartbeatLine<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    #[serde(rename = "event.dataset")]
    dataset: &'static str,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    identity: Option<&'a Identity>,
    uptime_secs: u64,
    /// Items shed by every bounded queue since the agent started.
    dropped_total: u64,
}

fn heartbeat_line(identity: Option<&Identity>, snapshot: &TelemetrySnapshot) -> Option<String> {
    let line = HeartbeatLine {
        timestamp: now(),
        dataset: "edr.agent.heartbeat",
        identity,
        uptime_secs: snapshot.uptime_secs,
        dropped_total: snapshot.total_dropped(),
    };
    serde_json::to_string(&line).ok()
}

struct Heartbeat {
    handle: JoinHandle<()>,
    _guard: WorkerGuard,
}

/// Owns the heartbeat task and the run-state marker.
pub struct Lifecycle {
    alert_sink: AlertSink,
    platform: Platform,
    marker: Option<PathBuf>,
    heartbeat: Option<Heartbeat>,
}

impl Lifecycle {
    /// Report an unclean previous run, mark this one as running, and start the
    /// heartbeat. Call before the telemetry reporter overwrites the snapshot.
    pub fn start(
        cfg: &AppConfig,
        alert_sink: &AlertSink,
        identity: Arc<Identity>,
        alert_writer: AlertWriterMetrics,
        probes: PipelineProbes,
    ) -> Self {
        let platform = host_platform();
        let marker = cfg.agent.directory.join(RUN_STATE_FILE_NAME);

        let previous = read_state(&marker);
        let other_instance = previous
            .as_deref()
            .and_then(running_pid)
            .is_some_and(|pid| pid != std::process::id() && process_alive(pid));
        let marker = if other_instance {
            // Another agent owns the marker (a console run beside the service,
            // for example). Reporting or rewriting it would be wrong either way.
            info!("Another agent instance is running; this run does not track its stop");
            None
        } else {
            if previous.as_deref().and_then(running_pid).is_some() {
                let last_snapshot_at =
                    TelemetrySnapshot::read_from(&snapshot_path(&cfg.logging.directory))
                        .map(|snapshot| snapshot.captured_at);
                warn!(
                    last_snapshot_at = last_snapshot_at.as_deref(),
                    "The previous run did not stop cleanly"
                );
                alert_sink.write_ecs(&EcsAlert::agent_lifecycle(
                    platform,
                    now(),
                    AgentLifecycle {
                        kind: LifecycleKind::UncleanShutdown,
                        reason: "no_clean_stop_marker",
                        last_snapshot_at,
                    },
                ));
            }
            match write_state(&marker, &format!("{STATE_RUNNING} {}", std::process::id())) {
                Ok(()) => Some(marker),
                Err(err) => {
                    warn!(
                        path = %marker.display(),
                        error = %err,
                        "Cannot record the run state; an unclean shutdown will not be reported next start"
                    );
                    None
                }
            }
        };

        let heartbeat = start_heartbeat(cfg, alert_sink, identity, alert_writer, probes);

        Self {
            alert_sink: alert_sink.clone(),
            platform,
            marker,
            heartbeat,
        }
    }

    /// A lifecycle that does nothing, for tests.
    #[cfg(test)]
    pub fn disabled(alert_sink: &AlertSink) -> Self {
        Self {
            alert_sink: alert_sink.clone(),
            platform: host_platform(),
            marker: None,
            heartbeat: None,
        }
    }

    /// Write the `stopping` alert. Call after the sensors have drained and
    /// before the sink closes.
    pub fn stopping(&self, reason: StopReason) {
        write_stopping(&self.alert_sink, self.platform, reason);
    }

    /// Record that this run ended and said why, so the next start does not
    /// report it again. Used by the exits that skip the drain: their
    /// `stopping` alert is the report.
    pub fn mark_stopped(&self) {
        if let Some(marker) = &self.marker {
            if let Err(err) = write_state(marker, STATE_STOPPED) {
                warn!(path = %marker.display(), error = %err, "Cannot record the stop");
            }
        }
    }

    /// Stop the heartbeat and record a clean stop. The last thing shutdown does.
    pub async fn finish(self) {
        if let Some(heartbeat) = &self.heartbeat {
            heartbeat.handle.abort();
        }
        if let Some(heartbeat) = self.heartbeat {
            let _ = heartbeat.handle.await;
        }
        if let Some(marker) = &self.marker {
            if let Err(err) = write_state(marker, STATE_STOPPED) {
                warn!(path = %marker.display(), error = %err, "Cannot record the clean stop");
            }
        }
    }
}

/// The `stopping` alert for a path that exits without draining.
pub fn write_stopping(alert_sink: &AlertSink, platform: Platform, reason: StopReason) {
    alert_sink.write_ecs(&EcsAlert::agent_lifecycle(
        platform,
        now(),
        AgentLifecycle {
            kind: LifecycleKind::Stopping,
            reason: reason.as_str(),
            last_snapshot_at: None,
        },
    ));
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn start_heartbeat(
    cfg: &AppConfig,
    alert_sink: &AlertSink,
    identity: Arc<Identity>,
    alert_writer: AlertWriterMetrics,
    probes: PipelineProbes,
) -> Option<Heartbeat> {
    let appender = match open_daily_appender(
        "heartbeat",
        &cfg.logging.directory,
        HEARTBEAT_FILE_NAME,
        cfg.security.log_group(),
    ) {
        Ok(appender) => appender,
        Err(err) => {
            warn!(error = %format!("{err:#}"), "Heartbeat unavailable");
            return None;
        }
    };
    // Its own writer thread: the heartbeat never waits behind alert output.
    let (mut writer, guard) = tracing_appender::non_blocking(appender);
    let interval =
        Duration::from_secs(cfg.telemetry.snapshot_interval_secs).max(Duration::from_secs(1));
    let webhooks = cfg
        .heartbeat
        .webhooks
        .then(|| alert_sink.webhooks().cloned())
        .flatten();

    info!(
        interval_secs = interval.as_secs(),
        webhooks = webhooks.is_some(),
        "Writing heartbeat"
    );
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // The first tick is immediate, so a start is visible at once.
            ticker.tick().await;
            let snapshot = TelemetrySnapshot::capture_with_alert_writer(&alert_writer, &probes);
            let Some(mut line) = heartbeat_line(Some(&identity), &snapshot) else {
                continue;
            };
            if let Some(webhooks) = &webhooks {
                webhooks.dispatch(line.as_bytes());
            }
            line.push('\n');
            if let Err(err) = writer.write_all(line.as_bytes()) {
                debug!(error = %err, "Failed to write heartbeat");
            }
        }
    });
    Some(Heartbeat {
        handle,
        _guard: guard,
    })
}

/// The pid in a `running <pid>` marker. A bare `running` yields pid 0.
fn running_pid(state: &str) -> Option<u32> {
    let rest = state.strip_prefix(STATE_RUNNING)?;
    Some(rest.trim().parse().unwrap_or(0))
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 only checks that the process exists.
    let found = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
    found || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const STILL_ACTIVE: u32 = 259;
    if pid == 0 {
        return false;
    }
    // SAFETY: the handle is opened, queried and closed within this block.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut code = 0u32;
        let alive = GetExitCodeProcess(handle, &mut code).is_ok() && code == STILL_ACTIVE;
        let _ = CloseHandle(handle);
        alive
    }
}

fn read_state(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|state| state.trim().to_string())
}

fn write_state(path: &Path, state: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{state}\n"))?;
    let _ = crate::utils::fs::restrict_file_permissions(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn alerts_written(f: impl FnOnce(&AlertSink)) -> Vec<serde_json::Value> {
        let output = SharedWriter(Arc::new(Mutex::new(Vec::new())));
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .finish(output.clone());
        let sink = AlertSink::new(writer);
        f(&sink);
        drop(sink);
        drop(guard);
        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn stop_reasons_map_from_the_shutdown_signal() {
        assert_eq!(
            StopReason::from_signal("service stop"),
            StopReason::ServiceStop
        );
        assert_eq!(StopReason::from_signal("SIGTERM"), StopReason::Signal);
        assert_eq!(StopReason::from_signal("Ctrl+C"), StopReason::Signal);
    }

    #[test]
    fn stopping_alert_carries_reason_and_severity() {
        let alerts = alerts_written(|sink| {
            write_stopping(sink, Platform::Linux, StopReason::Signal);
            write_stopping(sink, Platform::Linux, StopReason::SensorFailure);
        });
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0]["rule.name"], "agent::lifecycle::stopping");
        assert_eq!(alerts[0]["edr.rule.engine"], "Agent");
        assert_eq!(alerts[0]["event.dataset"], "edr.agent");
        assert_eq!(alerts[0]["edr.agent.lifecycle.reason"], "signal");
        assert_eq!(alerts[0]["edr.rule.severity"], "Low");
        assert_eq!(alerts[1]["edr.agent.lifecycle.reason"], "sensor_failure");
        assert_eq!(alerts[1]["edr.rule.severity"], "High");
    }

    #[tokio::test]
    async fn unclean_shutdown_is_reported_only_when_the_marker_says_running() {
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = AppConfig::default();
        cfg.agent.directory = temp.path().join("state");
        cfg.logging.directory = temp.path().join("logs");
        cfg.telemetry.enabled = false;
        let identity = Arc::new(Identity::resolve(&cfg.agent.directory));
        let probes = PipelineProbes::default();

        let run = |expect_alerts: usize| {
            let alerts = alerts_written(|sink| {
                let lifecycle = Lifecycle::start(
                    &cfg,
                    sink,
                    identity.clone(),
                    sink.writer_metrics(),
                    probes.clone(),
                );
                drop(lifecycle);
            });
            assert_eq!(alerts.len(), expect_alerts, "{alerts:?}");
            alerts
        };

        // First ever run: no marker, nothing to report.
        run(0);
        // Killed: the marker still says running.
        let alerts = run(1);
        assert_eq!(alerts[0]["rule.name"], "agent::lifecycle::unclean_shutdown");
        assert_eq!(alerts[0]["edr.rule.severity"], "High");

        // A clean stop clears it.
        let marker = cfg.agent.directory.join(RUN_STATE_FILE_NAME);
        let mut finished = None;
        alerts_written(|sink| {
            finished = Some(Lifecycle::start(
                &cfg,
                sink,
                identity.clone(),
                sink.writer_metrics(),
                probes.clone(),
            ));
        });
        assert!(read_state(&marker).unwrap().starts_with(STATE_RUNNING));
        finished.unwrap().finish().await;
        assert_eq!(read_state(&marker).as_deref(), Some(STATE_STOPPED));
        run(0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_live_foreign_marker_is_neither_reported_nor_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = AppConfig::default();
        cfg.agent.directory = temp.path().join("state");
        cfg.logging.directory = temp.path().join("logs");
        let identity = Arc::new(Identity::resolve(&cfg.agent.directory));
        let marker = cfg.agent.directory.join(RUN_STATE_FILE_NAME);
        // Pid 1 is always alive and is not this test.
        write_state(&marker, "running 1").unwrap();

        let alerts = alerts_written(|sink| {
            let lifecycle = Lifecycle::start(
                &cfg,
                sink,
                identity.clone(),
                sink.writer_metrics(),
                PipelineProbes::default(),
            );
            assert!(lifecycle.marker.is_none());
        });
        assert!(alerts.is_empty(), "{alerts:?}");
        assert_eq!(read_state(&marker).as_deref(), Some("running 1"));
    }

    #[tokio::test]
    async fn an_exit_that_reported_itself_is_not_reported_again() {
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = AppConfig::default();
        cfg.agent.directory = temp.path().join("state");
        cfg.logging.directory = temp.path().join("logs");
        let identity = Arc::new(Identity::resolve(&cfg.agent.directory));
        let start = |sink: &AlertSink| {
            Lifecycle::start(
                &cfg,
                sink,
                identity.clone(),
                sink.writer_metrics(),
                PipelineProbes::default(),
            )
        };
        alerts_written(|sink| start(sink).mark_stopped());
        let alerts = alerts_written(|sink| drop(start(sink)));
        assert!(alerts.is_empty(), "{alerts:?}");
    }

    #[test]
    fn heartbeat_line_has_identity_and_snapshot() {
        let identity = Identity {
            host_id: None,
            host_name: Some("host-a".into()),
            agent_id: None,
            agent_type: "rustinel",
            agent_version: "9.9.9",
        };
        let snapshot = TelemetrySnapshot::capture(&PipelineProbes::default());
        let line = heartbeat_line(Some(&identity), &snapshot).unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(value["host.name"], "host-a");
        assert_eq!(value["agent.version"], "9.9.9");
        assert!(value["@timestamp"].is_string());
        assert!(value["uptime_secs"].is_u64());
        assert!(value["dropped_total"].is_u64());
        assert!(value.get("telemetry").is_none(), "{line}");
        assert!(line.len() < 400, "{line}");
    }
}
