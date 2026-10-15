//! Runtime wiring for the pipeline drop counters.
//!
//! The counters themselves are always live; this is the piece that publishes
//! them outside the process so `rustinel doctor` can read them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::alerts::{AlertSink, AlertWriterMetrics};
use crate::config::AppConfig;
use crate::models::ecs::{AgentLoss, EcsAlert};
use crate::telemetry::{
    sensor_event_drop_totals, snapshot_path, spawn_reporter, write_final_snapshot, PipelineProbes,
};
use crate::vocab::Platform;

/// Background task publishing the pipeline counters for `rustinel doctor`.
pub struct TelemetryReporter {
    path: PathBuf,
    handle: JoinHandle<()>,
    alert_writer: AlertWriterMetrics,
    probes: PipelineProbes,
}

impl TelemetryReporter {
    /// Start publishing, unless the operator turned persistence off.
    pub fn start(cfg: &AppConfig, alert_sink: &AlertSink, probes: PipelineProbes) -> Option<Self> {
        if !cfg.telemetry.enabled {
            return None;
        }

        let path = snapshot_path(&cfg.logging.directory);
        let alert_writer = alert_sink.writer_metrics();
        let handle = spawn_reporter(
            path.clone(),
            Duration::from_secs(cfg.telemetry.snapshot_interval_secs),
            alert_writer.clone(),
            probes.clone(),
        );
        Some(Self {
            path,
            handle,
            alert_writer,
            probes,
        })
    }

    /// Stop publishing after one final write.
    ///
    /// The last interval's drops are the ones an operator is most likely to be
    /// asking about — an agent that shed events and then stopped — so the
    /// shutdown snapshot is written rather than left to a tick that never came.
    pub async fn finish(self) {
        self.handle.abort();
        let _ = self.handle.await;
        write_final_snapshot(&self.path, &self.alert_writer, &self.probes);
    }
}

/// Turns `sensor_events` drops into operational alerts.
///
/// Delivery cannot feed back into the loss it reports. The task only reads the
/// drop counters and hands a finished alert to the sink, whose writer queue and
/// webhook dispatch are both non-blocking and separate from `sensor_events`. A
/// sink failure is logged by the sink and never touches those counters, so it
/// cannot produce a further loss alert. At most one alert per dropped category
/// is written per window, however many events were lost.
pub struct SensorLossAlerter {
    handle: JoinHandle<()>,
    state: LossWindow,
    alert_sink: AlertSink,
    window_secs: u64,
}

impl SensorLossAlerter {
    /// Start alerting, unless `telemetry.loss_alert_interval_secs` is zero.
    pub fn start(cfg: &AppConfig, alert_sink: &AlertSink) -> Option<Self> {
        let window_secs = cfg.telemetry.loss_alert_interval_secs;
        if window_secs == 0 {
            return None;
        }

        let state = LossWindow::default();
        let task_sink = alert_sink.clone();
        let mut task_state = state.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(window_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick completes immediately; the first window starts now.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                emit_loss_alerts(&task_sink, &mut task_state, window_secs);
            }
        });
        Some(Self {
            handle,
            state,
            alert_sink: alert_sink.clone(),
            window_secs,
        })
    }

    /// Stop after reporting what was lost since the last window closed.
    ///
    /// The remainder is reported with the full window length because the exact
    /// elapsed time is not tracked; receivers should treat `window_secs` as an
    /// upper bound on the final alert.
    pub async fn finish(self) {
        self.handle.abort();
        // The baseline is shared with the aborted task, so this continues from
        // the last window it closed.
        let _ = self.handle.await;
        let mut state = self.state;
        emit_loss_alerts(&self.alert_sink, &mut state, self.window_secs);
    }
}

/// Per-category drop totals already reported, shared so the shutdown flush
/// continues from where the periodic task stopped.
#[derive(Clone, Default)]
struct LossWindow {
    reported: std::sync::Arc<std::sync::Mutex<HashMap<&'static str, u64>>>,
}

impl LossWindow {
    /// Drops since the previous call, per category, advancing the baseline.
    fn advance(&mut self, totals: &[(&'static str, u64)]) -> Vec<(&'static str, u64)> {
        let mut reported = self
            .reported
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        totals
            .iter()
            .filter_map(|&(category, total)| {
                let previous = reported.insert(category, total).unwrap_or(0);
                let dropped = total.saturating_sub(previous);
                (dropped > 0).then_some((category, dropped))
            })
            .collect()
    }
}

fn emit_loss_alerts(alert_sink: &AlertSink, state: &mut LossWindow, window_secs: u64) {
    write_loss_alerts(
        alert_sink,
        state.advance(&sensor_event_drop_totals()),
        window_secs,
    );
}

fn write_loss_alerts(alert_sink: &AlertSink, losses: Vec<(&'static str, u64)>, window_secs: u64) {
    for (category, dropped) in losses {
        let ecs = EcsAlert::agent_loss(
            host_platform(),
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            AgentLoss {
                channel: crate::telemetry::ChannelId::SensorEvents.as_str(),
                category,
                dropped,
                window_secs,
            },
        );
        // Bypasses deduplication and active response, which only see detections.
        alert_sink.write_ecs(&ecs);
    }
}

fn host_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else {
        Platform::Linux
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

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

    #[test]
    fn each_window_reports_only_new_drops_per_category() {
        let mut window = LossWindow::default();

        assert!(window.advance(&[]).is_empty());
        assert_eq!(
            window.advance(&[("process", 3), ("file", 10)]),
            vec![("process", 3), ("file", 10)]
        );
        assert_eq!(
            window.advance(&[("process", 3), ("file", 14), ("dns", 1)]),
            vec![("file", 4), ("dns", 1)]
        );
        assert!(window
            .advance(&[("process", 3), ("file", 14), ("dns", 1)])
            .is_empty());
    }

    #[test]
    fn loss_alert_carries_the_agent_shape_and_the_count() {
        let output = SharedWriter(Arc::new(Mutex::new(Vec::new())));
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .finish(output.clone());
        let sink = AlertSink::new(writer);

        write_loss_alerts(&sink, vec![("process", 7), ("network", 2)], 60);
        drop(sink);
        drop(guard);

        let json = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let alerts: Vec<serde_json::Value> = json
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(alerts.len(), 2);
        let first = &alerts[0];
        assert_eq!(first["rule.name"], "agent::loss::sensor_events");
        assert_eq!(first["edr.rule.engine"], "Agent");
        assert_eq!(first["event.dataset"], "edr.agent");
        assert_eq!(first["edr.agent.loss.channel"], "sensor_events");
        assert_eq!(first["edr.agent.loss.category"], "process");
        assert_eq!(first["edr.agent.loss.dropped"], 7);
        assert_eq!(first["edr.agent.loss.window_secs"], 60);
        assert_eq!(alerts[1]["edr.agent.loss.category"], "network");
        assert_eq!(alerts[1]["edr.agent.loss.dropped"], 2);
    }

    /// Saturating the real sensor queue is what produces the totals the alert
    /// reads, and reporting them must not need that queue.
    #[tokio::test]
    async fn saturating_the_sensor_queue_produces_a_loss_alert() {
        use crate::sensor::RawEvent;

        let before = sensor_event_drop_totals();
        let (tx, mut _rx) = tokio::sync::mpsc::channel::<RawEvent>(1);
        let mut dropped = 0u64;
        for _ in 0..5 {
            if crate::telemetry::try_send_sensor_event(&tx, test_raw_event()).is_err() {
                dropped += 1;
            }
        }
        assert!(dropped >= 4);

        let mut window = LossWindow::default();
        window.advance(&before);
        let losses = window.advance(&sensor_event_drop_totals());
        let dns = losses.iter().find(|(category, _)| *category == "dns");
        assert!(dns.is_some_and(|(_, count)| *count >= 4), "{losses:?}");
    }

    fn test_raw_event() -> crate::sensor::RawEvent {
        use crate::models::DnsQueryFields;
        use crate::sensor::{RawPayload, SensorAction, SensorNormalization};

        crate::sensor::RawEvent {
            process_name: None,
            provenance: Default::default(),
            platform: crate::sensor::Platform::Linux,
            provider: "test",
            action: SensorAction::Connect,
            normalization: SensorNormalization {
                event_id: 22,
                action_code: 1,
            },
            pid: None,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
            payload: RawPayload::Dns(DnsQueryFields {
                user: None,
                query_name: None,
                query_results: None,
                record_type: None,
                query_status: None,
                process_id: None,
                image: None,
            }),
        }
    }
}
