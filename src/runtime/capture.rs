//! Shared runtime for `rustinel capture`.
//!
//! Capture is a passive runtime mode, not a lab orchestrator: it starts the
//! same sensors live protection uses, records every normalized event, and stops
//! on Ctrl-C. The user launches the sample, script, or Atomic test separately —
//! Rustinel never runs the activity being observed.
//!
//! The platform modules own sensor startup and privileges; everything before
//! and after that lives here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::capture::{CaptureRecorder, CaptureStatus};
use crate::config::AppConfig;
use crate::engine::NormalizedEventHandler;
use crate::normalizer::Normalizer;
use crate::runtime::logging::{init_operational_logging, log_startup_banner};
use crate::sensor::{Platform, SensorEvent, SensorEventRouter};
use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};

/// Capacity of the sensor-to-router channel, matching the live runtimes.
const SENSOR_CHANNEL_CAPACITY: usize = 8192;

/// How often the running event count is reported on stderr.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

/// Arguments accepted by `rustinel capture`.
#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    /// Explicit recording path; overrides the generated default.
    pub output: Option<PathBuf>,
    /// Override for `logging.level`.
    pub log_level: Option<String>,
    /// Explicit configuration file path.
    pub config_path: Option<PathBuf>,
}

/// Configuration and logging, established before platform preflight so that a
/// privilege failure is reported through the normal logging pipeline.
pub(crate) struct CaptureContext {
    config: AppConfig,
    _log_guard: tracing_appender::non_blocking::WorkerGuard,
}

impl CaptureContext {
    /// Load configuration the same way `run` does and initialize logging.
    pub(crate) fn load(options: &CaptureOptions, runtime_label: &str) -> anyhow::Result<Self> {
        let mut config = match AppConfig::from_config_path(options.config_path.clone()) {
            Ok(config) => config,
            Err(err) => {
                eprintln!("Failed to load configuration: {}", err);
                eprintln!("Hint: run rustinel doctor --config <path> to inspect configuration and runtime prerequisites.");
                return Err(anyhow::anyhow!("configuration error: {}", err));
            }
        };
        // Capture is a foreground command; mirror `run`'s console behavior.
        config.logging.console_output = true;
        if let Some(level) = options.log_level.clone() {
            if !level.trim().is_empty() {
                config.logging.level = level;
            }
        }

        let log_guard = init_operational_logging(&config);
        log_startup_banner(runtime_label);

        Ok(Self {
            config,
            _log_guard: log_guard,
        })
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Open the recording and build the record-only event pipeline.
    pub(crate) fn start_recording(
        self,
        options: &CaptureOptions,
        platform: Platform,
    ) -> anyhow::Result<CaptureSession> {
        let payload_path = resolve_output_path(&self.config, options.output.as_deref(), Utc::now());
        let recorder = CaptureRecorder::start(payload_path, platform)?;

        let process_cache = Arc::new(ProcessCache::with_max_entries(
            self.config.process.max_entries,
        ));
        let normalizer = Arc::new(Normalizer::new(
            Arc::clone(&process_cache),
            Arc::new(SidCache::new()),
            Arc::new(DnsCache::new()),
            Arc::new(ConnectionAggregator::with_limits_and_window(
                self.config.network.aggregation_max_entries,
                self.config.network.aggregation_interval_buffer_size,
                self.config.network.aggregation_window_secs,
            )),
            self.config.network.aggregation_enabled,
        ));

        // The only handler: no detectors, no alert sink, no response engine.
        let mut router = SensorEventRouter::new();
        router.register_handler(Box::new(NormalizedEventHandler::recording(
            normalizer,
            recorder.sink(),
        )));

        eprintln!("Recording to {}", recorder.payload_path().display());
        eprintln!("Start the activity you want to record, then press Ctrl+C to finish.");

        let progress = spawn_progress_reporter(&recorder);

        Ok(CaptureSession {
            _context: self,
            recorder,
            router: Arc::new(router),
            process_cache,
            progress,
        })
    }
}

/// A running capture session.
pub(crate) struct CaptureSession {
    /// Held for the lifetime of the session: dropping it closes the log writer.
    _context: CaptureContext,
    recorder: CaptureRecorder,
    router: Arc<SensorEventRouter>,
    #[cfg_attr(not(windows), allow(dead_code))]
    process_cache: Arc<ProcessCache>,
    progress: JoinHandle<()>,
}

impl CaptureSession {
    /// Process metadata cache, so platforms that can enumerate running
    /// processes seed it before the sensors start. Only Windows does today.
    #[cfg(windows)]
    pub(crate) fn process_cache(&self) -> &Arc<ProcessCache> {
        &self.process_cache
    }

    /// Start the router worker and hand back the channel the sensors feed.
    pub(crate) fn sensor_channel(&self) -> (mpsc::Sender<SensorEvent>, JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<SensorEvent>(SENSOR_CHANNEL_CAPACITY);
        let router = Arc::clone(&self.router);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(event) = rx.blocking_recv() {
                #[cfg(windows)]
                let event = {
                    let mut event = event;
                    crate::sensor::windows::enrich_event(&mut event);
                    event
                };
                router.route_event(&event);
            }
        });
        (tx, worker)
    }

    /// Mark the recording as incomplete for loss the capture sink cannot see,
    /// such as a sensor that stopped feeding events mid-session. Only the ETW
    /// runtime detects that today.
    #[cfg(windows)]
    pub(crate) fn mark_incomplete(&self, reason: &str) {
        self.recorder.mark_incomplete(reason);
    }

    /// Give up on a session whose sensors never started.
    ///
    /// Removes the empty recording this session just created rather than
    /// leaving an artifact that looks like a failed capture of something.
    ///
    /// Only the eBPF and ESF runtimes learn about a failed start synchronously;
    /// an ETW session reports it by ending, which the Windows runtime handles
    /// with [`Self::mark_incomplete`] instead.
    #[cfg(not(windows))]
    pub(crate) async fn abandon(self, sensor_worker: JoinHandle<()>) {
        drop(self.router);
        let _ = sensor_worker.await;
        self.progress.abort();
        let _ = self.progress.await;

        let payload_path = self.recorder.payload_path().to_path_buf();
        let manifest_path = self.recorder.manifest_path().to_path_buf();
        let _ = self.recorder.finish().await;
        let _ = std::fs::remove_file(&payload_path);
        let _ = std::fs::remove_file(&manifest_path);
    }

    /// Wait for a clean shutdown request.
    pub(crate) async fn wait_for_shutdown() {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("Received Ctrl+C, finalizing recording"),
            Err(err) => error!("Failed to listen for Ctrl+C: {}", err),
        }
    }

    /// Drain queued events, finalize the manifest, and report final counts.
    ///
    /// Call after the sensors have been shut down.
    pub(crate) async fn finish(
        self,
        sensor_worker: JoinHandle<()>,
        source_lost: u64,
    ) -> anyhow::Result<()> {
        drop(self.router);
        let _ = sensor_worker.await;
        self.progress.abort();
        let _ = self.progress.await;

        let payload_path = self.recorder.payload_path().to_path_buf();
        let manifest_path = self.recorder.manifest_path().to_path_buf();
        let manifest = self.recorder.finish_with_source_loss(source_lost).await?;

        info!(
            target: "capture",
            status = manifest.status.as_str(),
            received = manifest.events.received,
            written = manifest.events.written,
            lost = manifest.events.lost,
            source_lost = manifest.events.source_lost,
            "Capture finished"
        );

        eprintln!();
        eprintln!("Recording: {}", payload_path.display());
        eprintln!("Manifest:  {}", manifest_path.display());
        eprintln!(
            "Events:    {} recorded, {} writer lost, {} source lost",
            manifest.events.written, manifest.events.lost, manifest.events.source_lost
        );
        eprintln!("Status:    {}", manifest.status.as_str());
        if manifest.status != CaptureStatus::Complete {
            eprintln!(
                "This recording is incomplete and will be rejected by replay. \
                 {} events could not be written and {} were lost at the source.",
                manifest.events.lost, manifest.events.source_lost
            );
        }

        Ok(())
    }
}

/// Report the running event count on stderr. Event payloads are never printed.
fn spawn_progress_reporter(recorder: &CaptureRecorder) -> JoinHandle<()> {
    let sink = recorder.sink();
    tokio::spawn(async move {
        let mut reported = 0u64;
        loop {
            tokio::time::sleep(PROGRESS_INTERVAL).await;
            let counts = sink.counts();
            if counts.received == reported {
                continue;
            }
            reported = counts.received;
            if counts.lost > 0 {
                eprintln!("  {} events recorded, {} lost", counts.written, counts.lost);
            } else {
                eprintln!("  {} events recorded", counts.written);
            }
        }
    })
}

/// Recording path for a session: the explicit `--output` path when given,
/// otherwise a timestamped file under the configured capture directory.
pub fn resolve_output_path(
    config: &AppConfig,
    explicit: Option<&Path>,
    started_at: DateTime<Utc>,
) -> PathBuf {
    match explicit {
        Some(path) => path.to_path_buf(),
        None => config
            .capture
            .directory
            .join(default_recording_name(started_at)),
    }
}

/// Default recording file name. The timestamp is UTC and uses no characters
/// that need quoting or are rejected by Windows filesystems.
fn default_recording_name(started_at: DateTime<Utc>) -> String {
    format!(
        "rustinel-capture-{}.ndjson",
        started_at.format("%Y%m%dT%H%M%SZ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn started_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 16, 9, 12, 40)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn default_name_uses_a_path_safe_utc_timestamp() {
        let name = default_recording_name(started_at());

        assert_eq!(name, "rustinel-capture-20260816T091240Z.ndjson");
        assert!(
            !name.contains(':'),
            "colons are not valid in Windows file names"
        );
    }

    #[test]
    fn default_output_lands_in_the_configured_capture_directory() {
        let mut config = AppConfig::default();
        config.capture.directory = PathBuf::from("/var/lib/rustinel/captures");

        assert_eq!(
            resolve_output_path(&config, None, started_at()),
            PathBuf::from("/var/lib/rustinel/captures/rustinel-capture-20260816T091240Z.ndjson")
        );
    }

    #[test]
    fn an_explicit_output_path_overrides_the_default() {
        let config = AppConfig::default();
        let explicit = PathBuf::from("/tmp/lab/run-42.ndjson");

        assert_eq!(
            resolve_output_path(&config, Some(&explicit), started_at()),
            explicit
        );
    }
}
