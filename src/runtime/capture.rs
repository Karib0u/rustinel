//! Shared runtime for `rustinel capture`.
//!
//! Capture is a passive runtime mode, not a lab orchestrator: it starts the
//! same sensors live protection uses, records every canonical event, and stops
//! on Ctrl-C. The user launches the sample, script, or Atomic test separately —
//! Rustinel never runs the activity being observed.
//!
//! The platform modules describe their sensors and privileges with a
//! `PlatformRuntime`; everything before and after that lives here, including
//! the run itself.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::artifact::{spawn_artifact_resolver, ArtifactRuntime};
use crate::capture::{CaptureRecorder, CaptureStatus};
use crate::config::AppConfig;
use crate::engine::CanonicalEventDispatcher;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use crate::runtime::logging::TARGET_CONSOLE;
use crate::runtime::logging::{init_operational_logging, log_startup_banner};
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use crate::runtime::sensors::{
    spawn_sensor_worker, PlatformRuntime, RunMode, ShutdownFuture, StartFailure,
};
use crate::sensor::{Platform, RawEvent, SensorEventRouter};
use crate::state::HostState;

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

        let log_guard = init_operational_logging(&config)?;
        log_startup_banner(runtime_label);

        Ok(Self {
            config,
            _log_guard: log_guard,
        })
    }

    /// Open the recording and build the record-only event pipeline.
    pub(crate) fn start_recording(
        self,
        options: &CaptureOptions,
        platform: Platform,
    ) -> anyhow::Result<CaptureSession> {
        let payload_path = resolve_output_path(&self.config, options.output.as_deref(), Utc::now());
        let recorder = CaptureRecorder::start(payload_path, platform)?;

        let host_state = HostState::for_runtime(self.config.process.max_entries);

        // The only handler: no detectors, no alert sink, no response engine.
        let mut downstream = SensorEventRouter::new();
        downstream.register_handler(Box::new(CanonicalEventDispatcher::recording(
            Arc::clone(&host_state),
            recorder.sink(),
        )));
        let (router, artifact_worker, artifact_resolver) = spawn_artifact_resolver(
            Arc::new(downstream),
            Arc::clone(&host_state),
            ArtifactRuntime::capture(platform),
        );

        eprintln!("Recording to {}", recorder.payload_path().display());

        let progress = spawn_progress_reporter(&recorder);

        Ok(CaptureSession {
            _context: self,
            recorder,
            router,
            host_state,
            artifact_worker,
            artifact_resolver,
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
    host_state: Arc<HostState>,
    artifact_worker: JoinHandle<()>,
    artifact_resolver: crate::artifact::ArtifactResolverHandle,
    progress: JoinHandle<()>,
}

impl CaptureSession {
    /// Tell the operator that every required collector is ready to admit
    /// telemetry. Platform runtimes call this only after sensor startup has
    /// completed, so callers can use the line as a readiness barrier.
    pub(crate) fn announce_ready(&self) {
        eprintln!("Start the activity you want to record, then press Ctrl+C to finish.");
    }

    /// Process metadata cache, so platforms that can enumerate running
    /// processes can seed it during startup.
    pub(crate) fn host_state(&self) -> &Arc<HostState> {
        &self.host_state
    }

    /// Start the router worker and hand back the channel the sensors feed.
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    pub(crate) fn sensor_channel(
        &self,
        capacity: usize,
    ) -> (mpsc::Sender<RawEvent>, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<RawEvent>(capacity);
        let worker =
            spawn_sensor_worker(rx, Arc::clone(&self.router), Arc::clone(&self.host_state));
        (tx, worker)
    }

    /// Mark the recording as incomplete for loss the capture sink cannot see,
    /// such as a sensor that stopped feeding events mid-session.
    pub(crate) fn mark_incomplete(&self, reason: &str) {
        self.recorder.mark_incomplete(reason);
    }

    /// Give up on a session whose sensors never started.
    ///
    /// Removes the empty recording this session just created rather than
    /// leaving an artifact that looks like a failed capture of something.
    ///
    /// Which runtimes abandon and which keep an incomplete recording is
    /// [`StartFailure`].
    pub(crate) async fn abandon(self, sensor_worker: JoinHandle<()>) {
        drop(self.router);
        let _ = sensor_worker.await;
        let _ = self.artifact_worker.await;
        drop(self.artifact_resolver);
        self.progress.abort();
        let _ = self.progress.await;

        let payload_path = self.recorder.payload_path().to_path_buf();
        let manifest_path = self.recorder.manifest_path().to_path_buf();
        let _ = self.recorder.finish().await;
        let _ = std::fs::remove_file(&payload_path);
        let _ = std::fs::remove_file(&manifest_path);
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
        let _ = self.artifact_worker.await;
        drop(self.artifact_resolver);
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

/// Record one run: start the platform's sensors, wait for `shutdown`, then
/// drain and finalize the recording.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(super) async fn run_capture(
    runtime: &PlatformRuntime,
    mut shutdown: ShutdownFuture,
    options: &CaptureOptions,
) -> anyhow::Result<()> {
    let context = CaptureContext::load(options, runtime.label)?;
    (runtime.preflight)()?;
    let config = context.config.clone();
    let session = context.start_recording(options, runtime.platform)?;
    (runtime.seed_host_state)(session.host_state());

    let (sensor_tx, sensor_worker) = session.sensor_channel(runtime.channel_capacity);
    let sensors = (runtime.sensors)(&config, session.host_state(), RunMode::Capture);
    info!(target: TARGET_CONSOLE, "Starting {}...", runtime.starting);

    // A reduced sensor set is a narrower recording, not a lossy one, so it
    // still finalizes as complete.
    let started = sensors
        .start(&sensor_tx, |name, consequence, error| {
            eprintln!("Warning: {name} unavailable ({error:#}); {consequence}");
        })
        .await;
    drop(sensor_tx);

    if let Err(failed) = started {
        sensors.stop().await;
        return match runtime.start_failure {
            StartFailure::Abandon => {
                session.abandon(sensor_worker).await;
                Err(failed.error)
            }
            StartFailure::KeepIncomplete => {
                let reason = format!("{} failed during startup: {:#}", failed.name, failed.error);
                session.mark_incomplete(&reason);
                session.finish(sensor_worker, sensors.events_lost()).await?;
                Err(anyhow::anyhow!(reason))
            }
        };
    }
    session.announce_ready();

    // A sensor that ends on its own takes the recording with it: everything
    // after that point is missing, which the capture sink cannot see, so the
    // recording has to be marked incomplete explicitly.
    let mut sensor_failure = None;
    tokio::select! {
        signal = &mut shutdown => match signal {
            Some(signal) => info!("Received {}, finalizing recording", signal),
            None => error!("Shutdown signal listener closed unexpectedly"),
        },
        (name, reason) = sensors.first_ended() => {
            let reason = format!("{name}: {reason}");
            error!("🚨 {}", reason);
            session.mark_incomplete(&reason);
            sensor_failure = Some(anyhow::anyhow!(reason));
        }
    }
    sensors.stop().await;

    session.finish(sensor_worker, sensors.events_lost()).await?;
    sensor_failure.map_or(Ok(()), Err)
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
