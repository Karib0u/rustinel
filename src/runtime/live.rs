//! The live detection loop, shared by every platform.
//!
//! A platform runtime describes its sensors with a [`PlatformRuntime`]; this
//! module owns everything else: configuration, logging, the detection
//! pipeline, the sensor channel and its worker, the wait for shutdown, and the
//! drain.
//! A sensor that fails to start takes the same drain as a normal shutdown, so
//! the dedup flush and the final telemetry snapshot are never skipped.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;

use crate::response::ResponseEngine;
use crate::runtime::logging::TARGET_CONSOLE;
use crate::runtime::pipeline::{LivePipeline, SharedState};
use crate::runtime::sensors::{PlatformRuntime, RunMode, ShutdownFuture};
use crate::runtime::shutdown::exit_on_critical_worker_failure;
use crate::runtime::startup::{load_config, RuntimeLogging};

/// Run detection until `shutdown` resolves.
///
/// The caller builds `shutdown` before this starts so the process handles its
/// stop signal from the first moment sensors run.
pub(super) async fn run_live(
    runtime: &PlatformRuntime,
    mut shutdown: ShutdownFuture,
    console_output_override: Option<bool>,
    log_level_override: Option<String>,
    config_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let (cfg, resolved_config_path) =
        load_config(console_output_override, log_level_override, config_path)?;
    let RuntimeLogging {
        alert_sink,
        dedup_worker_handle,
        telemetry_reporter,
        _guards,
    } = RuntimeLogging::start(&cfg, runtime.label, resolved_config_path.as_deref())?;

    info!(target: TARGET_CONSOLE, "Agent initializing");

    let response_config = Arc::new(ArcSwap::from(Arc::new(cfg.response.clone())));
    let (response_engine, mut response_worker_handle) =
        ResponseEngine::new(response_config.clone());

    (runtime.preflight)()?;

    let state = SharedState::new(&cfg);
    (runtime.seed_host_state)(&state.host);
    let sensors = (runtime.sensors)(&cfg, &state.host, RunMode::Live);

    let mut pipeline = LivePipeline::new(
        &cfg,
        resolved_config_path,
        runtime.platform,
        state,
        alert_sink.clone(),
        response_config,
        response_engine.clone(),
    );

    let (sensor_tx, sensor_rx) = mpsc::channel(runtime.channel_capacity);
    let mut sensor_worker_handle = super::sensors::spawn_sensor_worker(
        sensor_rx,
        Arc::clone(&pipeline.router),
        Arc::clone(&pipeline.host_state),
    );

    info!(target: TARGET_CONSOLE, "Starting {}", runtime.starting);
    let started = sensors.start(&sensor_tx, |_, _, _| {}).await;
    // The sensors hold their own senders; the channel closes once they stop.
    drop(sensor_tx);

    let outcome = match started {
        Err(failed) => Err(failed.error),
        Ok(()) => {
            info!(
                target: TARGET_CONSOLE,
                "Agent ready; press Ctrl+C to stop gracefully"
            );
            tokio::select! {
                biased;
                signal = &mut shutdown => match signal {
                    Some(signal) => {
                        info!(target: TARGET_CONSOLE, "Received {}, shutting down", signal);
                        Ok(())
                    }
                    None => Err(anyhow::anyhow!("Shutdown signal listener closed unexpectedly")),
                },
                (name, result) = pipeline.critical_worker_exit(&mut sensor_worker_handle, &mut response_worker_handle) => {
                    exit_on_critical_worker_failure(name, result, _guards);
                }
                (name, reason) = sensors.first_ended() => {
                    exit_on_sensor_end(name, &reason, _guards);
                }
            }
        }
    };

    sensors.stop().await;

    drop(response_engine);
    pipeline
        .shutdown(
            sensor_worker_handle,
            response_worker_handle,
            dedup_worker_handle,
            &alert_sink,
            telemetry_reporter,
        )
        .await;

    info!(target: TARGET_CONSOLE, "Shutdown complete");
    outcome
}

/// A sensor that ends on its own leaves the agent running but blind, so exit
/// and let the service manager restart it.
fn exit_on_sensor_end(name: &str, reason: &str, guards: (WorkerGuard, WorkerGuard)) -> ! {
    error!(
        sensor = name,
        reason, "Sensor ended before shutdown; restarting agent"
    );
    drop(guards);
    std::process::exit(1);
}
