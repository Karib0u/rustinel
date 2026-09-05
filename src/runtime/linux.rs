use crate::response::ResponseEngine;
use crate::runtime::capture::{CaptureContext, CaptureOptions, CaptureSession};
use crate::runtime::logging::TARGET_CONSOLE;
use crate::runtime::pipeline::{LivePipeline, SharedState};
use crate::runtime::startup::{load_config, RuntimeLogging};
use crate::sensor::linux::EbpfSensor;
use crate::sensor::{Platform, Sensor, SensorEvent};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tracing::{error, info};

pub fn run(
    console_output: bool,
    log_level: Option<String>,
    config_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_linux_edr(Some(console_output), log_level, config_path))
}

/// Linux capture runtime: the same eBPF sensor as `run`, recording normalized
/// events instead of evaluating them.
pub fn run_capture(options: CaptureOptions) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let context = CaptureContext::load(&options, "Linux eBPF")?;
        let session = context.start_recording(&options, Platform::Linux)?;
        let (sensor_tx, sensor_worker) = session.sensor_channel();

        let sensor = Arc::new(EbpfSensor::new());
        info!(target: TARGET_CONSOLE, "Starting eBPF sensor...");
        if let Err(e) = sensor.start(sensor_tx) {
            error!("eBPF sensor failed to start: {:#}", e);
            session.abandon(sensor_worker).await;
            return Err(e);
        }

        CaptureSession::wait_for_shutdown().await;
        sensor.shutdown();
        session.finish(sensor_worker, 0).await
    })
}

/// Linux eBPF EDR main loop. Mirrors `run_edr` but replaces ETW with the
/// eBPF sensor and omits Windows-only subsystems.
async fn run_linux_edr(
    console_output_override: Option<bool>,
    log_level_override: Option<String>,
    config_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let (cfg, resolved_config_path) =
        load_config(console_output_override, log_level_override, config_path)?;
    let RuntimeLogging {
        alert_sink,
        dedup_worker_handle,
        telemetry_reporter,
        _guards,
    } = RuntimeLogging::start(&cfg, "Linux eBPF");

    // 3. Shared state
    let state = SharedState::new(&cfg);

    // 4. Active response engine
    let response_config = Arc::new(ArcSwap::from(Arc::new(cfg.response.clone())));
    let (response_engine, response_worker_handle) = ResponseEngine::new(response_config.clone());

    let pipeline = LivePipeline::new(
        &cfg,
        resolved_config_path,
        Platform::Linux,
        state,
        alert_sink.clone(),
        response_config,
        response_engine.clone(),
    );

    // 13. eBPF sensor
    let sensor = Arc::new(EbpfSensor::new());

    info!(
        target: TARGET_CONSOLE,
        "Starting eBPF sensor; press Ctrl+C to stop gracefully"
    );

    let (sensor_tx, mut sensor_rx) = mpsc::channel::<SensorEvent>(8192);
    let router_for_worker = Arc::clone(&pipeline.router);
    let sensor_worker_handle = tokio::task::spawn_blocking(move || {
        while let Some(event) = sensor_rx.blocking_recv() {
            router_for_worker.route_event(&event);
        }
    });

    let sensor_clone = Arc::clone(&sensor);
    if let Err(e) = sensor_clone.start(sensor_tx) {
        error!("eBPF sensor failed to start: {:#}", e);
        return Err(e);
    }

    // 14. Wait for Ctrl+C
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!(target: TARGET_CONSOLE, "Received Ctrl+C, shutting down"),
        Err(e) => error!("Failed to listen for Ctrl+C: {}", e),
    }
    sensor.shutdown();

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
    Ok(())
}
