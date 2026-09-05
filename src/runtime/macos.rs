use crate::response::ResponseEngine;
use crate::runtime::capture::{CaptureContext, CaptureOptions, CaptureSession};
use crate::runtime::logging::TARGET_CONSOLE;
use crate::runtime::pipeline::{LivePipeline, SharedState};
use crate::runtime::startup::{load_config, RuntimeLogging};
use crate::sensor::macos::{BpfSensor, EsfSensor};
use crate::sensor::{Platform, Sensor, SensorEvent};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub fn run(
    console_output: bool,
    log_level: Option<String>,
    config_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_macos_edr(Some(console_output), log_level, config_path))
}

/// macOS capture runtime: the same Endpoint Security and network sensors as
/// `run`, recording normalized events instead of evaluating them.
pub fn run_capture(options: CaptureOptions) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let context = CaptureContext::load(&options, "macOS ESF")?;
        let session = context.start_recording(&options, Platform::MacOS)?;
        let (sensor_tx, sensor_worker) = session.sensor_channel();

        let esf_sensor = Arc::new(EsfSensor::new());
        let bpf_sensor = Arc::new(BpfSensor::new());
        info!(target: TARGET_CONSOLE, "Starting macOS sensors...");

        // Endpoint Security is the primary source; failing to start it is fatal.
        if let Err(e) = esf_sensor.start(sensor_tx.clone()) {
            error!("macOS Endpoint Security sensor failed to start: {:#}", e);
            drop(sensor_tx);
            session.abandon(sensor_worker).await;
            return Err(e);
        }

        // Network/DNS capture is best-effort; degrade to ESF-only if it fails,
        // exactly as `run` does. A reduced sensor set is a narrower recording,
        // not a lossy one, so the recording still finalizes as complete.
        if let Err(e) = bpf_sensor.start(sensor_tx) {
            warn!(
                "macOS network/DNS sensor unavailable: {:#}; recording Endpoint Security only",
                e
            );
            eprintln!("Warning: network and DNS events will not be recorded ({e:#})");
        }

        CaptureSession::wait_for_shutdown().await;
        esf_sensor.shutdown();
        bpf_sensor.shutdown();
        session.finish(sensor_worker, 0).await
    })
}

/// macOS EDR main loop. Mirrors `run_linux_edr`, sourcing process and file
/// events from Endpoint Security and network and DNS events from a /dev/bpf
/// capture sensor.
async fn run_macos_edr(
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
    } = RuntimeLogging::start(&cfg, "macOS ESF");

    // 3. Shared state
    let state = SharedState::new(&cfg);

    // 4. Active response engine
    let response_config = Arc::new(ArcSwap::from(Arc::new(cfg.response.clone())));
    let (response_engine, response_worker_handle) = ResponseEngine::new(response_config.clone());

    let pipeline = LivePipeline::new(
        &cfg,
        resolved_config_path,
        Platform::MacOS,
        state,
        alert_sink.clone(),
        response_config,
        response_engine.clone(),
    );

    // 13. macOS sensors: Endpoint Security (process/file) and bpf (network/DNS)
    let esf_sensor = Arc::new(EsfSensor::new());
    let bpf_sensor = Arc::new(BpfSensor::new());

    info!(
        target: TARGET_CONSOLE,
        "Starting macOS sensors; press Ctrl+C to stop gracefully"
    );

    let (sensor_tx, mut sensor_rx) = mpsc::channel::<SensorEvent>(8192);
    let router_for_worker = Arc::clone(&pipeline.router);
    let sensor_worker_handle = tokio::task::spawn_blocking(move || {
        while let Some(event) = sensor_rx.blocking_recv() {
            router_for_worker.route_event(&event);
        }
    });

    // Endpoint Security is the primary source; failing to start it is fatal.
    let esf_clone = Arc::clone(&esf_sensor);
    if let Err(e) = esf_clone.start(sensor_tx.clone()) {
        error!("macOS Endpoint Security sensor failed to start: {:#}", e);
        return Err(e);
    }

    // Network/DNS capture is best-effort; degrade to ESF-only if it fails.
    let bpf_clone = Arc::clone(&bpf_sensor);
    if let Err(e) = bpf_clone.start(sensor_tx) {
        warn!(
            "macOS network/DNS sensor unavailable: {:#}; continuing with Endpoint Security only",
            e
        );
    }

    // 14. Wait for Ctrl+C
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!(target: TARGET_CONSOLE, "Received Ctrl+C, shutting down"),
        Err(e) => error!("Failed to listen for Ctrl+C: {}", e),
    }
    esf_sensor.shutdown();
    bpf_sensor.shutdown();

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
