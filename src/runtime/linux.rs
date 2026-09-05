use crate::alerts::dedup::{spawn_flush_worker, Deduplicator};
use crate::config;
use crate::response::ResponseEngine;
use crate::runtime::capture::{CaptureContext, CaptureOptions, CaptureSession};
use crate::runtime::logging::{init_logging, log_startup_banner, TARGET_CONSOLE};
use crate::runtime::pipeline::{LivePipeline, SharedState};
use crate::runtime::telemetry::TelemetryReporter;
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
    // 1. Configuration
    let resolved_config_path = config::AppConfig::resolve_config_path(config_path.clone());
    let mut cfg = match config::AppConfig::from_config_path(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Failed to load configuration: {}", err);
            eprintln!("Hint: run rustinel doctor --config <path> to inspect configuration and runtime prerequisites.");
            return Err(anyhow::anyhow!("configuration error: {}", err));
        }
    };
    if let Some(console_output) = console_output_override {
        cfg.logging.console_output = console_output;
    }
    if let Some(level) = log_level_override {
        if !level.trim().is_empty() {
            cfg.logging.level = level;
        }
    }

    // 2. Logging
    let (app_guard, alert_guard, mut alert_sink) = init_logging(&cfg);
    let _guards = (app_guard, alert_guard);

    // 2a. Alert deduplication
    let dedup_worker_handle = if cfg.dedup.enabled {
        let dedup = Arc::new(Deduplicator::new(
            cfg.dedup.window_secs,
            cfg.dedup.max_entries,
        ));
        let tick = std::time::Duration::from_secs(cfg.dedup.window_secs.max(1));
        let handle = spawn_flush_worker(Arc::clone(&dedup), alert_sink.clone(), tick);
        alert_sink = alert_sink.with_deduplicator(dedup);
        Some(handle)
    } else {
        None
    };

    log_startup_banner("Linux eBPF");

    // 2b. Pipeline drop counters, published for `rustinel doctor`
    let telemetry_reporter = TelemetryReporter::start(&cfg);

    // 3. Shared state
    let state = SharedState::new(&cfg);

    // 4. Active response engine
    let response_config = Arc::new(ArcSwap::from(Arc::new(cfg.response.clone())));
    let (response_engine, response_worker_handle) = ResponseEngine::new(response_config.clone());

    let LivePipeline {
        router,
        yara_worker_handle,
        yara_memory_worker_handle,
        mut ioc_hash_worker_handle,
        mut reload_poller,
        mut reload_worker_handle,
        mut reload_tx,
    } = LivePipeline::new(
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
    let router_for_worker = Arc::clone(&router);
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

    // Drain workers
    drop(router);
    drop(response_engine);
    let _ = sensor_worker_handle.await;
    if let Some(h) = yara_worker_handle {
        let _ = h.await;
    }
    if let Some(h) = yara_memory_worker_handle {
        let _ = h.await;
    }
    if let Some(h) = ioc_hash_worker_handle.take() {
        let _ = h.await;
    }
    if let Some(poller) = reload_poller.take() {
        poller.shutdown().await;
    }
    drop(reload_tx.take());
    if let Some(h) = reload_worker_handle.take() {
        let _ = h.await;
    }
    let _ = response_worker_handle.await;

    if let Some(handle) = dedup_worker_handle {
        handle.abort();
        let _ = handle.await;
    }
    if let Some(dedup) = alert_sink.dedup() {
        dedup.flush_all(&alert_sink);
        dedup.log_metrics();
    }

    if let Some(reporter) = telemetry_reporter {
        reporter.finish().await;
    }

    info!(target: TARGET_CONSOLE, "Shutdown complete");
    Ok(())
}
