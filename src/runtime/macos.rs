use crate::engine::{Engine, SigmaDetectionHandler};
use crate::ioc::IocEngine;
use crate::memory::MemoryScanConfig;
use crate::normalizer::Normalizer;
use crate::reload::DetectorStore;
use crate::response::ResponseEngine;
use crate::runtime::logging::{init_logging, log_startup_banner};
use crate::runtime::{ioc as runtime_ioc, yara as runtime_yara};
use crate::scanner::{YaraEventHandler, YaraMemoryJob};
use crate::sensor::macos::EsfSensor;
use crate::sensor::{Platform, Sensor, SensorEvent, SensorEventRouter};
use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
use crate::{config, reload, scanner};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub fn run() -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_macos_edr())
}

/// macOS EDR main loop. Mirrors `run_linux_edr` but replaces the eBPF sensor
/// with the macOS sensor. In Phase 0 this is a no-op placeholder sensor so the
/// shared pipeline can be exercised end to end; the Endpoint Security and
/// /dev/bpf sources land in later phases.
async fn run_macos_edr() -> anyhow::Result<()> {
    // 1. Configuration
    let cfg = match config::AppConfig::new() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Failed to load configuration: {}", err);
            return Err(anyhow::anyhow!("configuration error: {}", err));
        }
    };

    // 2. Logging
    let (app_guard, alert_guard, alert_sink) = init_logging(&cfg);
    let _guards = (app_guard, alert_guard);

    log_startup_banner("macOS ESF");

    // 3. Shared state
    let process_cache = Arc::new(ProcessCache::new());
    let sid_cache = Arc::new(SidCache::new()); // no-op on macOS; kept for Normalizer compat
    let dns_cache = Arc::new(DnsCache::new());
    let connection_aggregator = Arc::new(ConnectionAggregator::with_limits(
        cfg.network.aggregation_max_entries,
        cfg.network.aggregation_interval_buffer_size,
    ));

    // 4. Active response engine
    let (response_engine, response_worker_handle) = ResponseEngine::new(&cfg.response);

    // 5. Sigma engine
    let mut sigma_engine = Engine::new_for_platform_with_logging_level_and_match_debug(
        Platform::MacOS,
        &cfg.logging.level,
        cfg.alerts.match_debug,
    );

    if cfg.scanner.sigma_enabled {
        info!(rules_path = ?cfg.scanner.sigma_rules_path, "Loading Sigma rules");
        if let Err(e) = sigma_engine.load_rules(&cfg.scanner.sigma_rules_path) {
            warn!(error = %e, "Failed to load Sigma rules");
        } else {
            let stats = sigma_engine.stats();
            info!(
                total_rules = stats.total_rules,
                skipped_deferred_rules = stats.skipped_deferred_rules,
                skipped_unknown_logsource_rules = stats.skipped_unknown_logsource_rules,
                skipped_product_rules = stats.skipped_product_rules,
                inactive_collector_rules = stats.inactive_collector_rules,
                "Sigma engine initialized"
            );
            for (logsource, count) in stats.rules_by_logsource {
                info!(logsource = %logsource, count, "Sigma rules loaded");
            }
        }
    }
    let sigma_engine = Arc::new(sigma_engine);

    // 6. YARA scanner
    let yara_scanner = if cfg.scanner.yara_enabled {
        match scanner::Scanner::new(&cfg.scanner.yara_rules_path) {
            Ok(s) => {
                info!("YARA scanner initialized");
                Arc::new(s)
            }
            Err(e) => {
                warn!(error = %e, "Failed to load YARA rules; YARA scanning disabled");
                Arc::new(scanner::Scanner::new(Path::new(".")).expect("empty YARA scanner"))
            }
        }
    } else {
        Arc::new(scanner::Scanner::new(Path::new(".")).expect("empty YARA scanner"))
    };

    let yara_allowlist_paths =
        scanner::normalize_allowlist_paths(&cfg.scanner.yara_allowlist_paths);

    // 7. IOC engine
    let ioc_engine = Arc::new(IocEngine::load(&cfg.ioc));

    // 8. Detector store + hot-reload
    let detectors = DetectorStore::new(
        Arc::clone(&sigma_engine),
        Arc::clone(&yara_scanner),
        Arc::clone(&ioc_engine),
    );

    let mut reload_poller_handle = None;
    let mut reload_worker_handle = None;
    let mut reload_tx = None;
    if cfg.reload.enabled {
        let (tx, rx) = mpsc::unbounded_channel();
        reload_worker_handle = Some(reload::spawn_reload_worker(
            Arc::clone(&detectors),
            cfg.scanner.clone(),
            cfg.ioc.clone(),
            cfg.reload.clone(),
            cfg.logging.level.clone(),
            cfg.alerts.match_debug,
            rx,
        ));
        reload_poller_handle = Some(reload::spawn_reload_poller(
            cfg.scanner.clone(),
            cfg.ioc.clone(),
            cfg.reload.clone(),
            tx.clone(),
        ));
        reload_tx = Some(tx);
    }

    // 9. YARA background worker
    let (yara_tx, yara_rx) = mpsc::channel::<(String, u32)>(1000);

    let (yara_memory_tx, yara_memory_rx) =
        if cfg.scanner.yara_enabled && cfg.scanner.yara_memory_enabled {
            let capacity = cfg.scanner.yara_memory_queue_capacity.max(1);
            let (tx, rx) = mpsc::channel::<YaraMemoryJob>(capacity);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
    let yara_worker_handle = runtime_yara::spawn_yara_file_worker(
        Arc::clone(&detectors),
        alert_sink.clone(),
        response_engine.clone(),
        cfg.alerts.match_debug,
        yara_rx,
        yara_allowlist_paths.clone(),
        Platform::MacOS,
        "esf",
    );

    // Spawn optional YARA memory scanning worker (macOS).
    let yara_memory_worker_handle = if let Some(mem_rx) = yara_memory_rx {
        let mem_cfg = MemoryScanConfig {
            max_process_bytes: (cfg.scanner.yara_memory_max_process_mb * 1024 * 1024) as usize,
            max_region_bytes: (cfg.scanner.yara_memory_max_region_mb * 1024 * 1024) as usize,
            include_private: cfg.scanner.yara_memory_include_private,
            include_image: cfg.scanner.yara_memory_include_image,
            include_mapped: cfg.scanner.yara_memory_include_mapped,
            delay_ms: cfg.scanner.yara_memory_delay_ms,
        };
        Some(runtime_yara::spawn_yara_memory_worker(
            Arc::clone(&detectors),
            alert_sink.clone(),
            response_engine.clone(),
            mem_cfg,
            cfg.alerts.match_debug,
            mem_rx,
            Platform::MacOS,
            "yara-memory",
        ))
    } else {
        None
    };

    // 10. IOC hash background worker
    let (ioc_hash_tx, mut ioc_hash_worker_handle) = if ioc_engine.is_enabled() {
        let (hash_tx, hash_rx) = mpsc::channel::<(String, u32)>(1000);
        let handle = runtime_ioc::spawn_ioc_hash_worker(
            Arc::clone(&detectors),
            alert_sink.clone(),
            response_engine.clone(),
            hash_rx,
            Platform::MacOS,
            "esf",
        );
        (Some(hash_tx), Some(handle))
    } else {
        (None, None)
    };

    // 11. Normalizer
    let normalizer = Arc::new(Normalizer::new(
        Arc::clone(&process_cache),
        Arc::clone(&sid_cache),
        Arc::clone(&dns_cache),
        Arc::clone(&connection_aggregator),
        cfg.network.aggregation_enabled,
    ));

    // 12. Detection handlers + router
    let sigma_handler = SigmaDetectionHandler {
        normalizer: Arc::clone(&normalizer),
        detectors: Arc::clone(&detectors),
        ioc_hash_tx,
        alert_sink: alert_sink.clone(),
        response_engine: response_engine.clone(),
    };
    let yara_handler = YaraEventHandler {
        tx: yara_tx,
        memory_tx: yara_memory_tx,
        allowlist_paths: yara_allowlist_paths,
    };
    let mut router_inner = SensorEventRouter::new();
    router_inner.register_handler(Box::new(sigma_handler));
    router_inner.register_handler(Box::new(yara_handler));
    let router = Arc::new(router_inner);

    // 13. macOS Endpoint Security sensor
    let sensor = Arc::new(EsfSensor::new());

    info!("Starting macOS sensor...");
    info!("Press Ctrl+C to stop gracefully");

    let (sensor_tx, mut sensor_rx) = mpsc::channel::<SensorEvent>(8192);
    let router_for_worker = Arc::clone(&router);
    let sensor_worker_handle = tokio::task::spawn_blocking(move || {
        while let Some(event) = sensor_rx.blocking_recv() {
            router_for_worker.route_event(&event);
        }
    });

    let sensor_clone = Arc::clone(&sensor);
    if let Err(e) = sensor_clone.start(sensor_tx) {
        error!("macOS sensor failed to start: {:#}", e);
        return Err(e);
    }

    // 14. Wait for Ctrl+C
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("Received Ctrl+C, shutting down"),
        Err(e) => error!("Failed to listen for Ctrl+C: {}", e),
    }
    sensor.shutdown();

    // Drain workers
    drop(router);
    drop(response_engine);
    let _ = sensor_worker_handle.await;
    let _ = yara_worker_handle.await;
    if let Some(h) = yara_memory_worker_handle {
        let _ = h.await;
    }
    if let Some(h) = ioc_hash_worker_handle.take() {
        let _ = h.await;
    }
    if let Some(h) = reload_poller_handle.take() {
        h.abort();
        let _ = h.await;
    }
    drop(reload_tx.take());
    if let Some(h) = reload_worker_handle.take() {
        let _ = h.await;
    }
    let _ = response_worker_handle.await;

    info!("Shutdown complete");
    Ok(())
}
