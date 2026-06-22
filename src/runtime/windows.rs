use crate::alerts::dedup::{spawn_flush_worker, Deduplicator};
use crate::engine::{Engine, SigmaDetectionHandler};
use crate::ioc::IocEngine;
use crate::memory::MemoryScanConfig;
use crate::normalizer::Normalizer;
use crate::reload::DetectorStore;
use crate::response::ResponseEngine;
use crate::runtime::logging::{init_logging, log_startup_banner};
use crate::runtime::{ioc as runtime_ioc, yara as runtime_yara};
use crate::scanner::{YaraEventHandler, YaraMemoryJob};
use crate::sensor::windows::EtwSensor;
use crate::sensor::{Platform, Sensor, SensorEvent, SensorEventRouter};
use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
use crate::{config, reload, scanner};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

enum ShutdownMode {
    Console,
    Service(watch::Receiver<bool>),
}

pub fn run_console(console_output: bool, log_level: Option<String>) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_edr(
        ShutdownMode::Console,
        Some(console_output),
        log_level,
    ))
}

pub extern "system" fn ffi_service_main(_args: u32, _raw_args: *mut *mut u16) {
    if let Err(err) = service_main() {
        eprintln!("Service error: {:?}", err);
    }
}

fn service_main() -> anyhow::Result<()> {
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx = Arc::new(shutdown_tx);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle =
        service_control_handler::register(crate::platform::windows::SERVICE_NAME, event_handler)?;
    let status_handle = Arc::new(status_handle);

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    let runtime = Builder::new_multi_thread().enable_all().build()?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    let status_handle_for_stop = Arc::clone(&status_handle);
    let mut stop_rx = shutdown_rx.clone();

    let result = runtime.block_on(async move {
        let stop_task = tokio::spawn(async move {
            if stop_rx.changed().await.is_ok() {
                let _ = status_handle_for_stop.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::StopPending,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 1,
                    wait_hint: Duration::from_secs(10),
                    process_id: None,
                });
            }
        });

        let run_result = run_edr(ShutdownMode::Service(shutdown_rx), None, None).await;
        stop_task.abort();
        let _ = stop_task.await;
        run_result
    });

    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    })?;

    result
}

fn spawn_shutdown_handler(
    shutdown_mode: ShutdownMode,
    sensor: Arc<EtwSensor>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match shutdown_mode {
            ShutdownMode::Console => match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    info!("Received Ctrl+C signal");
                    sensor.shutdown();
                }
                Err(err) => {
                    error!("Failed to listen for Ctrl+C: {}", err);
                }
            },
            ShutdownMode::Service(mut shutdown_rx) => {
                if shutdown_rx.changed().await.is_ok() {
                    info!("Received service stop signal");
                } else {
                    warn!("Service shutdown channel dropped");
                }
                sensor.shutdown();
            }
        }
    })
}

async fn run_edr(
    shutdown_mode: ShutdownMode,
    console_output_override: Option<bool>,
    log_level_override: Option<String>,
) -> anyhow::Result<()> {
    // 1. Load Configuration
    let mut cfg = match config::AppConfig::new() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Failed to load configuration: {}", err);
            eprintln!("Hint: check config.toml and EDR__* environment overrides.");
            return Err(anyhow::anyhow!("Failed to load configuration: {}", err));
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

    // 2. Initialize Logging (CRITICAL: Store guards to keep file writing alive)
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

    log_startup_banner("Windows ETW");

    // 2.1 Initialize Active Response Engine (optional)
    let (response_engine, response_worker_handle) = ResponseEngine::new(&cfg.response);
    info!(
        target: "rustinel",
        logs_dir = ?cfg.logging.directory,
        alerts_dir = ?cfg.alerts.directory,
        "Agent started with dual-pipeline logging"
    );

    // Verify running with appropriate privileges
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
                let mut elevation = TOKEN_ELEVATION::default();
                let mut return_length = 0u32;

                if GetTokenInformation(
                    token,
                    TokenElevation,
                    Some(&mut elevation as *mut _ as *mut _),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut return_length,
                )
                .is_ok()
                {
                    if elevation.TokenIsElevated == 0 {
                        error!("❌ ERROR: This application requires Administrator privileges!");
                        error!("   Please run as Administrator to access ETW providers.");
                        return Err(anyhow::anyhow!(
                            "Insufficient privileges - Administrator access required"
                        ));
                    } else {
                        info!("✓ Running with Administrator privileges");
                    }
                }
            }
        }
    }

    // Initialize modules
    info!("Initializing modules...");

    // Initialize Process Cache and perform cold start snapshot
    info!("Initializing Process Cache...");
    let process_cache = Arc::new(ProcessCache::new());
    let sid_cache = Arc::new(SidCache::new());
    let dns_cache = Arc::new(DnsCache::new());
    let connection_aggregator = Arc::new(ConnectionAggregator::with_limits(
        cfg.network.aggregation_max_entries,
        cfg.network.aggregation_interval_buffer_size,
    ));

    // Snapshot existing processes using Windows API (handles cold start problem)
    {
        match crate::platform::windows::snapshot_processes(&process_cache) {
            Ok(count) => {
                info!(
                    "✓ Process Cache initialized with {} existing processes",
                    count
                );
            }
            Err(e) => {
                warn!(
                    "Failed to snapshot processes: {}. Cache will populate from ETW events.",
                    e
                );
            }
        }
    }

    #[cfg(not(windows))]
    {
        info!("Process snapshot not available on non-Windows platforms");
    }

    let sensor = Arc::new(EtwSensor::new());

    // Initialize Sigma engine
    let mut sigma_engine = Engine::new_for_platform_with_logging_level_and_match_debug(
        Platform::Windows,
        &cfg.logging.level,
        cfg.alerts.match_debug,
    );

    if cfg.scanner.sigma_enabled {
        info!(
            target: "rustinel",
            rules_path = ?cfg.scanner.sigma_rules_path,
            "Loading Sigma rules"
        );

        if let Err(e) = sigma_engine.load_rules(&cfg.scanner.sigma_rules_path) {
            warn!(target: "rustinel", error = %e, "Failed to load Sigma rules");
        } else {
            let stats = sigma_engine.stats();
            info!(
                target: "rustinel",
                total_rules = stats.total_rules,
                skipped_deferred_rules = stats.skipped_deferred_rules,
                skipped_unknown_logsource_rules = stats.skipped_unknown_logsource_rules,
                skipped_product_rules = stats.skipped_product_rules,
                inactive_collector_rules = stats.inactive_collector_rules,
                "Sigma Engine initialized"
            );
            for (logsource, count) in stats.rules_by_logsource {
                info!(target: "rustinel", logsource = %logsource, count = count, "Sigma rules loaded");
            }
        }
    } else {
        info!(target: "rustinel", "Sigma detection disabled by configuration");
    }
    let sigma_engine = Arc::new(sigma_engine);

    // Initialize YARA Scanner
    let yara_scanner = if cfg.scanner.yara_enabled {
        info!(
            target: "rustinel",
            rules_path = ?cfg.scanner.yara_rules_path,
            "Initializing YARA Scanner"
        );

        match scanner::Scanner::new(&cfg.scanner.yara_rules_path) {
            Ok(s) => {
                info!(target: "rustinel", "YARA Scanner initialized successfully");
                Arc::new(s)
            }
            Err(e) => {
                warn!(target: "rustinel", error = %e, "Failed to load YARA rules. YARA scanning disabled.");
                // Create an empty scanner so we don't crash
                Arc::new(
                    scanner::Scanner::new(Path::new("."))
                        .expect("Failed to create empty YARA scanner"),
                )
            }
        }
    } else {
        info!(target: "rustinel", "YARA scanning disabled by configuration");
        Arc::new(
            scanner::Scanner::new(Path::new(".")).expect("Failed to create empty YARA scanner"),
        )
    };

    let yara_allowlist_paths =
        scanner::normalize_allowlist_paths(&cfg.scanner.yara_allowlist_paths);
    if !yara_allowlist_paths.is_empty() {
        info!(
            target: "rustinel",
            count = yara_allowlist_paths.len(),
            "YARA allowlist paths loaded (files under these paths will NOT be scanned)"
        );
    }

    // Initialize IOC engine
    let ioc_engine = Arc::new(IocEngine::load(&cfg.ioc));
    if ioc_engine.is_enabled() {
        let stats = ioc_engine.stats();
        info!(
            target: "rustinel",
            md5 = stats.md5,
            sha1 = stats.sha1,
            sha256 = stats.sha256,
            ip = stats.ip,
            cidr = stats.cidr,
            domain_exact = stats.domain_exact,
            domain_suffix = stats.domain_suffix,
            path_regex = stats.path_regex,
            "IOC engine initialized"
        );
    } else {
        info!(target: "rustinel", "IOC detection disabled by configuration");
    }

    let detectors = DetectorStore::new(
        Arc::clone(&sigma_engine),
        Arc::clone(&yara_scanner),
        Arc::clone(&ioc_engine),
    );

    // Create background worker channel for YARA scanning
    // Buffer = 1000 items. If 1000 processes start instantly, we drop events rather than blocking.
    let (yara_tx, yara_worker_handle) = if cfg.scanner.yara_enabled {
        let (tx, rx) = mpsc::channel::<(String, u32)>(1000);
        let handle = runtime_yara::spawn_yara_file_worker(
            Arc::clone(&detectors),
            alert_sink.clone(),
            response_engine.clone(),
            cfg.alerts.match_debug,
            rx,
            yara_allowlist_paths.clone(),
            Platform::Windows,
            "etw",
        );
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    // Create optional YARA memory scanning channel.
    let (yara_memory_tx, yara_memory_rx) =
        if cfg.scanner.yara_enabled && cfg.scanner.yara_memory_enabled {
            let capacity = cfg.scanner.yara_memory_queue_capacity.max(1);
            let (tx, rx) = mpsc::channel::<YaraMemoryJob>(capacity);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

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
    } else {
        info!(target: "reload", "Hot-reload disabled by configuration");
    }

    // Spawn optional YARA memory scanning worker.
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
            Platform::Windows,
            "yara-memory",
        ))
    } else {
        None
    };

    // Create background worker channel for IOC hashing (process start only)
    // Uses spawn_blocking to avoid starving the tokio async thread pool with
    // CPU-bound crypto work and synchronous file I/O.
    let (ioc_hash_tx, mut ioc_hash_worker_handle) = if ioc_engine.is_enabled() {
        let (hash_tx, hash_rx) = mpsc::channel::<(String, u32)>(1000);
        let hash_worker_handle = runtime_ioc::spawn_ioc_hash_worker(
            Arc::clone(&detectors),
            alert_sink.clone(),
            response_engine.clone(),
            hash_rx,
            Platform::Windows,
            "etw",
        );

        (Some(hash_tx), Some(hash_worker_handle))
    } else {
        (None, None)
    };

    // Initialize normalizer with process cache and connection aggregator
    let normalizer = Arc::new(Normalizer::new(
        Arc::clone(&process_cache),
        Arc::clone(&sid_cache),
        Arc::clone(&dns_cache),
        Arc::clone(&connection_aggregator),
        cfg.network.aggregation_enabled,
    ));

    info!("✓ ETW sensor initialized");
    info!("✓ Normalizer initialized");

    // Create Sigma detection handler
    let sigma_handler = SigmaDetectionHandler {
        normalizer: Arc::clone(&normalizer),
        detectors: Arc::clone(&detectors),
        ioc_hash_tx,
        alert_sink: alert_sink.clone(),
        response_engine: response_engine.clone(),
    };

    // Create YARA event handler
    let yara_handler = if cfg.scanner.yara_enabled {
        let yara_handler = YaraEventHandler {
            tx: yara_tx.expect("yara_tx exists when enabled"),
            memory_tx: yara_memory_tx,
            allowlist_paths: yara_allowlist_paths,
        };
        Some(yara_handler)
    } else {
        None
    };

    // Setup shared SensorEventRouter (mutable)
    let mut router_inner = SensorEventRouter::new();
    router_inner.register_handler(Box::new(sigma_handler));
    if let Some(yh) = yara_handler {
        router_inner.register_handler(Box::new(yh));
    }

    // Freeze router (immutable/shared)
    let router = Arc::new(router_inner);

    info!("✓ Event Router initialized");
    info!("✓ Event handlers registered");

    // Setup graceful shutdown handler
    let shutdown_handler = spawn_shutdown_handler(shutdown_mode, Arc::clone(&sensor));

    info!("✓ Signal handlers configured");
    info!("");
    info!("Starting ETW trace session...");
    info!("Press Ctrl+C to stop gracefully");
    info!("");

    // Start shared sensor event pipeline
    let (sensor_tx, mut sensor_rx) = mpsc::channel::<SensorEvent>(8192);
    let router_clone = Arc::clone(&router);
    let sensor_worker_handle = tokio::task::spawn_blocking(move || {
        info!(target: "sensor", "Sensor event worker thread started");
        while let Some(event) = sensor_rx.blocking_recv() {
            router_clone.route_event(&event);
        }
        info!(target: "sensor", "Sensor event worker thread shutting down");
    });

    let sensor_clone = Arc::clone(&sensor);

    // We make trace_handle mutable so we can await it.
    let mut trace_handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = sensor_clone.start(sensor_tx) {
            error!("ETW sensor error: {}", e);
        }
    });

    // Wait for either shutdown signal or trace completion.
    tokio::select! {
        _ = shutdown_handler => {
            info!("Shutdown signal received, waiting for ETW session to close...");
            match trace_handle.await {
                Ok(_) => info!("ETW sensor thread finished"),
                Err(e) => error!("Failed to join ETW sensor thread: {}", e),
            }
        }
        // CRITICAL: If trace finishes unexpectedly, the ETW sensor died.
        // This means the agent is "blind" - still running but not collecting events.
        result = &mut trace_handle => {
            if sensor.is_shutdown() {
                info!("ETW sensor thread finished after shutdown request");
            } else {
                error!("🚨 CRITICAL: ETW sensor thread died unexpectedly!");
                match result {
                    Ok(_) => {
                        error!("Trace stopped without panic (unexpected normal termination)");
                        error!("This indicates the ETW session closed unexpectedly");
                    }
                    Err(join_err) => {
                        if join_err.is_panic() {
                            error!("🔥 PANIC: Trace thread PANICKED!");
                            // Try to extract panic message (into_panic consumes join_err)
                            let panic_info = join_err.into_panic();
                            if let Some(panic_msg) = panic_info.downcast_ref::<&str>() {
                                error!("Panic message: {}", panic_msg);
                            } else if let Some(panic_msg) = panic_info.downcast_ref::<String>() {
                                error!("Panic message: {}", panic_msg);
                            } else {
                                error!("Panic message: <unable to extract>");
                            }
                        } else {
                            error!("Trace thread cancelled/failed: {}", join_err);
                        }
                    }
                }
                // Force exit so Service Manager/Watchdog restarts the agent
                // Without this, the agent appears "Online" but is blind to events
                error!("Forcing process exit to trigger restart...");
                std::process::exit(1);
            }
        }
    }

    // Common teardown (not reached if exit(1) above)
    match sensor_worker_handle.await {
        Ok(_) => info!("Sensor event worker thread finished"),
        Err(e) => error!("Failed to join sensor event worker thread: {}", e),
    }

    drop(router);
    drop(response_engine);
    if let Some(handle) = yara_worker_handle {
        info!("Signaling YARA worker to shut down...");
        match handle.await {
            Ok(_) => info!("YARA worker thread finished"),
            Err(e) => error!("Failed to join YARA worker thread: {}", e),
        }
    }

    if let Some(handle) = yara_memory_worker_handle {
        match handle.await {
            Ok(_) => info!("YARA memory worker thread finished"),
            Err(e) => error!("Failed to join YARA memory worker thread: {}", e),
        }
    }

    if let Some(handle) = ioc_hash_worker_handle.take() {
        info!("Signaling IOC hash worker to shut down...");
        match handle.await {
            Ok(_) => info!("IOC hash worker thread finished"),
            Err(e) => error!("Failed to join IOC hash worker thread: {}", e),
        }
    }

    if let Some(handle) = reload_poller_handle.take() {
        info!("Signaling hot-reload poller to shut down...");
        handle.abort();
        let _ = handle.await;
        info!("Hot-reload poller thread finished");
    }
    drop(reload_tx.take());
    if let Some(handle) = reload_worker_handle.take() {
        info!("Signaling hot-reload worker to shut down...");
        match handle.await {
            Ok(_) => info!("Hot-reload worker thread finished"),
            Err(e) => error!("Failed to join hot-reload worker thread: {}", e),
        }
    }

    info!("Signaling response worker to shut down...");
    match response_worker_handle.await {
        Ok(_) => info!("Response worker thread finished"),
        Err(e) => error!("Failed to join response worker thread: {}", e),
    }

    // Flush any pending dedup rollups before the alert file is closed.
    if let Some(handle) = dedup_worker_handle {
        handle.abort();
        let _ = handle.await;
    }
    if let Some(dedup) = alert_sink.dedup() {
        dedup.flush_all(&alert_sink);
        dedup.log_metrics();
    }

    info!("");
    info!("╔═══════════════════════════════════════════════════╗");
    info!("║           Shutdown Complete                       ║");
    info!("║        Thank you for using Rustinel!              ║");
    info!("╚═══════════════════════════════════════════════════╝");

    Ok(())
}
