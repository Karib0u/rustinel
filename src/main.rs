//! Rustinel: Rust ETW Sentinel
//!
//! High-performance, memory-safe Windows endpoint detection agent.
//! Replicates YAMAGoya functionality without .NET runtime dependencies.

mod alerts;
mod collector;
mod config;
mod engine;
mod models;
mod normalizer;
mod scanner;
mod state;
mod utils;

use alerts::AlertSink;
use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use collector::{Collector, EventRouter};
use engine::{Engine, SigmaDetectionHandler};
use models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
    ProcessCreationFields,
};
use normalizer::Normalizer;
use scanner::YaraEventHandler;
use state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

#[cfg(windows)]
const SERVICE_NAME: &str = "Rustinel";
#[cfg(windows)]
const SERVICE_DISPLAY_NAME: &str = "Rustinel ETW Sentinel";
#[cfg(windows)]
const SERVICE_DESCRIPTION: &str = "High-performance endpoint detection agent";

#[derive(Parser)]
#[command(name = "rustinel")]
#[command(about = "High-Performance Rust EDR", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Override logging level (e.g., error, warn, info, debug, trace)
    #[arg(long, global = true, value_name = "LEVEL")]
    log_level: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in console mode (foreground)
    Run {
        /// Force console output
        #[arg(long)]
        console: bool,
    },
    /// Service management commands
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand, Copy, Clone)]
enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
}

enum ShutdownMode {
    Console,
    Service(watch::Receiver<bool>),
}

fn main() -> Result<()> {
    #[cfg(windows)]
    {
        if windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main).is_ok() {
            return Ok(());
        }
    }

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Run { console }) => run_console(console, cli.log_level),
        None => run_console(false, cli.log_level),
        Some(Commands::Service { action }) => handle_service_command(action),
    }
}

fn run_console(force_console: bool, log_level: Option<String>) -> Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_edr(ShutdownMode::Console, force_console, log_level))
}

#[cfg(windows)]
fn handle_service_command(action: ServiceAction) -> Result<()> {
    match action {
        ServiceAction::Install => install_service(),
        ServiceAction::Uninstall => uninstall_service(),
        ServiceAction::Start => start_service(),
        ServiceAction::Stop => stop_service(),
    }
}

#[cfg(not(windows))]
fn handle_service_command(_action: ServiceAction) -> Result<()> {
    Err(anyhow::anyhow!(
        "Service commands are only supported on Windows"
    ))
}

#[cfg(windows)]
fn install_service() -> Result<()> {
    use std::env;
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let exe_path = env::current_exe()?;
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    let _ = service.set_description(SERVICE_DESCRIPTION);
    println!("Service '{}' installed.", SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
fn uninstall_service() -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    println!("Service '{}' uninstalled.", SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
fn start_service() -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[std::ffi::OsString])?;
    println!("Service '{}' started.", SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
fn stop_service() -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;
    println!("Service '{}' stopped.", SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
extern "system" fn ffi_service_main(_args: u32, _raw_args: *mut *mut u16) {
    if let Err(err) = service_main() {
        eprintln!("Service error: {:?}", err);
    }
}

#[cfg(windows)]
fn service_main() -> Result<()> {
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

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
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

        let run_result = run_edr(ShutdownMode::Service(shutdown_rx), false, None).await;
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

/// Initialize dual-pipeline logging system
/// Returns WorkerGuards that MUST be kept alive for the duration of the program
fn init_logging(
    cfg: &config::AppConfig,
) -> (
    tracing_appender::non_blocking::WorkerGuard,
    tracing_appender::non_blocking::WorkerGuard,
    AlertSink,
) {
    if let Err(err) = std::fs::create_dir_all(&cfg.logging.directory)
        .with_context(|| format!("Failed to create log directory {:?}", cfg.logging.directory))
    {
        eprintln!("{}", err);
    }
    if let Err(err) = std::fs::create_dir_all(&cfg.alerts.directory).with_context(|| {
        format!(
            "Failed to create alerts directory {:?}",
            cfg.alerts.directory
        )
    }) {
        eprintln!("{}", err);
    }

    // 1. Operational Logs (Human Readable Text)
    let app_file = rolling::daily(&cfg.logging.directory, &cfg.logging.filename);
    let (app_writer, app_guard) = tracing_appender::non_blocking(app_file);

    let app_layer = fmt::layer()
        .with_writer(app_writer)
        .compact()
        .with_ansi(false)
        .with_target(true)
        .with_filter(EnvFilter::new(&cfg.logging.level)); // Respect configured log level

    // 2. Security Alerts (ECS NDJSON)
    let alert_file = rolling::daily(&cfg.alerts.directory, &cfg.alerts.filename);
    let (alert_writer, alert_guard) = tracing_appender::non_blocking(alert_file);
    let alert_sink = AlertSink::new(alert_writer);

    // 3. Console (Optional, for Dev)
    let console_layer = if cfg.logging.console_output {
        Some(
            fmt::layer()
                .compact()
                .with_target(false) // Hide target for cleaner output
                .with_filter(EnvFilter::new(&cfg.logging.level)),
        )
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(app_layer)
        .with(console_layer)
        .init();

    (app_guard, alert_guard, alert_sink)
}

// Native API FFI structures for NtQuerySystemInformation
#[cfg(windows)]
mod native_snapshot {
    use crate::utils::query_process_command_line_from_handle;
    use windows::Win32::Foundation::{CloseHandle, UNICODE_STRING};
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // System Information Class
    const SYSTEM_PROCESS_INFORMATION: u32 = 5;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004

    // Native API function declaration
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            SystemInformationClass: u32,
            SystemInformation: *mut u8,
            SystemInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }

    // SYSTEM_PROCESS_INFORMATION_FULL includes the fields we need at correct offsets
    #[repr(C)]
    #[allow(non_snake_case)]
    struct SystemProcessInformationFull {
        NextEntryOffset: u32,
        NumberOfThreads: u32,
        WorkingSetPrivateSize: i64,
        HardFaultCount: u32,
        NumberOfThreadsHighWatermark: u32,
        CycleTime: u64,
        CreateTime: i64, // CRITICAL: Windows FILETIME (100-nanosecond intervals since 1601)
        UserTime: i64,
        KernelTime: i64,
        ImageName: UNICODE_STRING,
        BasePriority: i32,
        UniqueProcessId: usize,
        InheritedFromUniqueProcessId: usize, // Parent PID
        HandleCount: u32,
        SessionId: u32,
        // ... rest of structure omitted for brevity
    }

    pub struct ProcessSnapshot {
        pub pid: u32,
        pub parent_pid: u32,
        pub creation_time: u64,
        pub image_name: String,
        pub full_path: Option<String>,
        pub command_line: Option<String>,
    }

    pub fn query_system_processes() -> Result<Vec<ProcessSnapshot>, Box<dyn std::error::Error>> {
        unsafe {
            // Start with 1MB buffer
            let mut buffer_size: u32 = 1024 * 1024;
            let mut buffer: Vec<u8>;
            let mut return_length: u32 = 0;

            // Loop until we have a large enough buffer
            loop {
                buffer = vec![0u8; buffer_size as usize];
                let status = NtQuerySystemInformation(
                    SYSTEM_PROCESS_INFORMATION,
                    buffer.as_mut_ptr(),
                    buffer_size,
                    &mut return_length,
                );

                if status == 0 {
                    // STATUS_SUCCESS
                    break;
                } else if status == STATUS_INFO_LENGTH_MISMATCH {
                    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
                    buffer_size = return_length + 4096; // Add some extra space
                    continue;
                } else {
                    return Err(format!(
                        "NtQuerySystemInformation failed with status: {:#x}",
                        status
                    )
                    .into());
                }
            }

            let mut processes = Vec::new();
            let mut offset = 0usize;

            loop {
                let entry_ptr = buffer.as_ptr().add(offset) as *const SystemProcessInformationFull;
                let entry = &*entry_ptr;

                let pid = entry.UniqueProcessId as u32;
                let parent_pid = entry.InheritedFromUniqueProcessId as u32;

                // Convert CreateTime from i64 to u64 (FILETIME)
                // CRITICAL: This is the kernel creation time, matching future ETW events
                let creation_time = if entry.CreateTime > 0 {
                    entry.CreateTime as u64
                } else {
                    // For System Idle Process (PID 0) and possibly System (PID 4)
                    0
                };

                // Extract image name from UNICODE_STRING
                let image_name = if !entry.ImageName.Buffer.is_null() && entry.ImageName.Length > 0
                {
                    let slice = std::slice::from_raw_parts(
                        entry.ImageName.Buffer.as_ptr(),
                        (entry.ImageName.Length / 2) as usize,
                    );
                    String::from_utf16_lossy(slice)
                } else {
                    // System Idle Process has no name
                    String::from("System Idle Process")
                };

                // Hybrid Path Resolution: Try to get full path and command line via OpenProcess
                let (full_path, command_line) = if pid > 4 {
                    // Skip System Idle Process (0) and System (4)
                    match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                        Ok(handle) if !handle.is_invalid() => {
                            let mut path_buffer = [0u16; 1024]; // Increased buffer size
                            let len = K32GetProcessImageFileNameW(handle, &mut path_buffer);
                            let full_path = if len > 0 {
                                Some(String::from_utf16_lossy(&path_buffer[..len as usize]))
                            } else {
                                None
                            };

                            let command_line = query_process_command_line_from_handle(handle);
                            let _ = CloseHandle(handle);

                            (full_path, command_line)
                        }
                        _ => (None, None),
                    }
                } else {
                    (None, None)
                };

                processes.push(ProcessSnapshot {
                    pid,
                    parent_pid,
                    creation_time,
                    image_name: image_name.clone(),
                    full_path,
                    command_line,
                });

                // Move to next entry
                if entry.NextEntryOffset == 0 {
                    break;
                }
                offset += entry.NextEntryOffset as usize;
            }

            Ok(processes)
        }
    }
}

/// Snapshot all running processes using Native API (NtQuerySystemInformation)
/// This provides accurate CreateTime values that match ETW events
#[cfg(windows)]
fn snapshot_processes(cache: &ProcessCache) -> Result<usize> {
    use utils::{convert_nt_to_dos, parse_metadata};

    let processes = native_snapshot::query_system_processes()
        .map_err(|e| anyhow::anyhow!("Failed to query system processes: {}", e))?;

    let mut count = 0;
    for proc in processes {
        // Get raw image path (may be in NT Device format from K32GetProcessImageFileNameW)
        let raw_image = proc.full_path.unwrap_or_else(|| proc.image_name.clone());

        // Step 1: Normalize path (NT Device -> DOS)
        let image = convert_nt_to_dos(&raw_image);

        // Step 2: Parse PE metadata
        let (original_filename, product, description) =
            if let Some(metadata) = parse_metadata(&image) {
                (
                    metadata.original_filename,
                    metadata.product,
                    metadata.description,
                )
            } else {
                (None, None, None)
            };

        // Add to cache with compound key (PID, CreationTime), normalized path, and PE metadata
        // Parent info is not available during cold start, will be enriched on next process spawn
        cache.add(
            proc.pid,
            proc.creation_time,
            image,
            proc.command_line,
            None,
            Some(proc.parent_pid),
            None, // Parent image will be enriched later
            None, // Parent command line will be enriched later
            original_filename,
            product,
            description,
            None,
            None,
            None,
            None,
        );
        count += 1;
    }

    Ok(count)
}

fn now_timestamp_string() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn build_yara_alert(rule_name: &str, path: &str, pid: u32) -> Alert {
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: rule_name.to_string(),
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: now_timestamp_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(path.to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some(pid.to_string()),
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        },
    }
}

fn spawn_shutdown_handler(
    shutdown_mode: ShutdownMode,
    collector: Arc<Collector>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match shutdown_mode {
            ShutdownMode::Console => match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    info!("Received Ctrl+C signal");
                    collector.shutdown();
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
                collector.shutdown();
            }
        }
    })
}

async fn run_edr(
    shutdown_mode: ShutdownMode,
    force_console: bool,
    log_level_override: Option<String>,
) -> Result<()> {
    // 1. Load Configuration
    let mut cfg = match config::AppConfig::new() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Failed to load configuration: {}", err);
            eprintln!("Hint: check config.toml and EDR__* environment overrides.");
            return Err(anyhow::anyhow!("Failed to load configuration: {}", err));
        }
    };
    if force_console {
        cfg.logging.console_output = true;
    }
    if let Some(level) = log_level_override {
        if !level.trim().is_empty() {
            cfg.logging.level = level;
        }
    }

    // 2. Initialize Logging (CRITICAL: Store guards to keep file writing alive)
    let (app_guard, alert_guard, alert_sink) = init_logging(&cfg);
    let _guards = (app_guard, alert_guard);

    info!(target: "rustinel", "╔═══════════════════════════════════════════════════╗");
    info!(target: "rustinel", "║       Rustinel ETW Sentinel v0.1.0                ║");
    info!(target: "rustinel", "║   High-Performance Endpoint Detection Agent       ║");
    info!(target: "rustinel", "╚═══════════════════════════════════════════════════╝");
    info!(
        target: "rustinel",
        logs_dir = ?cfg.logging.directory,
        alerts_dir = ?cfg.alerts.directory,
        "Agent started with dual-pipeline logging"
    );

    // Verify running with appropriate privileges
    #[cfg(windows)]
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
    #[cfg(windows)]
    {
        match snapshot_processes(&process_cache) {
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

    let collector = Arc::new(Collector::new());

    // Initialize Sigma engine
    let mut sigma_engine = Engine::new_with_logging_level(&cfg.logging.level);

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
                "Sigma Engine initialized"
            );
            for (category, count) in stats.rules_by_category {
                info!(target: "rustinel", category = %category, count = count, "Sigma rules loaded");
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

    // Create background worker channel for YARA scanning
    // Buffer = 1000 items. If 1000 processes start instantly, we drop events rather than blocking.
    let (tx, mut rx) = mpsc::channel::<(String, u32)>(1000);

    // Spawn the background worker task for YARA scanning
    let scanner_clone = Arc::clone(&yara_scanner);
    let alert_sink_for_yara = alert_sink.clone();
    let yara_worker_handle = tokio::spawn(async move {
        info!("YARA Worker thread started and waiting for files to scan");
        while let Some((path, pid)) = rx.recv().await {
            debug!(
                "YARA Worker: Received file to scan: {} (PID: {})",
                path, pid
            );

            // This blocks the WORKER thread, not the ETW thread. Perfect.
            match scanner_clone.scan_file(&path) {
                Ok(matches) => {
                    if !matches.is_empty() {
                        warn!(
                            pid = pid,
                            file = %path,
                            rules = ?matches,
                            "YARA detection triggered"
                        );

                        // ECS NDJSON output
                        for rule in &matches {
                            let alert = build_yara_alert(rule, &path, pid);
                            alert_sink_for_yara.write_alert(&alert);
                        }
                    } else {
                        debug!("YARA Worker: No matches for {}", path);
                    }
                }
                Err(e) => {
                    debug!("YARA Worker: Failed to scan {} - {}", path, e);
                }
            }
        }
        info!("YARA Worker thread shutting down");
    });

    // Initialize normalizer with process cache and connection aggregator
    let normalizer = Arc::new(Normalizer::new(
        Arc::clone(&process_cache),
        Arc::clone(&sid_cache),
        Arc::clone(&dns_cache),
        Arc::clone(&connection_aggregator),
        cfg.network.aggregation_enabled,
    ));

    info!("✓ Collector initialized");
    info!("✓ Normalizer initialized");

    // Create Sigma detection handler
    let sigma_handler = SigmaDetectionHandler {
        normalizer: Arc::clone(&normalizer),
        engine: Arc::clone(&sigma_engine),
        alert_sink: alert_sink.clone(),
    };

    // Create YARA event handler
    let yara_handler = YaraEventHandler { tx };

    // Setup EventRouter (mutable)
    let mut router_inner = EventRouter::new();
    router_inner.register_handler(Box::new(sigma_handler));
    router_inner.register_handler(Box::new(yara_handler));

    // Freeze router (immutable/shared)
    let router = Arc::new(router_inner);

    info!("✓ Event Router initialized");
    info!("✓ Event handlers registered");

    // Setup graceful shutdown handler
    let shutdown_handler = spawn_shutdown_handler(shutdown_mode, Arc::clone(&collector));

    info!("✓ Signal handlers configured");
    info!("");
    info!("Starting ETW trace session...");
    info!("Press Ctrl+C to stop gracefully");
    info!("");

    // Start ETW trace session
    let router_clone = Arc::clone(&router);
    let collector_clone = Arc::clone(&collector);

    // We make trace_handle mutable so we can await it
    let mut trace_handle = tokio::task::spawn_blocking(move || {
        let result = collector_clone.start(move |record| {
            // Debug: Log that callback was invoked
            tracing::trace!(
                "Callback invoked - Provider: {:?}, Event ID: {}, OpCode: {}",
                record.provider_id(),
                record.event_id(),
                record.opcode()
            );

            // Route event to handlers (lock-free!)
            router_clone.route_event(record);
        });

        if let Err(e) = result {
            error!("ETW trace session error: {}", e);
        }
    });

    // Wait for either shutdown signal or trace completion
    // We use a pattern that ensures we wait for the trace to finish
    tokio::select! {
        _ = shutdown_handler => {
            info!("Shutdown signal received, waiting for ETW session to close...");

            // Wait for the trace thread to finish cleanly
            // collector.shutdown() has already been called by the signal handler
            match trace_handle.await {
                Ok(_) => info!("ETW trace thread finished"),
                Err(e) => error!("Failed to join trace thread: {}", e),
            }

            // Shutdown YARA worker: Drop the router (which holds tx sender)
            // This causes rx.recv() to return None, breaking the worker loop
            drop(router);
            info!("Signaling YARA worker to shut down...");

            match yara_worker_handle.await {
                Ok(_) => info!("YARA worker thread finished"),
                Err(e) => error!("Failed to join YARA worker thread: {}", e),
            }
        }
        // CRITICAL: If trace finishes unexpectedly, the collector died!
        // This means the agent is "blind" - still running but not collecting events.
        result = &mut trace_handle => {
            // Check if this was a graceful shutdown before treating it as an error
            if collector.is_shutdown() {
                info!("ETW trace thread finished after shutdown request");

                // Shutdown YARA worker even in this path
                drop(router);
                info!("Signaling YARA worker to shut down...");
                match yara_worker_handle.await {
                    Ok(_) => info!("YARA worker thread finished"),
                    Err(e) => error!("Failed to join YARA worker thread: {}", e),
                }
            } else {
                error!("🚨 CRITICAL: ETW Collector thread died unexpectedly!");
                match result {
                    Ok(_) => {
                        // Thread completed without panic, but shouldn't have finished on its own
                        error!("Trace stopped without panic (unexpected normal termination)");
                        error!("This indicates the ETW session closed unexpectedly");
                    },
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
                    },
                }
                // Force exit so Service Manager/Watchdog restarts the agent
                // Without this, the agent appears "Online" but is blind to events
                error!("Forcing process exit to trigger restart...");
                std::process::exit(1);
            }
        }
    }

    info!("");
    info!("╔═══════════════════════════════════════════════════╗");
    info!("║           Shutdown Complete                       ║");
    info!("║        Thank you for using Rustinel!              ║");
    info!("╚═══════════════════════════════════════════════════╝");

    Ok(())
}
