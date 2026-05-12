//! Rustinel: Open-source EDR for Windows and Linux, written in Rust.
//!
//! On Windows, telemetry is collected via ETW. On Linux, eBPF programs are
//! loaded via Aya. Both paths feed a shared userspace pipeline for Sigma,
//! YARA, and IOC detection, with alerts written as ECS NDJSON.

// ── Platform-shared imports ───────────────────────────────────────────────────
#[cfg(any(windows, target_os = "linux"))]
use rustinel::engine::{Engine, SigmaDetectionHandler};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::ioc::{HashCache, HashRequirements, IocEngine};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::memory::MemoryScanConfig;
#[cfg(any(windows, target_os = "linux"))]
use rustinel::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, MatchDebugLevel,
    MatchDetails, NormalizedEvent, ProcessCreationFields, YaraMatchDetails, YaraRuleMatch,
};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::normalizer::Normalizer;
#[cfg(any(windows, target_os = "linux"))]
use rustinel::reload::DetectorStore;
#[cfg(any(windows, target_os = "linux"))]
use rustinel::response::ResponseEngine;
#[cfg(any(windows, target_os = "linux"))]
use rustinel::runtime::logging::{init_logging, log_startup_banner};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::scanner::{YaraEventHandler, YaraMemoryJob};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::sensor::{Platform, Sensor, SensorEvent, SensorEventRouter};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::utils::{self, LogRateLimiter};
#[cfg(any(windows, target_os = "linux"))]
use rustinel::{config, memory, reload, scanner};
#[cfg(any(windows, target_os = "linux"))]
use std::path::Path;
#[cfg(any(windows, target_os = "linux"))]
use std::sync::Arc;
#[cfg(any(windows, target_os = "linux"))]
use std::time::Duration;
#[cfg(any(windows, target_os = "linux"))]
use tracing::{debug, error, info, warn};

// ── Platform-specific imports ─────────────────────────────────────────────────
#[cfg(windows)]
use rustinel::sensor::windows::EtwSensor;
#[cfg(windows)]
use tokio::runtime::Builder;
#[cfg(windows)]
use tokio::sync::{mpsc, watch};

#[cfg(target_os = "linux")]
use rustinel::sensor::linux::EbpfSensor;
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;

#[cfg(windows)]
const SERVICE_NAME: &str = "Rustinel";
#[cfg(windows)]
const SERVICE_DISPLAY_NAME: &str = "Rustinel ETW Sentinel";
#[cfg(windows)]
const SERVICE_DESCRIPTION: &str = "High-performance endpoint detection agent";

#[cfg(any(windows, target_os = "linux"))]
const WORKER_DEBUG_LOG_WINDOW_SECS: u64 = 30;
#[derive(clap::Parser)]
#[command(name = "rustinel")]
#[command(version)]
#[command(about = "High-Performance Rust EDR", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Override logging level (e.g., error, warn, info, debug, trace)
    #[arg(long, global = true, value_name = "LEVEL")]
    log_level: Option<String>,
}

#[derive(clap::Subcommand)]
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

#[derive(clap::Subcommand, Copy, Clone)]
enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
}

#[cfg(windows)]
enum ShutdownMode {
    Console,
    Service(watch::Receiver<bool>),
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    if windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main).is_ok() {
        return Ok(());
    }

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Run { console }) => run_console(console, cli.log_level),
        None => run_console(false, cli.log_level),
        Some(Commands::Service { action }) => handle_service_command(action),
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Service { action }) => handle_service_command(action),
        Some(Commands::Run { .. }) | None => run_linux(),
    }
}

#[cfg(target_os = "linux")]
fn run_linux() -> anyhow::Result<()> {
    use tokio::runtime::Builder;
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_linux_edr())
}

// Catch-all for non-Windows, non-Linux platforms.
#[cfg(not(any(windows, target_os = "linux")))]
fn main() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "This platform is not supported. Rustinel runs on Windows (ETW) and Linux (eBPF)."
    ))
}

#[cfg(windows)]
fn run_console(force_console: bool, log_level: Option<String>) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_edr(ShutdownMode::Console, force_console, log_level))
}

#[cfg(windows)]
fn handle_service_command(action: ServiceAction) -> anyhow::Result<()> {
    match action {
        ServiceAction::Install => install_service(),
        ServiceAction::Uninstall => uninstall_service(),
        ServiceAction::Start => start_service(),
        ServiceAction::Stop => stop_service(),
    }
}

#[cfg(not(windows))]
fn handle_service_command(_action: ServiceAction) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "Service commands are only supported on Windows"
    ))
}

#[cfg(windows)]
fn install_service() -> anyhow::Result<()> {
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
fn uninstall_service() -> anyhow::Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    println!("Service '{}' uninstalled.", SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
fn start_service() -> anyhow::Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[std::ffi::OsString])?;
    println!("Service '{}' started.", SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
fn stop_service() -> anyhow::Result<()> {
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

// ── Shared YARA helpers ───────────────────────────────────────────────────────

#[cfg(any(windows, target_os = "linux"))]
fn build_yara_match_details(
    match_debug: MatchDebugLevel,
    rule_match: &YaraRuleMatch,
) -> Option<MatchDetails> {
    if matches!(match_debug, MatchDebugLevel::Off) {
        return None;
    }

    let summary = if matches!(match_debug, MatchDebugLevel::Full) {
        if let Some(first_string) = rule_match.strings.first() {
            if let Some(offset) = first_string.offset {
                format!(
                    "matched YARA rule {} via {} at 0x{:x}",
                    rule_match.rule, first_string.id, offset
                )
            } else {
                format!(
                    "matched YARA rule {} via {}",
                    rule_match.rule, first_string.id
                )
            }
        } else {
            format!("matched YARA rule {}", rule_match.rule)
        }
    } else {
        format!("matched YARA rule {}", rule_match.rule)
    };

    let mut rule = rule_match.clone();
    if !matches!(match_debug, MatchDebugLevel::Full) {
        rule.strings.clear();
    }

    Some(MatchDetails {
        summary,
        sigma: None,
        yara: Some(YaraMatchDetails { rules: vec![rule] }),
    })
}

#[cfg(any(windows, target_os = "linux"))]
fn build_yara_alert(
    rule_name: &str,
    path: &str,
    pid: u32,
    match_details: Option<MatchDetails>,
    platform: Platform,
    provider: &str,
) -> Alert {
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: rule_name.to_string(),
        rule_description: None,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: utils::now_timestamp_string(),
            platform,
            provider: provider.to_string(),
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
        match_details,
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn build_yara_memory_match_details(
    match_debug: MatchDebugLevel,
    rule_match: &YaraRuleMatch,
    chunk: &memory::MemoryChunk,
) -> Option<MatchDetails> {
    if matches!(match_debug, MatchDebugLevel::Off) {
        return None;
    }

    let summary = format!(
        "matched YARA rule {} in process memory at 0x{:x} {:?} {}{}{}",
        rule_match.rule,
        chunk.base,
        chunk.region.kind,
        if chunk.region.readable { 'r' } else { '-' },
        if chunk.region.writable { 'w' } else { '-' },
        if chunk.region.executable { 'x' } else { '-' },
    );

    let mut rule = rule_match.clone();
    if !matches!(match_debug, MatchDebugLevel::Full) {
        rule.strings.clear();
    }

    Some(MatchDetails {
        summary,
        sigma: None,
        yara: Some(YaraMatchDetails { rules: vec![rule] }),
    })
}

#[cfg(any(windows, target_os = "linux"))]
fn build_yara_memory_alert(
    rule_name: &str,
    image: &str,
    pid: u32,
    match_details: Option<MatchDetails>,
    platform: Platform,
    provider: &str,
) -> Alert {
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: rule_name.to_string(),
        rule_description: None,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: utils::now_timestamp_string(),
            platform,
            provider: provider.to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image.to_string()),
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
        match_details,
    }
}

// ── Windows ETW EDR ───────────────────────────────────────────────────────────

// Native API FFI structures for NtQuerySystemInformation
#[cfg(windows)]
mod native_snapshot {
    use rustinel::utils::query_process_command_line_from_handle;
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
fn snapshot_processes(cache: &ProcessCache) -> anyhow::Result<usize> {
    use rustinel::utils::{convert_nt_to_dos, parse_metadata};

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

#[cfg(windows)]
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

#[cfg(windows)]
async fn run_edr(
    shutdown_mode: ShutdownMode,
    force_console: bool,
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

    // Create background worker channel for YARA scanning
    // Buffer = 1000 items. If 1000 processes start instantly, we drop events rather than blocking.
    let (tx, mut rx) = mpsc::channel::<(String, u32)>(1000);

    // Create optional YARA memory scanning channel.
    let (yara_memory_tx, yara_memory_rx) =
        if cfg.scanner.yara_enabled && cfg.scanner.yara_memory_enabled {
            let capacity = cfg.scanner.yara_memory_queue_capacity.max(1);
            let (tx, rx) = mpsc::channel::<YaraMemoryJob>(capacity);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

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

    // Spawn the background worker task for YARA scanning
    let detectors_for_yara = Arc::clone(&detectors);
    let yara_allowlist_paths_for_worker = yara_allowlist_paths.clone();
    let alert_sink_for_yara = alert_sink.clone();
    let response_engine_for_yara = response_engine.clone();
    let match_debug = cfg.alerts.match_debug;
    let yara_worker_handle = tokio::task::spawn_blocking(move || {
        info!(
            target: "scanner",
            "YARA worker thread started and waiting for files to scan"
        );
        let mut scan_error_limiter =
            LogRateLimiter::new(Duration::from_secs(WORKER_DEBUG_LOG_WINDOW_SECS));
        while let Some((path, pid)) = rx.blocking_recv() {
            if scanner::is_path_allowlisted(&path, &yara_allowlist_paths_for_worker) {
                tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    file = %path,
                    "YARA worker skipping allowlisted path"
                );
                continue;
            }

            tracing::trace!(
                target: "scanner",
                pid = pid,
                file = %path,
                "YARA worker received file for scan"
            );

            let scanner = detectors_for_yara.yara();
            match scanner.scan_file(&path, match_debug) {
                Ok(matches) => {
                    if !matches.is_empty() {
                        let rule_names: Vec<String> =
                            matches.iter().map(|rule| rule.rule.clone()).collect();

                        warn!(
                            pid = pid,
                            file = %path,
                            rules = ?rule_names,
                            "YARA detection triggered"
                        );

                        // ECS NDJSON output
                        for rule_match in &matches {
                            let match_details = build_yara_match_details(match_debug, rule_match);
                            let alert = build_yara_alert(
                                &rule_match.rule,
                                &path,
                                pid,
                                match_details,
                                Platform::Windows,
                                "etw",
                            );
                            alert_sink_for_yara.write_alert(&alert);
                            response_engine_for_yara.handle_alert(&alert);
                        }
                    } else {
                        tracing::trace!(
                            target: "scanner",
                            pid = pid,
                            file = %path,
                            "YARA worker no matches"
                        );
                    }
                }
                Err(e) => {
                    let decision = scan_error_limiter.should_emit("scan_error");
                    if decision.should_emit {
                        debug!(
                            target: "scanner",
                            pid = pid,
                            file = %path,
                            error = %e,
                            suppressed = decision.suppressed_since_last_emit,
                            "YARA worker scan failure"
                        );
                    }
                }
            }
        }
        info!(target: "scanner", "YARA worker thread shutting down");
    });

    // Spawn optional YARA memory scanning worker.
    let yara_memory_worker_handle = if let Some(mut mem_rx) = yara_memory_rx {
        let detectors_for_mem = Arc::clone(&detectors);
        let alert_sink_for_mem = alert_sink.clone();
        let response_engine_for_mem = response_engine.clone();
        let mem_cfg = MemoryScanConfig {
            max_process_bytes: (cfg.scanner.yara_memory_max_process_mb * 1024 * 1024) as usize,
            max_region_bytes: (cfg.scanner.yara_memory_max_region_mb * 1024 * 1024) as usize,
            include_private: cfg.scanner.yara_memory_include_private,
            include_image: cfg.scanner.yara_memory_include_image,
            include_mapped: cfg.scanner.yara_memory_include_mapped,
            delay_ms: cfg.scanner.yara_memory_delay_ms,
        };
        let mem_match_debug = cfg.alerts.match_debug;
        Some(tokio::task::spawn_blocking(move || {
            info!(target: "scanner", "YARA memory worker started");
            while let Some(job) = mem_rx.blocking_recv() {
                std::thread::sleep(Duration::from_millis(mem_cfg.delay_ms));
                let chunks = match memory::read_process_memory_chunks(job.pid, &mem_cfg) {
                    Ok(c) => c,
                    Err(err) => {
                        tracing::trace!(
                            target: "scanner",
                            pid = job.pid,
                            image = %job.image,
                            error = %err,
                            "YARA memory scan skipped"
                        );
                        continue;
                    }
                };
                let scanner = detectors_for_mem.yara();
                for chunk in &chunks {
                    let matches = match scanner.scan_bytes(&chunk.bytes, mem_match_debug) {
                        Ok(m) => m,
                        Err(err) => {
                            tracing::trace!(
                                target: "scanner",
                                pid = job.pid,
                                error = %err,
                                "YARA memory chunk scan failed"
                            );
                            continue;
                        }
                    };
                    if !matches.is_empty() {
                        let rule_names: Vec<String> =
                            matches.iter().map(|r| r.rule.clone()).collect();
                        warn!(
                            pid = job.pid,
                            image = %job.image,
                            rules = ?rule_names,
                            "YARA memory detection triggered"
                        );
                        for rule_match in &matches {
                            let details =
                                build_yara_memory_match_details(mem_match_debug, rule_match, chunk);
                            let alert = build_yara_memory_alert(
                                &rule_match.rule,
                                &job.image,
                                job.pid,
                                details,
                                Platform::Windows,
                                "yara-memory",
                            );
                            alert_sink_for_mem.write_alert(&alert);
                            response_engine_for_mem.handle_alert(&alert);
                        }
                    }
                }
            }
            info!(target: "scanner", "YARA memory worker shutting down");
        }))
    } else {
        None
    };

    // Create background worker channel for IOC hashing (process start only)
    // Uses spawn_blocking to avoid starving the tokio async thread pool with
    // CPU-bound crypto work and synchronous file I/O.
    let (ioc_hash_tx, mut ioc_hash_worker_handle) = if ioc_engine.is_enabled() {
        let (hash_tx, mut hash_rx) = mpsc::channel::<(String, u32)>(1000);
        let detectors_for_ioc_hash = Arc::clone(&detectors);
        let alert_sink_for_ioc = alert_sink.clone();
        let response_engine_for_ioc = response_engine.clone();

        let hash_worker_handle = tokio::task::spawn_blocking(move || {
            info!(
                target: "ioc",
                "IOC hash worker thread started and waiting for files to hash"
            );
            let mut cache = HashCache::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut last_requirements = HashRequirements {
                md5: false,
                sha1: false,
                sha256: false,
            };
            let mut hash_error_limiter =
                LogRateLimiter::new(Duration::from_secs(WORKER_DEBUG_LOG_WINDOW_SECS));

            while let Some((path, pid)) = hash_rx.blocking_recv() {
                if path.is_empty() {
                    continue;
                }

                let ioc_engine = detectors_for_ioc_hash.ioc();
                if !ioc_engine.is_enabled() || !ioc_engine.wants_hashing() {
                    continue;
                }

                let requirements = ioc_engine.hash_requirements();
                if requirements != last_requirements {
                    cache = HashCache::new();
                    last_requirements = requirements;
                    info!(
                        target: "ioc",
                        md5 = requirements.md5,
                        sha1 = requirements.sha1,
                        sha256 = requirements.sha256,
                        "IOC hash requirements changed; cache reset"
                    );
                }

                let max_file_size = ioc_engine.max_file_size_bytes();

                // Skip allowlisted paths (trusted directories)
                if ioc_engine.is_hash_allowlisted(&path) {
                    tracing::trace!(
                        target: "ioc",
                        pid = pid,
                        file = %path,
                        "IOC hash worker skipping allowlisted path"
                    );
                    continue;
                }

                // Skip files exceeding the size limit
                if max_file_size > 0 {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if metadata.len() > max_file_size {
                            tracing::trace!(
                                target: "ioc",
                                pid = pid,
                                file = %path,
                                file_mb = metadata.len() / (1024 * 1024),
                                max_mb = max_file_size / (1024 * 1024),
                                "IOC hash worker skipping oversized file"
                            );
                            continue;
                        }
                    }
                }

                let hashes = match cache.get_or_compute(Path::new(&path), requirements, &mut buf) {
                    Ok(hashes) => hashes,
                    Err(err) => {
                        let decision = hash_error_limiter.should_emit("hash_error");
                        if decision.should_emit {
                            debug!(
                                target: "ioc",
                                pid = pid,
                                file = %path,
                                error = %err,
                                suppressed = decision.suppressed_since_last_emit,
                                "IOC hash worker failed to hash file"
                            );
                        }
                        continue;
                    }
                };

                let matches = ioc_engine.match_hashes(&hashes);
                if !matches.is_empty() {
                    info!(
                        pid = pid,
                        file = %path,
                        matches = matches.len(),
                        "IOC hash match detected"
                    );
                    for m in matches {
                        let alert = ioc_engine.build_alert_for_hash_match(
                            &m,
                            &path,
                            pid,
                            Platform::Windows,
                            "etw",
                        );
                        alert_sink_for_ioc.write_alert(&alert);
                        response_engine_for_ioc.handle_alert(&alert);
                    }
                } else {
                    tracing::trace!(
                        target: "ioc",
                        pid = pid,
                        file = %path,
                        "IOC hash worker no matches"
                    );
                }
            }
            info!(target: "ioc", "IOC hash worker thread shutting down");
        });

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
    let yara_handler = YaraEventHandler {
        tx,
        memory_tx: yara_memory_tx,
        allowlist_paths: yara_allowlist_paths,
    };

    // Setup shared SensorEventRouter (mutable)
    let mut router_inner = SensorEventRouter::new();
    router_inner.register_handler(Box::new(sigma_handler));
    router_inner.register_handler(Box::new(yara_handler));

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
    info!("Signaling YARA worker to shut down...");

    match yara_worker_handle.await {
        Ok(_) => info!("YARA worker thread finished"),
        Err(e) => error!("Failed to join YARA worker thread: {}", e),
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

    info!("");
    info!("╔═══════════════════════════════════════════════════╗");
    info!("║           Shutdown Complete                       ║");
    info!("║        Thank you for using Rustinel!              ║");
    info!("╚═══════════════════════════════════════════════════╝");

    Ok(())
}

// ── Linux eBPF EDR entry point ────────────────────────────────────────────────

/// Linux eBPF EDR main loop. Mirrors `run_edr` but replaces ETW with the
/// eBPF sensor and omits Windows-only subsystems.
#[cfg(target_os = "linux")]
async fn run_linux_edr() -> anyhow::Result<()> {
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

    log_startup_banner("Linux eBPF");

    // 3. Shared state
    let process_cache = Arc::new(ProcessCache::new());
    let sid_cache = Arc::new(SidCache::new()); // no-op on Linux; kept for Normalizer compat
    let dns_cache = Arc::new(DnsCache::new());
    let connection_aggregator = Arc::new(ConnectionAggregator::with_limits(
        cfg.network.aggregation_max_entries,
        cfg.network.aggregation_interval_buffer_size,
    ));

    // 4. Active response engine
    let (response_engine, response_worker_handle) = ResponseEngine::new(&cfg.response);

    // 5. Sigma engine
    let mut sigma_engine = Engine::new_for_platform_with_logging_level_and_match_debug(
        Platform::Linux,
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
    let (yara_tx, mut yara_rx) = mpsc::channel::<(String, u32)>(1000);

    let (yara_memory_tx, yara_memory_rx) =
        if cfg.scanner.yara_enabled && cfg.scanner.yara_memory_enabled {
            let capacity = cfg.scanner.yara_memory_queue_capacity.max(1);
            let (tx, rx) = mpsc::channel::<YaraMemoryJob>(capacity);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
    let detectors_for_yara = Arc::clone(&detectors);
    let yara_allowlist_paths_for_worker = yara_allowlist_paths.clone();
    let alert_sink_for_yara = alert_sink.clone();
    let response_engine_for_yara = response_engine.clone();
    let match_debug = cfg.alerts.match_debug;
    let yara_worker_handle = tokio::task::spawn_blocking(move || {
        let mut scan_error_limiter =
            LogRateLimiter::new(Duration::from_secs(WORKER_DEBUG_LOG_WINDOW_SECS));
        while let Some((path, pid)) = yara_rx.blocking_recv() {
            if scanner::is_path_allowlisted(&path, &yara_allowlist_paths_for_worker) {
                continue;
            }
            let scanner = detectors_for_yara.yara();
            match scanner.scan_file(&path, match_debug) {
                Ok(matches) if !matches.is_empty() => {
                    for rule_match in &matches {
                        let details = build_yara_match_details(match_debug, rule_match);
                        let alert = build_yara_alert(
                            &rule_match.rule,
                            &path,
                            pid,
                            details,
                            Platform::Linux,
                            "ebpf",
                        );
                        alert_sink_for_yara.write_alert(&alert);
                        response_engine_for_yara.handle_alert(&alert);
                    }
                }
                Err(e) => {
                    let decision = scan_error_limiter.should_emit("scan_error");
                    if decision.should_emit {
                        debug!(
                            pid,
                            file = %path,
                            error = %e,
                            suppressed = decision.suppressed_since_last_emit,
                            "YARA scan failure"
                        );
                    }
                }
                _ => {}
            }
        }
    });

    // Spawn optional YARA memory scanning worker (Linux).
    let yara_memory_worker_handle = if let Some(mut mem_rx) = yara_memory_rx {
        let detectors_for_mem = Arc::clone(&detectors);
        let alert_sink_for_mem = alert_sink.clone();
        let response_engine_for_mem = response_engine.clone();
        let mem_cfg = MemoryScanConfig {
            max_process_bytes: (cfg.scanner.yara_memory_max_process_mb * 1024 * 1024) as usize,
            max_region_bytes: (cfg.scanner.yara_memory_max_region_mb * 1024 * 1024) as usize,
            include_private: cfg.scanner.yara_memory_include_private,
            include_image: cfg.scanner.yara_memory_include_image,
            include_mapped: cfg.scanner.yara_memory_include_mapped,
            delay_ms: cfg.scanner.yara_memory_delay_ms,
        };
        let mem_match_debug = cfg.alerts.match_debug;
        Some(tokio::task::spawn_blocking(move || {
            info!(target: "scanner", "YARA memory worker started");
            while let Some(job) = mem_rx.blocking_recv() {
                std::thread::sleep(Duration::from_millis(mem_cfg.delay_ms));
                let chunks = match memory::read_process_memory_chunks(job.pid, &mem_cfg) {
                    Ok(c) => c,
                    Err(err) => {
                        tracing::trace!(
                            target: "scanner",
                            pid = job.pid,
                            image = %job.image,
                            error = %err,
                            "YARA memory scan skipped"
                        );
                        continue;
                    }
                };
                let scanner = detectors_for_mem.yara();
                for chunk in &chunks {
                    let matches = match scanner.scan_bytes(&chunk.bytes, mem_match_debug) {
                        Ok(m) => m,
                        Err(err) => {
                            tracing::trace!(
                                target: "scanner",
                                pid = job.pid,
                                error = %err,
                                "YARA memory chunk scan failed"
                            );
                            continue;
                        }
                    };
                    if !matches.is_empty() {
                        let rule_names: Vec<String> =
                            matches.iter().map(|r| r.rule.clone()).collect();
                        warn!(
                            pid = job.pid,
                            image = %job.image,
                            rules = ?rule_names,
                            "YARA memory detection triggered"
                        );
                        for rule_match in &matches {
                            let details =
                                build_yara_memory_match_details(mem_match_debug, rule_match, chunk);
                            let alert = build_yara_memory_alert(
                                &rule_match.rule,
                                &job.image,
                                job.pid,
                                details,
                                Platform::Linux,
                                "yara-memory",
                            );
                            alert_sink_for_mem.write_alert(&alert);
                            response_engine_for_mem.handle_alert(&alert);
                        }
                    }
                }
            }
            info!(target: "scanner", "YARA memory worker shutting down");
        }))
    } else {
        None
    };

    // 10. IOC hash background worker
    let (ioc_hash_tx, mut ioc_hash_worker_handle) = if ioc_engine.is_enabled() {
        let (hash_tx, mut hash_rx) = mpsc::channel::<(String, u32)>(1000);
        let detectors_for_ioc = Arc::clone(&detectors);
        let alert_sink_for_ioc = alert_sink.clone();
        let response_engine_for_ioc = response_engine.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let mut cache = HashCache::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut last_requirements = HashRequirements {
                md5: false,
                sha1: false,
                sha256: false,
            };
            let mut hash_error_limiter =
                LogRateLimiter::new(Duration::from_secs(WORKER_DEBUG_LOG_WINDOW_SECS));
            while let Some((path, pid)) = hash_rx.blocking_recv() {
                if path.is_empty() {
                    continue;
                }
                let ioc = detectors_for_ioc.ioc();
                if !ioc.is_enabled() || !ioc.wants_hashing() {
                    continue;
                }
                let requirements = ioc.hash_requirements();
                if requirements != last_requirements {
                    cache = HashCache::new();
                    last_requirements = requirements;
                }
                let max_size = ioc.max_file_size_bytes();
                if ioc.is_hash_allowlisted(&path) {
                    continue;
                }
                if max_size > 0 {
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if meta.len() > max_size {
                            continue;
                        }
                    }
                }
                match cache.get_or_compute(Path::new(&path), requirements, &mut buf) {
                    Ok(hashes) => {
                        for m in ioc.match_hashes(&hashes) {
                            let alert = ioc.build_alert_for_hash_match(
                                &m,
                                &path,
                                pid,
                                Platform::Linux,
                                "ebpf",
                            );
                            alert_sink_for_ioc.write_alert(&alert);
                            response_engine_for_ioc.handle_alert(&alert);
                        }
                    }
                    Err(e) => {
                        let decision = hash_error_limiter.should_emit("hash_error");
                        if decision.should_emit {
                            debug!(
                                pid,
                                file = %path,
                                error = %e,
                                suppressed = decision.suppressed_since_last_emit,
                                "IOC hash failure"
                            );
                        }
                    }
                }
            }
        });
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

    // 13. eBPF sensor
    let sensor = Arc::new(EbpfSensor::new());

    info!("Starting eBPF sensor...");
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
        error!("eBPF sensor failed to start: {:#}", e);
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
