use crate::config::AppConfig;
use crate::runtime::capture::{run_capture as capture, CaptureOptions};
use crate::runtime::live::run_live;
use crate::runtime::logging::TARGET_CONSOLE;
use crate::runtime::sensors::{
    BoxFuture, LiveSensor, Member, PlatformRuntime, RunMode, SensorSet, ShutdownFuture,
    StartFailure,
};
use crate::sensor::windows::EtwSensor;
use crate::sensor::{RawEvent, Sensor};
use crate::state::HostState;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

enum ShutdownMode {
    Console,
    Service(watch::Receiver<bool>),
}

pub fn run_console(
    console_output: bool,
    log_level: Option<String>,
    config_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run_edr(
        ShutdownMode::Console,
        Some(console_output),
        log_level,
        config_path,
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

        let run_result = run_edr(ShutdownMode::Service(shutdown_rx), None, None, None).await;
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

/// ETW providers require an elevated token. Shared by `run` and `capture` so
/// both fail with the same clear preflight error.
fn ensure_administrator_privileges() -> anyhow::Result<()> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing, and
    // `token` and `elevation` are valid out-pointers. The elevation buffer size
    // passed matches TOKEN_ELEVATION.
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
                    info!(target: TARGET_CONSOLE, "✓ Running with Administrator privileges");
                }
            }
        }
    }

    Ok(())
}

/// The ETW trace thread, supervised from async code.
///
/// ETW starts on a blocking thread and reports readiness over a channel, and
/// the thread ending is how a dead session shows up.
struct EtwLive {
    sensor: Arc<EtwSensor>,
    trace: tokio::sync::Mutex<Trace>,
}

enum Trace {
    NotStarted,
    Running(JoinHandle<anyhow::Result<()>>),
    Finished,
}

impl EtwLive {
    fn new(sensor: EtwSensor) -> Self {
        Self {
            sensor: Arc::new(sensor),
            trace: tokio::sync::Mutex::new(Trace::NotStarted),
        }
    }
}

fn describe_trace_end(result: Result<anyhow::Result<()>, tokio::task::JoinError>) -> String {
    match result {
        Ok(Ok(())) => "ETW session closed".to_string(),
        Ok(Err(err)) => format!("ETW session failed: {err:#}"),
        Err(err) if err.is_panic() => {
            let panic = err.into_panic();
            let message = panic
                .downcast_ref::<&str>()
                .map(|message| message.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<unable to extract>".to_string());
            format!("ETW trace thread panicked: {message}")
        }
        Err(err) => format!("ETW trace thread did not finish cleanly: {err}"),
    }
}

impl LiveSensor for EtwLive {
    fn start(&self, tx: mpsc::Sender<RawEvent>) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let sensor = Arc::clone(&self.sensor);
            let (readiness_tx, readiness_rx) = oneshot::channel();
            let mut handle =
                tokio::task::spawn_blocking(move || sensor.start_with_readiness(tx, readiness_tx));

            // Startup runs on the trace thread. Report ready only once both
            // ETW sessions, their consumers, and the Event Log subscriptions
            // accept events.
            let (failure, trace_finished) = tokio::select! {
                result = &mut handle => (
                    Some(format!("{} during startup", describe_trace_end(result))),
                    true,
                ),
                readiness = readiness_rx => match readiness {
                    Ok(Ok(())) => (None, false),
                    Ok(Err(err)) => (Some(format!("ETW startup failed: {err}")), false),
                    Err(_) => (
                        Some("ETW sensor stopped before reporting readiness".to_string()),
                        false,
                    ),
                },
            };

            if let Some(reason) = failure {
                if !trace_finished {
                    let _ = (&mut handle).await;
                }
                return Err(anyhow::anyhow!(reason));
            }
            *self.trace.lock().await = Trace::Running(handle);
            Ok(())
        })
    }

    fn shutdown(&self) {
        self.sensor.shutdown();
    }

    fn ended(&self) -> BoxFuture<'_, String> {
        Box::pin(async move {
            let mut trace = self.trace.lock().await;
            let Trace::Running(handle) = &mut *trace else {
                return std::future::pending().await;
            };
            let result = handle.await;
            *trace = Trace::Finished;
            describe_trace_end(result)
        })
    }

    fn stopped(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut trace = self.trace.lock().await;
            if let Trace::Running(handle) = &mut *trace {
                match handle.await {
                    Ok(Ok(())) => info!("ETW sensor thread finished"),
                    Ok(Err(err)) => warn!("ETW sensor exited with error during shutdown: {err:#}"),
                    Err(err) => error!("Failed to join ETW sensor thread: {}", err),
                }
            }
            *trace = Trace::Finished;
        })
    }

    fn events_lost(&self) -> u64 {
        self.sensor.events_lost()
    }
}

fn sensors(config: &AppConfig, host: &Arc<HostState>, mode: RunMode) -> SensorSet {
    let event_log = match mode {
        RunMode::Live => "event-log",
        RunMode::Capture => "event-log-capture",
    };
    let etw = EtwSensor::with_flush_intervals(
        config.windows.etw_flush_interval_ms,
        config.windows.etw_process_flush_interval_ms,
    )
    .with_host_state(Arc::clone(host))
    .with_event_log_directory(config.logging.directory.join(event_log))
    .with_security_filtering_platform_connections(
        config.windows.security_filtering_platform_connections,
    );
    SensorSet::new(vec![Member::required(
        "ETW sensor",
        Arc::new(EtwLive::new(etw)),
    )])
}

/// Cold start: seed the process cache so early events resolve parents.
fn seed_host_state(host: &Arc<HostState>) {
    match crate::platform::windows::snapshot_processes(host) {
        Ok(count) => info!(
            target: TARGET_CONSOLE,
            "✓ Process Cache initialized with {} existing processes",
            count
        ),
        Err(e) => warn!(
            "Failed to snapshot processes: {}. Cache will populate from ETW events.",
            e
        ),
    }
}

// ETW is the busiest source, so its channel holds more than the other
// platforms' (#364). Capture uses the same capacity as live.
const RUNTIME: PlatformRuntime = PlatformRuntime {
    platform: crate::sensor::Platform::Windows,
    label: "Windows ETW",
    channel_capacity: 32_768,
    // An ETW session reports a failed start by ending, and the recording is
    // still the evidence of what ran, so it is kept and marked incomplete.
    start_failure: StartFailure::KeepIncomplete,
    preflight: ensure_administrator_privileges,
    seed_host_state,
    sensors,
    starting: "ETW sensor",
};

fn shutdown_future(mode: ShutdownMode) -> ShutdownFuture {
    match mode {
        ShutdownMode::Console => {
            let listener = tokio::spawn(async {
                match tokio::signal::ctrl_c().await {
                    Ok(()) => Some("Ctrl+C".to_string()),
                    Err(err) => {
                        error!("Failed to listen for Ctrl+C: {}", err);
                        None
                    }
                }
            });
            Box::pin(async move { listener.await.ok().flatten() })
        }
        ShutdownMode::Service(mut shutdown_rx) => Box::pin(async move {
            if shutdown_rx.changed().await.is_ok() {
                Some("service stop".to_string())
            } else {
                warn!("Service shutdown channel dropped");
                None
            }
        }),
    }
}

/// Windows process groups receive `CTRL_BREAK_EVENT` from automation such as
/// Python's `subprocess.send_signal`. Capture treats it like interactive
/// Ctrl+C so it can still drain and finalize its manifest.
fn capture_shutdown_future() -> ShutdownFuture {
    Box::pin(async {
        let mut ctrl_break = match tokio::signal::windows::ctrl_break() {
            Ok(signal) => signal,
            Err(err) => {
                error!("Failed to listen for Ctrl+Break: {}", err);
                return match tokio::signal::ctrl_c().await {
                    Ok(()) => Some("Ctrl+C".to_string()),
                    Err(err) => {
                        error!("Failed to listen for Ctrl+C: {}", err);
                        None
                    }
                };
            }
        };

        tokio::select! {
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => Some("Ctrl+C".to_string()),
                Err(err) => {
                    error!("Failed to listen for Ctrl+C: {}", err);
                    None
                }
            },
            signal = ctrl_break.recv() => match signal {
                Some(()) => Some("Ctrl+Break".to_string()),
                None => {
                    error!("Ctrl+Break listener closed before shutdown");
                    None
                }
            },
        }
    })
}

/// Windows capture runtime: the same ETW session as `run`, recording normalized
/// events instead of evaluating them.
pub fn run_capture(options: CaptureOptions) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(capture(&RUNTIME, capture_shutdown_future(), &options))
}

async fn run_edr(
    shutdown_mode: ShutdownMode,
    console_output_override: Option<bool>,
    log_level_override: Option<String>,
    config_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    run_live(
        &RUNTIME,
        shutdown_future(shutdown_mode),
        console_output_override,
        log_level_override,
        config_path,
    )
    .await
}
