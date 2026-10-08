use crate::config::AppConfig;
use crate::runtime::capture::{run_capture as capture, CaptureOptions};
use crate::runtime::live::run_live;
use crate::runtime::sensors::{Direct, Member, PlatformRuntime, RunMode, SensorSet, StartFailure};
use crate::runtime::signals::ShutdownSignals;
use crate::sensor::macos::{BpfSensor, EsfSensor};
use crate::sensor::Platform;
use crate::state::HostState;
use std::sync::Arc;
use tokio::runtime::Builder;

/// Endpoint Security supplies process and file events and is the primary
/// source, so failing to start it is fatal.
/// A /dev/bpf capture supplies network and DNS events; without it the agent
/// degrades to Endpoint Security only.
fn sensors(_config: &AppConfig, _host: &Arc<HostState>, _mode: RunMode) -> SensorSet {
    SensorSet::new(vec![
        Member::required(
            "macOS Endpoint Security sensor",
            Arc::new(Direct(Arc::new(EsfSensor::new()))),
        ),
        Member::best_effort(
            "macOS network/DNS sensor",
            "continuing with Endpoint Security only",
            Arc::new(Direct(Arc::new(BpfSensor::new()))),
        ),
    ])
}

const RUNTIME: PlatformRuntime = PlatformRuntime {
    platform: Platform::MacOS,
    label: "macOS ESF",
    channel_capacity: 8192,
    start_failure: StartFailure::Abandon,
    preflight: || Ok(()),
    seed_host_state: |_| {},
    sensors,
    starting: "macOS sensors",
};

pub fn run(
    console_output: bool,
    log_level: Option<String>,
    config_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let shutdown = ShutdownSignals::new()?.wait();
        run_live(
            &RUNTIME,
            shutdown,
            Some(console_output),
            log_level,
            config_path,
        )
        .await
    })
}

/// macOS capture runtime: the same Endpoint Security and network sensors as
/// `run`, recording normalized events instead of evaluating them.
pub fn run_capture(options: CaptureOptions) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let shutdown = ShutdownSignals::new()?.wait();
        capture(&RUNTIME, shutdown, &options).await
    })
}
