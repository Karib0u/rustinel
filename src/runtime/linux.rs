use crate::config::AppConfig;
use crate::runtime::capture::{run_capture as capture, CaptureOptions};
use crate::runtime::live::run_live;
use crate::runtime::sensors::{Direct, Member, PlatformRuntime, RunMode, SensorSet, StartFailure};
use crate::runtime::signals::ShutdownSignals;
use crate::sensor::linux::EbpfSensor;
use crate::sensor::Platform;
use crate::state::HostState;
use std::sync::Arc;
use tokio::runtime::Builder;

fn sensors(_config: &AppConfig, host: &Arc<HostState>, _mode: RunMode) -> SensorSet {
    let ebpf = EbpfSensor::with_host_state(Arc::clone(host));
    SensorSet::new(vec![Member::required(
        "eBPF sensor",
        Arc::new(Direct(Arc::new(ebpf))),
    )])
}

const RUNTIME: PlatformRuntime = PlatformRuntime {
    platform: Platform::Linux,
    label: "Linux eBPF",
    channel_capacity: 8192,
    start_failure: StartFailure::Abandon,
    preflight: || Ok(()),
    seed_host_state: |_| {},
    sensors,
    starting: "eBPF sensor",
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

/// Linux capture runtime: the same eBPF sensor as `run`, recording normalized
/// events instead of evaluating them.
pub fn run_capture(options: CaptureOptions) -> anyhow::Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let shutdown = ShutdownSignals::new()?.wait();
        capture(&RUNTIME, shutdown, &options).await
    })
}
