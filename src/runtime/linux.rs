use crate::config::AppConfig;
use crate::runtime::capture::{run_capture as capture, CaptureOptions};
use crate::runtime::live::run_live;
use crate::runtime::sensors::{
    BoxFuture, Direct, LiveSensor, Member, PlatformRuntime, RunMode, SensorSet, StartFailure,
};
use crate::runtime::signals::ShutdownSignals;
use crate::sensor::linux::{EbpfSensor, JournalAuthSensor};
use crate::sensor::{Platform, RawEvent, Sensor};
use crate::state::HostState;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::mpsc::Sender;

fn sensors(config: &AppConfig, host: &Arc<HostState>, mode: RunMode) -> SensorSet {
    let ebpf = EbpfSensor::with_host_state(Arc::clone(host));
    // Live and capture keep separate cursors, so a capture never moves the
    // position the agent resumes from.
    let journal = match mode {
        RunMode::Live => "journal",
        RunMode::Capture => "journal-capture",
    };
    let journal = JournalAuthSensor::new(host, config.logging.directory.join(journal));
    SensorSet::new(vec![
        Member::required("eBPF sensor", Arc::new(Direct(Arc::new(ebpf)))),
        Member::best_effort(
            "Linux auth journal reader",
            "continuing without sshd, sudo and su authentication events",
            Arc::new(JournalLive(Arc::new(journal))),
        ),
    ])
}

/// Runs the journal reader and waits, on stop, for its last cursor write.
struct JournalLive(Arc<JournalAuthSensor>);

impl LiveSensor for JournalLive {
    fn start(&self, tx: Sender<RawEvent>) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(std::future::ready(self.0.start(tx)))
    }

    fn shutdown(&self) {
        self.0.shutdown();
    }

    fn stopped(&self) -> BoxFuture<'_, ()> {
        let sensor = Arc::clone(&self.0);
        Box::pin(async move {
            let _ = tokio::task::spawn_blocking(move || sensor.join()).await;
        })
    }
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
