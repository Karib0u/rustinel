#[cfg(test)]
mod common;

use std::sync::Arc;

use common::{process_start_event, SigmaFixture, TestNormalizer, TEST_PID};
use rustinel::utils::hash_command_line;
use rustinel::{
    alerts::AlertSink,
    config::ResponseConfig,
    engine::{DetectionPipeline, DetectorStore, Engine, NormalizedEventHandler},
    ioc::IocEngine,
    scanner::{normalize_allowlist_paths, Scanner, YaraEventHandler},
    sensor::{Platform, SensorAction, SensorEventHandler, SensorEventRouter},
};
use tokio::sync::mpsc;

#[tokio::test]
async fn router_invokes_sigma_handler_and_writes_alert() {
    let fixture = SigmaFixture::new();
    fixture.write_process_rule(Platform::Linux);
    let mut sigma = Engine::new_for_platform(Platform::Linux);
    sigma
        .load_rules(fixture.rules_dir())
        .expect("load sigma rule");

    let yara_fixture = common::YaraFixture::new();
    let detectors = DetectorStore::new(
        Arc::new(sigma),
        Arc::new(Scanner::new(yara_fixture.rules_dir()).expect("empty yara scanner")),
        Arc::new(IocEngine::disabled()),
    );

    let tempdir = tempfile::tempdir().expect("create alerts tempdir");
    let output = tempdir.path().join("alerts.ndjson");
    let file = std::fs::File::create(&output).expect("create alert output");
    let (writer, guard) = tracing_appender::non_blocking(file);
    let (response, response_handle) = rustinel::response::ResponseEngine::new(std::sync::Arc::new(
        arc_swap::ArcSwap::from(std::sync::Arc::new(ResponseConfig {
            enabled: false,
            prevention_enabled: false,
            min_severity: "critical".to_string(),
            channel_capacity: 4,
            allowlist_images: Vec::new(),
            allowlist_paths: Vec::new(),
        })),
    ));

    let harness = TestNormalizer::new();
    let handler = NormalizedEventHandler::detecting(
        Arc::clone(&harness.host_state),
        DetectionPipeline {
            detectors,
            ioc_hash_tx: None,
            alert_sink: AlertSink::new(writer),
            response_engine: response,
        },
    );

    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));
    router.route_raw_event(&harness.host_state, &process_start_event(Platform::Linux));

    drop(router);
    drop(guard);
    response_handle.abort();

    let contents = std::fs::read_to_string(output).expect("read alert output");
    assert_eq!(contents.lines().count(), 1);
    assert!(contents.contains("\"rule.name\":\"Test Process Curl\""));
    assert!(contents.contains("\"edr.rule.engine\":\"Sigma\""));
}

#[tokio::test]
async fn yara_event_handler_queues_disk_and_memory_only_for_non_allowlisted_starts() {
    let (file_tx, mut file_rx) = mpsc::channel(8);
    let (memory_tx, mut memory_rx) = mpsc::channel(8);
    let handler = YaraEventHandler {
        tx: file_tx,
        memory_tx: Some(memory_tx),
        allowlist_paths: Vec::new(),
    };

    let before_enqueue = std::time::Instant::now();
    let mut start = process_start_event(Platform::Linux);
    let rustinel::sensor::SensorPayload::Process(fields) = &mut start.payload else {
        unreachable!();
    };
    let rustinel::sensor::RawProcessPlatform::Linux(source) = fields.platform.as_mut() else {
        unreachable!();
    };
    source.identity.kernel_start_boottime = Some(common::TEST_PROCESS_START_TIME);
    let host_state = TestNormalizer::new().host_state;
    let start = host_state.canonicalize(start).expect("start canonicalizes");
    handler.handle_event(&start);
    let target = file_rx.try_recv().expect("disk job queued");
    let (path, pid) = (target.path, target.pid);
    assert_eq!(path, common::image_for(Platform::Linux));
    assert_eq!(pid, TEST_PID);
    let memory = memory_rx.try_recv().expect("memory job queued");
    assert!(memory.enqueued_at >= before_enqueue);
    assert!(memory.enqueued_at <= std::time::Instant::now());
    assert_eq!(memory.expected_identity.pid, TEST_PID);
    assert_eq!(
        memory.expected_identity.image,
        common::image_for(Platform::Linux)
    );
    assert_eq!(
        memory.expected_identity.start_time,
        Some(expected_linux_start_time(common::TEST_PROCESS_START_TIME))
    );
    assert_eq!(
        memory.expected_identity.command_line_hash,
        Some(hash_command_line(&format!(
            "{} https://{}",
            common::image_for(Platform::Linux),
            common::TEST_DOMAIN
        )))
    );

    let mut stop = process_start_event(Platform::Linux);
    stop.action = SensorAction::Stop;
    assert!(host_state.canonicalize(stop).is_none());
    assert!(file_rx.try_recv().is_err());
    assert!(memory_rx.try_recv().is_err());
}

fn expected_linux_start_time(event_start_time: u64) -> u64 {
    #[cfg(target_os = "linux")]
    {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        assert!(hz > 0);
        let hz = hz as u64;
        (u128::from(event_start_time) * u128::from(hz) / 1_000_000_000) as u64
    }
    #[cfg(not(target_os = "linux"))]
    {
        event_start_time
    }
}

#[tokio::test]
async fn yara_event_handler_respects_disabled_memory_and_allowlisted_paths() {
    let (file_tx, mut file_rx) = mpsc::channel(8);
    let handler = YaraEventHandler {
        tx: file_tx,
        memory_tx: None,
        allowlist_paths: Vec::new(),
    };
    let host_state = TestNormalizer::new().host_state;
    let start = host_state
        .canonicalize(process_start_event(Platform::Linux))
        .expect("start canonicalizes");
    handler.handle_event(&start);
    assert!(file_rx.try_recv().is_ok());

    let (allow_file_tx, mut allow_file_rx) = mpsc::channel(8);
    let allowlisted = YaraEventHandler {
        tx: allow_file_tx,
        memory_tx: None,
        allowlist_paths: normalize_allowlist_paths(&["/usr/bin".to_string()]),
    };
    allowlisted.handle_event(&start);
    assert!(allow_file_rx.try_recv().is_err());

    let network = host_state
        .canonicalize(common::network_connect_event(Platform::Linux))
        .expect("network canonicalizes");
    allowlisted.handle_event(&network);
    assert!(allow_file_rx.try_recv().is_err());
}
