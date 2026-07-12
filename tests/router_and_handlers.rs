#[cfg(test)]
mod common;

use std::sync::Arc;

use common::{process_start_event, SigmaFixture, TestNormalizer, TEST_PID};
use rustinel::utils::hash_command_line;
use rustinel::{
    alerts::AlertSink,
    config::ResponseConfig,
    engine::{Engine, SigmaDetectionHandler},
    ioc::IocEngine,
    reload::DetectorStore,
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
    let (response, response_handle) = rustinel::response::ResponseEngine::new(&ResponseConfig {
        enabled: false,
        prevention_enabled: false,
        min_severity: "critical".to_string(),
        channel_capacity: 4,
        allowlist_images: Vec::new(),
        allowlist_paths: Vec::new(),
    });

    let harness = TestNormalizer::new(false);
    let handler = SigmaDetectionHandler {
        normalizer: Arc::new(harness.normalizer),
        detectors,
        ioc_hash_tx: None,
        alert_sink: AlertSink::new(writer),
        response_engine: response,
    };

    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));
    router.route_event(&process_start_event(Platform::Linux));

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

    handler.handle_event(&process_start_event(Platform::Linux));
    let (path, pid) = file_rx.try_recv().expect("disk job queued");
    assert_eq!(path, common::image_for(Platform::Linux));
    assert_eq!(pid, TEST_PID);
    let memory = memory_rx.try_recv().expect("memory job queued");
    assert_eq!(memory.expected_identity.pid, TEST_PID);
    assert_eq!(
        memory.expected_identity.image,
        common::image_for(Platform::Linux)
    );
    assert_eq!(
        memory.expected_identity.start_time,
        Some(common::TEST_PROCESS_START_TIME)
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
    handler.handle_event(&stop);
    assert!(file_rx.try_recv().is_err());
    assert!(memory_rx.try_recv().is_err());
}

#[tokio::test]
async fn yara_event_handler_respects_disabled_memory_and_allowlisted_paths() {
    let (file_tx, mut file_rx) = mpsc::channel(8);
    let handler = YaraEventHandler {
        tx: file_tx,
        memory_tx: None,
        allowlist_paths: Vec::new(),
    };
    handler.handle_event(&process_start_event(Platform::Linux));
    assert!(file_rx.try_recv().is_ok());

    let (allow_file_tx, mut allow_file_rx) = mpsc::channel(8);
    let allowlisted = YaraEventHandler {
        tx: allow_file_tx,
        memory_tx: None,
        allowlist_paths: normalize_allowlist_paths(&["/usr/bin".to_string()]),
    };
    allowlisted.handle_event(&process_start_event(Platform::Linux));
    assert!(allow_file_rx.try_recv().is_err());

    allowlisted.handle_event(&common::network_connect_event(Platform::Linux));
    assert!(allow_file_rx.try_recv().is_err());
}
