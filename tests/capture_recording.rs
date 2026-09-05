//! Behavioral recording at the shared normalization boundary.
//!
//! These tests drive the same `SensorEventRouter` the platform runtimes use, so
//! they exercise the real capture boundary rather than the writer in isolation.

#[cfg(test)]
mod common;

use std::path::Path;
use std::sync::Arc;

use common::{
    dns_query_event, file_create_event, network_connect_event, process_start_event, SigmaFixture,
    TestNormalizer, YaraFixture,
};
use rustinel::{
    alerts::AlertSink,
    capture::{CaptureRecorder, CaptureStatus},
    config::ResponseConfig,
    engine::{DetectionPipeline, DetectorStore, Engine, NormalizedEventHandler},
    ioc::IocEngine,
    scanner::Scanner,
    sensor::{Platform, SensorEventRouter},
};
use serde_json::Value;

fn read_lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("recording exists")
        .lines()
        .map(|line| serde_json::from_str(line).expect("recording line is JSON"))
        .collect()
}

#[tokio::test]
async fn capture_records_every_normalized_event_in_order() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = temp.path().join("captures").join("session.ndjson");
    let recorder =
        CaptureRecorder::start(payload.clone(), Platform::Linux).expect("capture starts");

    let harness = TestNormalizer::new(false);
    let handler = NormalizedEventHandler::recording(Arc::new(harness.normalizer), recorder.sink());
    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));

    // A repeated event must appear twice: capture does not deduplicate.
    router.route_event(&process_start_event(Platform::Linux));
    router.route_event(&network_connect_event(Platform::Linux));
    router.route_event(&file_create_event(Platform::Linux));
    router.route_event(&process_start_event(Platform::Linux));
    drop(router);

    let manifest = recorder.finish().await.expect("capture finalizes");

    let events = read_lines(&payload);
    let categories: Vec<&str> = events
        .iter()
        .map(|event| event["category"].as_str().expect("category present"))
        .collect();
    assert_eq!(
        categories,
        vec!["Process", "Network", "File", "Process"],
        "events are recorded in observed order, repeats included"
    );

    assert_eq!(manifest.status, CaptureStatus::Complete);
    assert_eq!(manifest.events.received, 4);
    assert_eq!(manifest.events.written, 4);
    assert_eq!(manifest.events.lost, 0);
    assert_eq!(manifest.platform, Platform::Linux);
}

#[tokio::test]
async fn capture_records_canonical_events_without_alert_enrichment() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = temp.path().join("session.ndjson");
    let recorder =
        CaptureRecorder::start(payload.clone(), Platform::Linux).expect("capture starts");

    let harness = TestNormalizer::new(false);
    let handler = NormalizedEventHandler::recording(Arc::new(harness.normalizer), recorder.sink());
    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));
    // A process start first, so the cache holds context the alert path would
    // otherwise graft onto the later non-process events.
    router.route_event(&process_start_event(Platform::Linux));
    router.route_event(&dns_query_event(Platform::Linux));
    drop(router);

    recorder.finish().await.expect("capture finalizes");

    let events = read_lines(&payload);
    let dns = events.last().expect("dns event recorded");
    assert_eq!(dns["category"], "Dns");
    assert!(
        dns.get("process_context").is_none(),
        "alert-only process context must not be baked into a recording: {dns}"
    );
}

#[tokio::test]
async fn capture_does_not_evaluate_detectors_or_write_alerts() {
    let fixture = SigmaFixture::new();
    // A rule that the recorded process start would match under live protection.
    fixture.write_process_rule(Platform::Linux);
    let mut sigma = Engine::new_for_platform(Platform::Linux);
    sigma
        .load_rules(fixture.rules_dir())
        .expect("load sigma rule");
    assert!(sigma.stats().total_rules > 0, "fixture rule is loaded");

    let temp = tempfile::tempdir().expect("tempdir");
    let alerts = temp.path().join("alerts.ndjson");
    let payload = temp.path().join("captures").join("session.ndjson");
    let recorder =
        CaptureRecorder::start(payload.clone(), Platform::Linux).expect("capture starts");

    let harness = TestNormalizer::new(false);
    let handler = NormalizedEventHandler::recording(Arc::new(harness.normalizer), recorder.sink());
    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));
    router.route_event(&process_start_event(Platform::Linux));
    drop(router);

    recorder.finish().await.expect("capture finalizes");

    assert_eq!(read_lines(&payload).len(), 1, "the event was recorded");
    assert!(
        !alerts.exists(),
        "capture must not produce alert output alongside the recording"
    );
}

#[tokio::test]
async fn live_protection_does_not_write_a_recording() {
    let fixture = SigmaFixture::new();
    fixture.write_process_rule(Platform::Linux);
    let mut sigma = Engine::new_for_platform(Platform::Linux);
    sigma
        .load_rules(fixture.rules_dir())
        .expect("load sigma rule");

    let yara_fixture = YaraFixture::new();
    let detectors = DetectorStore::new(
        Arc::new(sigma),
        Arc::new(Scanner::new(yara_fixture.rules_dir()).expect("empty yara scanner")),
        Arc::new(IocEngine::disabled()),
    );

    let temp = tempfile::tempdir().expect("tempdir");
    let alerts = temp.path().join("alerts.ndjson");
    let captures = temp.path().join("captures");
    let file = std::fs::File::create(&alerts).expect("create alert output");
    let (writer, guard) = tracing_appender::non_blocking(file);
    let (response, response_handle) = rustinel::response::ResponseEngine::new(Arc::new(
        arc_swap::ArcSwap::from(Arc::new(ResponseConfig {
            enabled: false,
            prevention_enabled: false,
            min_severity: "critical".to_string(),
            channel_capacity: 4,
            allowlist_images: Vec::new(),
            allowlist_paths: Vec::new(),
        })),
    ));

    let harness = TestNormalizer::new(false);
    let handler = NormalizedEventHandler::detecting(
        Arc::new(harness.normalizer),
        DetectionPipeline {
            detectors,
            ioc_hash_tx: None,
            alert_sink: AlertSink::new(writer),
            response_engine: response,
        },
    );
    assert!(
        handler.capture.is_none(),
        "the live pipeline carries no capture sink"
    );

    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));
    router.route_event(&process_start_event(Platform::Linux));
    drop(router);
    drop(guard);
    response_handle.abort();

    assert!(
        std::fs::read_to_string(&alerts)
            .expect("alert output readable")
            .contains("\"rule.name\""),
        "live protection still alerts"
    );
    assert!(
        !captures.exists(),
        "ordinary run must not produce a recording"
    );
}

#[tokio::test]
async fn shutdown_finalizes_queued_events_and_the_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = temp.path().join("session.ndjson");
    let recorder =
        CaptureRecorder::start(payload.clone(), Platform::Linux).expect("capture starts");
    let manifest_path = recorder.manifest_path().to_path_buf();

    let harness = TestNormalizer::new(false);
    let handler = NormalizedEventHandler::recording(Arc::new(harness.normalizer), recorder.sink());
    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));
    for _ in 0..64 {
        router.route_event(&process_start_event(Platform::Linux));
    }
    drop(router);

    let manifest = recorder.finish().await.expect("capture finalizes");
    let persisted: rustinel::capture::CaptureManifest =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("manifest exists"))
            .expect("manifest parses");

    assert_eq!(read_lines(&payload).len(), 64, "queued events are drained");
    assert_eq!(manifest.events.written, 64);
    assert_eq!(persisted, manifest);
    assert!(persisted.is_replayable());
}
