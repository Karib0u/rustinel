#[cfg(test)]
mod common;

use common::{
    assert_ecs_field_eq, assert_ecs_field_present, image_for, process_start_event, TestNormalizer,
    TEST_PID, TEST_USER,
};
use rustinel::{
    alerts::AlertSink,
    models::{Alert, AlertSeverity, DetectionEngine},
    sensor::Platform,
};
use serde_json::Value;

#[test]
fn alert_sink_writes_single_valid_ecs_ndjson_line() {
    let tempdir = tempfile::tempdir().expect("create alert output tempdir");
    let output_path = tempdir.path().join("alerts.ndjson");
    let file = std::fs::File::create(&output_path).expect("create alert output file");
    let (writer, guard) = tracing_appender::non_blocking(file);

    {
        let harness = TestNormalizer::new(false);
        let event = harness
            .normalizer
            .normalize(&process_start_event(Platform::Linux))
            .expect("process start should normalize");
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "Test Process Curl".to_string(),
            rule_description: Some("process test alert".to_string()),
            rule_id: None,
            engine: DetectionEngine::Sigma,
            event,
            match_details: None,
        };

        AlertSink::new(writer).write_alert(&alert);
    }

    drop(guard);

    let contents = std::fs::read_to_string(&output_path).expect("read alert output");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one NDJSON line");

    let json: Value = serde_json::from_str(lines[0]).expect("alert line should be valid JSON");
    assert!(
        json.is_object(),
        "NDJSON line should contain one JSON object"
    );

    assert_ecs_field_present(&json, "@timestamp");
    assert_ecs_field_eq(&json, "event.kind", "alert");
    assert_ecs_field_eq(&json, "rule.name", "Test Process Curl");
    assert_ecs_field_eq(&json, "rule.description", "process test alert");
    assert_ecs_field_eq(&json, "edr.rule.engine", "Sigma");
    assert_ecs_field_eq(&json, "event.dataset", "edr.process");
    assert_ecs_field_eq(&json, "event.provider", "ebpf");
    assert_ecs_field_eq(&json, "process.executable", image_for(Platform::Linux));
    assert_ecs_field_eq(&json, "process.pid", TEST_PID);
    assert_ecs_field_eq(&json, "user.name", TEST_USER);
}
