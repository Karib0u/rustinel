#[cfg(test)]
mod common;

use common::{
    assert_ecs_field_eq, assert_ecs_field_present, image_for, process_start_event, TestNormalizer,
    TEST_PID, TEST_USER,
};
use rustinel::{
    alerts::AlertSink,
    memory::{MemoryChunk, MemoryRegion, MemoryRegionKind},
    models::{
        Alert, AlertSeverity, DetectionEngine, MatchDebugLevel, YaraRuleMatch, YaraScanSource,
        YaraStringMatch,
    },
    runtime::yara::{
        build_yara_alert, build_yara_match_details, build_yara_memory_alert,
        build_yara_memory_match_details,
    },
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
        let harness = TestNormalizer::new();
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

#[test]
fn yara_scan_source_is_stable_across_debug_modes_and_scan_paths() {
    let tempdir = tempfile::tempdir().expect("create alert output tempdir");
    let output_path = tempdir.path().join("yara-alerts.ndjson");
    let file = std::fs::File::create(&output_path).expect("create alert output file");
    let (writer, guard) = tracing_appender::non_blocking(file);
    let sink = AlertSink::new(writer);
    let rule_match = YaraRuleMatch {
        rule: "TestRule".to_string(),
        metadata_id: Some("test-id".to_string()),
        tags: vec!["test".to_string()],
        namespace: Some("default".to_string()),
        strings: vec![YaraStringMatch {
            id: "$marker".to_string(),
            offset: Some(0x1010),
            snippet: Some("marker".to_string()),
        }],
    };
    let chunk = MemoryChunk {
        base: 0x1000,
        bytes: b"marker".to_vec(),
        region: MemoryRegion {
            base: 0x1000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
            kind: MemoryRegionKind::Private,
        },
    };

    for match_debug in [
        MatchDebugLevel::Off,
        MatchDebugLevel::Summary,
        MatchDebugLevel::Full,
    ] {
        let file_alert = build_yara_alert(
            &rule_match.rule,
            rule_match.metadata_id.clone(),
            "/usr/bin/test-target",
            TEST_PID,
            build_yara_match_details(match_debug, &rule_match),
            Platform::Linux,
            "ebpf",
        );
        sink.write_yara_alert(&file_alert, YaraScanSource::File);

        let memory_alert = build_yara_memory_alert(
            &rule_match.rule,
            rule_match.metadata_id.clone(),
            "/usr/bin/test-target",
            TEST_PID,
            build_yara_memory_match_details(match_debug, &rule_match, &chunk),
            Platform::Linux,
            "ebpf",
        );
        sink.write_yara_alert(&memory_alert, YaraScanSource::ProcessMemory);
    }

    drop(sink);
    drop(guard);

    let contents = std::fs::read_to_string(&output_path).expect("read alert output");
    let lines: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid ECS alert"))
        .collect();
    assert_eq!(lines.len(), 6);

    for (index, line) in lines.iter().enumerate() {
        let expected_source = if index % 2 == 0 {
            "file"
        } else {
            "process_memory"
        };
        assert_ecs_field_eq(line, "edr.yara.scan_source", expected_source);
        assert_ecs_field_eq(line, "event.provider", "ebpf");
        if index < 2 {
            assert!(
                line.get("edr.match").is_none(),
                "match debug off must omit details without omitting scan source"
            );
        } else {
            assert!(line.get("edr.match").is_some());
        }
    }
}
