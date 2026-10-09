//! Host and agent identity on live alerts.

use rustinel::alerts::{AlertSink, Deduplicator};
use rustinel::identity::Identity;
use rustinel::models::ecs::EcsAlert;
use rustinel::models::{Alert, AlertSeverity, DetectionEngine, NormalizedEvent};
use serde_json::Value;
use std::sync::Arc;

fn alert(rule: &str) -> Alert {
    let event: NormalizedEvent = serde_json::from_value(serde_json::json!({
        "timestamp": "2026-09-15T10:00:00Z",
        "platform": "linux",
        "provider": "ebpf",
        "category": "Process",
        "event_id": 1,
        "opcode": 1,
        "fields": { "Image": "/usr/bin/whoami", "ProcessId": "4242" }
    }))
    .unwrap();
    Alert {
        severity: AlertSeverity::High,
        rule_name: rule.to_string(),
        rule_description: None,
        rule_id: None,
        sigma_metadata: None,
        engine: DetectionEngine::Sigma,
        event,
        match_details: None,
    }
}

fn identity() -> Arc<Identity> {
    Arc::new(Identity {
        host_id: Some("0123456789abcdef0123456789abcdef".to_string()),
        host_name: Some("lab-01".to_string()),
        agent_id: Some("6f1c2f4e-7a58-4b52-9f55-0d1c7e3a9b10".to_string()),
        agent_type: "rustinel",
        agent_version: "9.9.9",
    })
}

fn lines_of(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn assert_identity(json: &Value) {
    assert_eq!(json["host.id"], "0123456789abcdef0123456789abcdef");
    assert_eq!(json["host.name"], "lab-01");
    assert_eq!(json["agent.id"], "6f1c2f4e-7a58-4b52-9f55-0d1c7e3a9b10");
    assert_eq!(json["agent.type"], "rustinel");
    assert_eq!(json["agent.version"], "9.9.9");
}

#[test]
fn live_alerts_and_dedup_rollups_carry_identity() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(std::fs::File::create(&out).unwrap());
    let dedup = Arc::new(Deduplicator::new(60, 100));
    let sink = AlertSink::new(writer)
        .with_identity(identity())
        .with_deduplicator(Arc::clone(&dedup));

    let repeated = alert("Repeated");
    for _ in 0..3 {
        sink.write_alert(&repeated);
    }
    dedup.flush_all(&sink);
    drop(sink);
    drop(guard);

    let lines = lines_of(&out);
    assert_eq!(lines.len(), 2, "first alert plus rollup");
    assert!(lines[1].get("event.count").is_some());
    for line in &lines {
        assert_identity(line);
    }
}

#[test]
fn sink_without_identity_omits_every_identity_field() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(std::fs::File::create(&out).unwrap());
    AlertSink::new(writer).write_alert(&alert("Replay-like"));
    drop(guard);

    let line = &lines_of(&out)[0];
    for key in [
        "host.id",
        "host.name",
        "agent.id",
        "agent.type",
        "agent.version",
    ] {
        assert!(line.get(key).is_none(), "{key} must be omitted");
    }
    // The mapper itself never fabricates identity, which is what replay uses.
    let json = serde_json::to_value(EcsAlert::from(&alert("x"))).unwrap();
    assert!(json.get("agent.id").is_none() && json.get("host.id").is_none());
}

#[test]
fn undeterminable_identifiers_are_omitted() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(std::fs::File::create(&out).unwrap());
    let partial = Identity {
        host_id: None,
        host_name: Some("lab-01".to_string()),
        agent_id: None,
        agent_type: "rustinel",
        agent_version: "9.9.9",
    };
    AlertSink::new(writer)
        .with_identity(Arc::new(partial))
        .write_alert(&alert("Partial"));
    drop(guard);

    let line = &lines_of(&out)[0];
    assert!(line.get("host.id").is_none() && line.get("agent.id").is_none());
    assert_eq!(line["host.name"], "lab-01");
    assert_eq!(line["agent.type"], "rustinel");
}

#[test]
fn resolved_identity_is_stable_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let first = Identity::resolve(dir.path());
    let second = Identity::resolve(dir.path());
    assert_eq!(first, second);
    assert!(first.agent_id.is_some());
    assert_eq!(first.agent_version, env!("CARGO_PKG_VERSION"));
}
