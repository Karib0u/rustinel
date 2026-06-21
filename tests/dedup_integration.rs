//! Integration tests for alert deduplication.
//!
//! Verifies the full round-trip: write N identical alerts through a dedup-attached
//! sink, flush, and confirm the output file contains the expected NDJSON lines.

#[cfg(test)]
mod common;

use rustinel::alerts::{AlertSink, Deduplicator};
use rustinel::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
    ProcessCreationFields,
};
use rustinel::sensor::Platform;
use serde_json::Value;
use std::sync::Arc;

fn make_alert(rule: &str, image: &str) -> Alert {
    Alert {
        severity: AlertSeverity::High,
        rule_name: rule.to_string(),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Sigma,
        event: NormalizedEvent {
            timestamp: "2026-06-09T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image.to_string()),
                command_line: None,
                process_id: Some("42".to_string()),
                process_start_time: None,
                parent_image: None,
                parent_process_id: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some("alice".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        },
        match_details: None,
    }
}

/// Build a real AlertSink + Deduplicator backed by a temp file; return the sink,
/// dedup handle, and worker guard (must outlive the sink).
fn setup(
    output: &std::path::Path,
    window_secs: u64,
) -> (
    AlertSink,
    Arc<Deduplicator>,
    tracing_appender::non_blocking::WorkerGuard,
) {
    let file = std::fs::File::create(output).expect("create output file");
    let (writer, guard) = tracing_appender::non_blocking(file);
    let dedup = Arc::new(Deduplicator::new(window_secs, 10_000));
    let sink = AlertSink::new(writer).with_deduplicator(Arc::clone(&dedup));
    (sink, dedup, guard)
}

fn read_json_lines(path: &std::path::Path) -> Vec<Value> {
    let contents = std::fs::read_to_string(path).expect("read output");
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid JSON line"))
        .collect()
}

#[test]
fn first_alert_emits_immediately_without_event_count() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let out = dir.path().join("alerts.ndjson");
    let (sink, dedup, _guard) = setup(&out, 60);

    let alert = make_alert("Suspicious Shell", "/usr/bin/bash");
    sink.write_alert(&alert);

    // Flush the sink's writer.
    drop(sink);
    drop(_guard);
    drop(dedup);

    let lines = read_json_lines(&out);
    assert_eq!(lines.len(), 1, "exactly one line for the first alert");
    assert!(
        lines[0].get("event.count").is_none(),
        "singleton alert must not carry event.count"
    );
    assert_eq!(lines[0]["rule.name"], "Suspicious Shell");
}

#[test]
fn repeated_alerts_suppressed_and_rollup_emitted_on_flush() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let out = dir.path().join("alerts.ndjson");
    let (sink, dedup, _guard) = setup(&out, 60);

    let alert = make_alert("Suspicious Shell", "/usr/bin/bash");
    // First emission + 4 more repeats (should be suppressed).
    for _ in 0..5 {
        sink.write_alert(&alert);
    }

    // Manually flush_all to drain without waiting for the timer.
    dedup.flush_all(&sink);

    drop(sink);
    drop(_guard);

    let lines = read_json_lines(&out);
    assert_eq!(
        lines.len(),
        2,
        "expected: 1 live alert + 1 rollup; got {}",
        lines.len()
    );

    // Line 0: the live alert (no event.count)
    assert!(
        lines[0].get("event.count").is_none(),
        "live alert must not carry event.count"
    );

    // Line 1: the rollup
    assert_eq!(
        lines[1]["event.count"], 5,
        "rollup must carry event.count = 5 (all occurrences)"
    );
    assert_eq!(lines[1]["rule.name"], "Suspicious Shell");
}

#[test]
fn distinct_rules_tracked_and_flushed_independently() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let out = dir.path().join("alerts.ndjson");
    let (sink, dedup, _guard) = setup(&out, 60);

    let a = make_alert("Rule A", "/usr/bin/curl");
    let b = make_alert("Rule B", "/usr/bin/curl");

    sink.write_alert(&a);
    sink.write_alert(&b);
    sink.write_alert(&a); // second occurrence of Rule A
    sink.write_alert(&b); // second occurrence of Rule B

    dedup.flush_all(&sink);

    drop(sink);
    drop(_guard);

    let lines = read_json_lines(&out);
    // 2 live alerts + 2 rollups
    assert_eq!(lines.len(), 4, "2 live + 2 rollup lines");
    let rollups: Vec<&Value> = lines
        .iter()
        .filter(|l| l.get("event.count").is_some())
        .collect();
    assert_eq!(rollups.len(), 2, "two rollup lines (one per rule)");
    for rollup in rollups {
        assert_eq!(rollup["event.count"], 2, "each rollup has count=2");
    }
}

#[test]
fn no_rollup_for_alerts_that_occurred_only_once() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let out = dir.path().join("alerts.ndjson");
    let (sink, dedup, _guard) = setup(&out, 60);

    let a = make_alert("Rule A", "/usr/bin/curl");
    let b = make_alert("Rule B", "/usr/bin/ssh");
    sink.write_alert(&a);
    sink.write_alert(&b);

    dedup.flush_all(&sink);

    drop(sink);
    drop(_guard);

    let lines = read_json_lines(&out);
    assert_eq!(lines.len(), 2, "2 live alerts; no rollups for count=1");
    assert!(lines.iter().all(|l| l.get("event.count").is_none()));
}

#[test]
fn dedup_disabled_sink_passes_all_alerts_through() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let out = dir.path().join("alerts.ndjson");
    let file = std::fs::File::create(&out).expect("create output file");
    let (writer, guard) = tracing_appender::non_blocking(file);
    // No deduplicator attached.
    let sink = AlertSink::new(writer);

    let alert = make_alert("Rule A", "/usr/bin/curl");
    for _ in 0..3 {
        sink.write_alert(&alert);
    }

    drop(sink);
    drop(guard);

    let lines = read_json_lines(&out);
    assert_eq!(
        lines.len(),
        3,
        "with dedup off, all 3 alerts must be written"
    );
    assert!(lines.iter().all(|l| l.get("event.count").is_none()));
}
