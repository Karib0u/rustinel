use rustinel::config::AppConfig;
use rustinel::engine::compatibility::analyze_rules;
use rustinel::sensor::Platform;

#[test]
fn first_party_rules_pack_report_matches_golden_schema() {
    let fixture = std::path::Path::new("tests/fixtures/sigma_compatibility");
    let report = analyze_rules(fixture, Platform::Linux, &AppConfig::default())
        .expect("compatibility fixture should analyze");
    let mut actual = serde_json::to_value(report).expect("report should serialize");
    actual["rules_path"] = serde_json::Value::String("<fixture>".to_string());
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/sigma_compatibility/expected-linux.json"
    ))
    .expect("golden report should parse");
    assert_eq!(actual, expected);
}

#[test]
fn remote_thread_rules_use_the_windows_route_and_report_field_gaps() {
    use rustinel::engine::Engine;
    use rustinel::models::{EventCategory, EventFields, NormalizedEvent, RemoteThreadFields};
    use std::{fs, process::Command};

    let rules = tempfile::tempdir().unwrap();
    for (name, selection) in [
        ("ids", "SourceProcessId: 101\n    TargetProcessId: 200"),
        (
            "address",
            "SourceProcessId: 102\n    StartAddress|endswith: '0B80'",
        ),
        (
            "module",
            "SourceProcessId: 103\n    StartModule|endswith: '\\kernel32.dll'",
        ),
        ("function", "StartFunction: LoadLibraryW"),
        ("empty-module", "StartModule: ''"),
        (
            "absent-module",
            "SourceProcessId: 104\n    StartModule: null",
        ),
    ] {
        fs::write(
            rules.path().join(format!("{name}.yml")),
            format!(
                "title: {name}\nlogsource:\n  product: windows\n  category: create_remote_thread\n\
                 detection:\n  selection:\n    EventID: 8\n    {selection}\n  condition: selection\nlevel: high\n"
            ),
        )
        .unwrap();
    }

    let mut engine = Engine::new_for_platform(Platform::Windows);
    engine.load_rules(rules.path()).unwrap();
    assert_eq!(engine.stats().total_rules, 6);

    let mut event: NormalizedEvent = serde_json::from_value(serde_json::json!({
        "event_time": "2026-11-01T00:00:00.000000000Z",
        "platform": "windows",
        "provider": "etw",
        "category": "RemoteThread",
        "event_id": 8,
        "opcode": 1,
        "fields": {
            "SourceProcessId": 101,
            "TargetProcessId": 200
        }
    }))
    .unwrap();
    assert_eq!(event.category, EventCategory::RemoteThread);
    let eval = |event: &NormalizedEvent| {
        engine
            .evaluate_event(event)
            .into_iter()
            .map(|alert| alert.rule_name)
            .collect::<Vec<_>>()
    };
    assert_eq!(eval(&event), ["ids"]);

    fn fields(event: &mut NormalizedEvent) -> &mut RemoteThreadFields {
        match &mut event.fields {
            EventFields::RemoteThread(fields) => fields,
            _ => unreachable!(),
        }
    }
    fields(&mut event).source_process_id = 102;
    assert!(eval(&event).is_empty());
    fields(&mut event).start_address = Some("0x00007FFC9B110B80".into());
    assert_eq!(eval(&event), ["address"]);
    fields(&mut event).source_process_id = 103;
    assert!(eval(&event).is_empty());
    fields(&mut event).start_module = Some(r"C:\Windows\System32\kernel32.dll".into());
    assert_eq!(eval(&event), ["module"]);
    fields(&mut event).source_process_id = 104;
    assert!(eval(&event).is_empty());
    fields(&mut event).start_module = None;
    assert_eq!(eval(&event), ["absent-module"]);

    let output = Command::new(env!("CARGO_BIN_EXE_rustinel"))
        .args([
            "sigma",
            "doctor",
            "--platform",
            "windows",
            "--json",
            "--rules",
        ])
        .arg(rules.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{:?}", output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let documents = report["documents"].as_array().unwrap();
    let document = |title| {
        documents
            .iter()
            .find(|doc| doc["title"] == title)
            .expect("rule appears in report")
    };
    for (title, verdict) in [
        ("ids", "can-fire"),
        ("address", "degraded"),
        ("module", "degraded"),
        ("function", "can-never-fire"),
        ("empty-module", "can-never-fire"),
    ] {
        let doc = document(title);
        assert_eq!(doc["verdict"], verdict, "{doc}");
        assert_eq!(doc["logsource"]["collector_active"], true);
    }
    for (title, field, availability) in [
        ("ids", "SourceProcessId", "always"),
        ("address", "StartAddress", "conditional"),
        ("module", "StartModule", "conditional"),
        ("function", "StartFunction", "never"),
    ] {
        assert!(
            document(title)["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["field"] == field && entry["availability"] == availability),
            "unexpected contract for {title}: {}",
            document(title)
        );
    }
}
