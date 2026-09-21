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
