//! Application channel logsource routing and provider-specific matching.

mod common;

use std::time::SystemTime;

use common::{SigmaFixture, TestNormalizer};
use rustinel::config::AppConfig;
use rustinel::engine::compatibility::{analyze_rules, CompatibilityVerdict};
use rustinel::engine::{Engine, LogSource, LogSourceStatus};
use rustinel::field_availability::{availability_for_event, missing_always_fields, Availability};
use rustinel::models::{ApplicationEventFields, EventCategory};
use rustinel::sensor::{Platform, SensorAction, SensorEvent, SensorNormalization, SensorPayload};

fn event(provider: &str, id: u16) -> rustinel::models::NormalizedEvent {
    let mut fields = ApplicationEventFields::default();
    fields.insert("Provider_Name", provider);
    fields.insert("Level", "2");
    let raw = SensorEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Windows,
        provider: "windows_event_log",
        action: SensorAction::Access,
        normalization: SensorNormalization {
            event_id: id,
            action_code: 0,
        },
        pid: None,
        timestamp: SystemTime::now(),
        source_seq: Some(42),
        process_start_key: None,
        parent_process_start_key: None,
        payload: SensorPayload::Application(fields),
    };
    TestNormalizer::new().normalizer.normalize(&raw).unwrap()
}

#[test]
fn application_logsource_is_active_and_preserves_the_native_provider() {
    let engine = Engine::new_for_platform(Platform::Windows);
    let classification = engine.classify_logsource(&LogSource {
        product: Some("windows".to_string()),
        service: Some("application".to_string()),
        category: None,
    });
    assert_eq!(classification.status, LogSourceStatus::Supported);
    assert_eq!(classification.collector_active, Some(true));

    let normalized = event("Application Error", 1000);
    assert_eq!(normalized.category, EventCategory::Application);
    assert_eq!(normalized.provider, "windows_event_log");
    assert_eq!(normalized.get_field("Channel"), Some("Application"));
    assert_eq!(
        normalized.get_field("Provider_Name"),
        Some("Application Error")
    );
    assert!(missing_always_fields(&normalized).is_empty());
    let replay: rustinel::models::NormalizedEvent =
        serde_json::from_str(&serde_json::to_string(&normalized).unwrap()).unwrap();
    assert_eq!(replay.get_field("Provider_Name"), Some("Application Error"));
}

#[test]
fn rules_with_the_same_event_id_match_only_their_windows_provider() {
    let fixture = SigmaFixture::new();
    for (name, provider) in [
        ("manifest", "Microsoft-Windows-Audit-CVE"),
        ("classic", "Audit-CVE"),
    ] {
        fixture.write_rule(
            &format!("{name}.yml"),
            &format!(
                "title: {name}\nlogsource:\n  product: windows\n  service: application\ndetection:\n  selection:\n    Provider_Name: '{provider}'\n    EventID: 1\n  condition: selection\n"
            ),
        );
    }
    let mut engine = Engine::new_for_platform(Platform::Windows);
    engine.load_rules(fixture.rules_dir()).unwrap();
    assert_eq!(engine.stats().total_rules, 2);

    let manifest = event("Microsoft-Windows-Audit-CVE", 1);
    assert_eq!(engine.check_event(&manifest)[0].rule_name, "manifest");
    let classic = event("Audit-CVE", 1);
    assert_eq!(engine.check_event(&classic)[0].rule_name, "classic");
    assert_eq!(engine.check_event(&manifest).len(), 1);
    assert_eq!(engine.check_event(&classic).len(), 1);
}

#[test]
fn unavailable_message_field_is_reported_as_unsatisfiable() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "message.yml",
        "title: Formatted message\nlogsource:\n  product: windows\n  service: application\ndetection:\n  selection:\n    Provider_Name: MsiInstaller\n    EventID: 1033\n    Message|contains: AteraAgent\n  condition: selection\n",
    );
    let report = analyze_rules(
        fixture.rules_dir(),
        Platform::Windows,
        &AppConfig::default(),
    )
    .expect("analyze Application rule");
    assert_eq!(
        report.documents[0].verdict,
        CompatibilityVerdict::CanNeverFire
    );
    assert!(matches!(
        availability_for_event(&event("MsiInstaller", 1033), "Message"),
        Some(Availability::Never(_))
    ));
}

#[test]
fn provider_specific_field_cannot_be_claimed_by_another_provider() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "wrong-provider.yml",
        "title: Wrong provider shape\nlogsource:\n  product: windows\n  service: application\ndetection:\n  selection:\n    Provider_Name: Windows Error Reporting\n    EventID: 1001\n    AppName: lsass.exe\n  condition: selection\n",
    );
    let report = analyze_rules(
        fixture.rules_dir(),
        Platform::Windows,
        &AppConfig::default(),
    )
    .expect("analyze provider-specific rule");
    assert_eq!(
        report.documents[0].verdict,
        CompatibilityVerdict::CanNeverFire
    );
}

#[test]
fn application_level_matches_numeric_sigma_selector() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "level.yml",
        "title: numeric\nlogsource:\n  product: windows\n  service: application\ndetection:\n  selection:\n    Provider_Name: MSMQ\n    EventID: 2027\n    Level: 2\n  condition: selection\n",
    );
    let mut engine = Engine::new_for_platform(Platform::Windows);
    engine.load_rules(fixture.rules_dir()).unwrap();
    let application_event = event("MSMQ", 2027);
    assert_eq!(application_event.get_field("Level"), Some("2"));
    let names: Vec<_> = engine
        .check_event(&application_event)
        .into_iter()
        .map(|alert| alert.rule_name)
        .collect();
    assert_eq!(names, ["numeric"]);
}

#[test]
fn textual_application_level_is_reported_unsatisfiable() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "text-level.yml",
        "title: Text level\nlogsource:\n  product: windows\n  service: application\ndetection:\n  selection:\n    Provider_Name: MSExchange Control Panel\n    EventID: 4\n    Level: Error\n  condition: selection\n",
    );
    let report = analyze_rules(
        fixture.rules_dir(),
        Platform::Windows,
        &AppConfig::default(),
    )
    .expect("analyze numeric Level field");
    assert_eq!(
        report.documents[0].verdict,
        CompatibilityVerdict::CanNeverFire
    );
}
