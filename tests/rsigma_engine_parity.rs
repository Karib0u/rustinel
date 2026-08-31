//! Sigma detection parity checks across the built-in and RSigma engines.
//!
//! With the `rsigma-engine` feature enabled both backends are compiled in, so
//! each test builds one engine per available backend over the same rules and
//! events and asserts they reach the same verdict. Without the feature only the
//! built-in backend runs. The rules deliberately exercise the modifiers most
//! likely to diverge between the two matchers: `cidr` (where the RSigma adapter
//! yields values as strings) plus `re` and `contains|all`.

#[cfg(test)]
mod common;

use common::{
    network_connect_event, powershell_module_event, process_start_event,
    service_installation_event, SigmaFixture, TestNormalizer,
};
use rustinel::engine::{Engine, SigmaEngineKind};
use rustinel::models::MatchDebugLevel;
use rustinel::sensor::{Platform, SensorPayload};

/// Every Sigma backend compiled into this build.
fn backends() -> Vec<SigmaEngineKind> {
    vec![
        SigmaEngineKind::Builtin,
        #[cfg(feature = "rsigma-engine")]
        SigmaEngineKind::Rsigma,
    ]
}

fn engine_with(fixture: &SigmaFixture, platform: Platform, kind: SigmaEngineKind) -> Engine {
    let mut engine = Engine::new_for_platform_with_logging_level_and_match_debug(
        platform,
        "info",
        MatchDebugLevel::Off,
        kind,
    );
    engine
        .load_rules(fixture.rules_dir())
        .expect("sigma rules should load");
    assert_eq!(
        engine.stats().failed_rules,
        Vec::<(String, String)>::new(),
        "no rule should fail to load ({kind:?})"
    );
    engine
}

#[test]
fn cidr_and_port_rule_matches_network_event() {
    let fixture = SigmaFixture::new();
    // TEST_DESTINATION_IP is 198.51.100.10 on port 443.
    fixture.write_rule(
        "net_cidr.yml",
        r#"title: Parity Network CIDR
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: 198.51.100.0/24
    DestinationPort: '443'
  condition: selection
level: high
"#,
    );
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("network event should normalize");

    for kind in backends() {
        let engine = engine_with(&fixture, Platform::Linux, kind);
        let alert = engine
            .check_event(&normalized)
            .unwrap_or_else(|| panic!("cidr + port rule should match ({kind:?})"));
        assert_eq!(alert.rule_name, "Parity Network CIDR", "backend {kind:?}");
    }
}

#[test]
fn out_of_range_cidr_does_not_alert() {
    let fixture = SigmaFixture::new();
    // The destination (198.51.100.10) is outside 10.0.0.0/8; only the source
    // IP is in that range, and the rule matches on DestinationIp.
    fixture.write_rule(
        "net_miss.yml",
        r#"title: Parity Network Miss
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: 10.0.0.0/8
  condition: selection
level: high
"#,
    );
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("network event should normalize");

    for kind in backends() {
        let engine = engine_with(&fixture, Platform::Linux, kind);
        assert!(
            engine.check_event(&normalized).is_none(),
            "destination outside the CIDR must not alert ({kind:?})"
        );
    }
}

#[test]
fn contains_all_and_regex_rule_matches_process_event() {
    let fixture = SigmaFixture::new();
    // The process command line is "<image> https://example.test" and the image
    // ends in /curl.
    fixture.write_rule(
        "proc_all_re.yml",
        r#"title: Parity Process ContainsAll Regex
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - curl
      - example.test
    Image|re: '.*/curl$'
  condition: selection
level: high
"#,
    );
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .expect("process event should normalize");

    for kind in backends() {
        let engine = engine_with(&fixture, Platform::Linux, kind);
        let alert = engine
            .check_event(&normalized)
            .unwrap_or_else(|| panic!("contains|all + re rule should match ({kind:?})"));
        assert_eq!(
            alert.rule_name, "Parity Process ContainsAll Regex",
            "backend {kind:?}"
        );
    }
}

/// `Provider_Name` is carried on the event and `ImagePath` is an alias resolved
/// in `NormalizedEvent::get_field`, so both backends have to see them: the
/// RSigma adapter reads fields through that same accessor, but enumerates them
/// through serde, where the alias does not exist.
#[test]
fn service_provider_and_image_path_rule_matches_on_every_backend() {
    let fixture = SigmaFixture::new();
    fixture.write_service_rule();
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&service_installation_event())
        .expect("service event should normalize");

    for kind in backends() {
        let engine = engine_with(&fixture, Platform::Windows, kind);
        let alert = engine
            .check_event(&normalized)
            .unwrap_or_else(|| panic!("service rule should match ({kind:?})"));
        assert_eq!(
            alert.rule_name, "Test Service Installation",
            "backend {kind:?}"
        );
    }
}

#[test]
fn initiated_rules_separate_outbound_from_inbound_connections() {
    // Sysmon Event 3's `Initiated` is written as a string in rules even though
    // the model holds a boolean, and the two backends have to agree on that.
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "net_inbound.yml",
        r#"title: Parity Inbound Connection
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationPort: '443'
    Initiated: 'false'
  condition: selection
level: high
"#,
    );

    let harness = TestNormalizer::new(false);
    let outbound = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Windows))
        .expect("outbound event should normalize");

    let mut accepted = network_connect_event(Platform::Windows);
    if let SensorPayload::Network(fields) = &mut accepted.payload {
        fields.initiated = Some(false);
    }
    let inbound = harness
        .normalizer
        .normalize(&accepted)
        .expect("inbound event should normalize");

    for kind in backends() {
        let engine = engine_with(&fixture, Platform::Windows, kind);
        assert!(
            engine.check_event(&outbound).is_none(),
            "an outbound connection must not match Initiated: 'false' ({kind:?})"
        );
        let alert = engine
            .check_event(&inbound)
            .unwrap_or_else(|| panic!("an accepted connection should match ({kind:?})"));
        assert_eq!(
            alert.rule_name, "Parity Inbound Connection",
            "backend {kind:?}"
        );
    }
}

#[test]
fn an_unknown_direction_matches_neither_initiated_value() {
    // A sensor that cannot tell the direction leaves the field absent, and an
    // absent field matches no equality selection in either direction. Guessing
    // would silently answer a question the sensor never asked.
    let fixture = SigmaFixture::new();
    for (name, value) in [("net_true.yml", "true"), ("net_false.yml", "false")] {
        fixture.write_rule(
            name,
            &format!(
                r#"title: Parity Initiated {value}
logsource:
  product: macos
  category: network_connection
detection:
  selection:
    Initiated: '{value}'
  condition: selection
level: high
"#
            ),
        );
    }

    let mut unknown = network_connect_event(Platform::MacOS);
    if let SensorPayload::Network(fields) = &mut unknown.payload {
        fields.initiated = None;
    }
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&unknown)
        .expect("network event should normalize");

    for kind in backends() {
        let engine = engine_with(&fixture, Platform::MacOS, kind);
        assert!(
            engine.check_event(&normalized).is_none(),
            "an unknown direction must not match either value ({kind:?})"
        );
    }
}

#[test]
fn powershell_module_rule_matches_on_every_backend() {
    let fixture = SigmaFixture::new();
    fixture.write_ps_module_rule();
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&powershell_module_event())
        .expect("module logging event should normalize");

    for kind in backends() {
        let engine = engine_with(&fixture, Platform::Windows, kind);
        let alert = engine
            .check_event(&normalized)
            .unwrap_or_else(|| panic!("ps_module rule should match ({kind:?})"));
        assert_eq!(alert.rule_name, "Test PowerShell Module Download");
    }
}
