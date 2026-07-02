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

use common::{network_connect_event, process_start_event, SigmaFixture, TestNormalizer};
use rustinel::engine::{Engine, SigmaEngineKind};
use rustinel::models::MatchDebugLevel;
use rustinel::sensor::Platform;

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
