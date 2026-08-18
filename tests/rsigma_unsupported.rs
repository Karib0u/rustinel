#![cfg(feature = "rsigma-engine")]

use std::fs;

use rustinel::engine::{Engine, SigmaEngineKind, UnsupportedRuleKind};
use rustinel::models::MatchDebugLevel;
use rustinel::sensor::Platform;
use tempfile::TempDir;

fn engine_for(path: &std::path::Path) -> Engine {
    let mut engine = Engine::new_for_platform_with_logging_level_and_match_debug(
        Platform::Linux,
        "info",
        MatchDebugLevel::Off,
        SigmaEngineKind::Rsigma,
    );
    engine.load_rules(path).expect("Sigma rules should load");
    engine
}

#[test]
fn reports_correlations_and_filters_without_discarding_context() {
    let fixture = TempDir::new().expect("temporary rule directory");
    let path = fixture.path().join("collection.yml");
    fs::write(
        &path,
        r#"title: Base Process Rule
id: base-process-rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
---
title: Repeated Process Rule
id: repeated-process-rule
correlation:
  type: event_count
  rules:
    - base-process-rule
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 2
level: high
---
title: Suppress Admin Process
id: suppress-admin-process
logsource:
  product: linux
  category: process_creation
filter:
  rules:
    - base-process-rule
  selection:
    User: alice
  condition: selection
"#,
    )
    .expect("write Sigma fixture");

    let stats = engine_for(fixture.path()).stats();

    assert_eq!(stats.total_rules, 1);
    assert!(stats.failed_rules.is_empty());
    assert_eq!(stats.unsupported_rules.len(), 2);
    assert_eq!(stats.unsupported_correlation_rules, 1);
    assert_eq!(stats.unsupported_filter_rules, 1);

    let correlation = stats
        .unsupported_rules
        .iter()
        .find(|rule| rule.kind == UnsupportedRuleKind::Correlation)
        .expect("correlation diagnostic");
    assert_eq!(correlation.source_path, path.display().to_string());
    assert!(correlation.identity.contains("repeated-process-rule"));
    assert!(correlation.identity.contains("Repeated Process Rule"));
    assert!(correlation.reason.contains("stateful correlation"));
    assert!(correlation.reason.contains("#143"));

    let filter = stats
        .unsupported_rules
        .iter()
        .find(|rule| rule.kind == UnsupportedRuleKind::Filter)
        .expect("filter diagnostic");
    assert_eq!(filter.source_path, path.display().to_string());
    assert!(filter.identity.contains("suppress-admin-process"));
    assert!(filter.reason.contains("filter application"));
}

#[test]
fn reload_engine_stats_only_include_documents_in_the_new_collection() {
    let fixture = TempDir::new().expect("temporary rule directory");
    let path = fixture.path().join("collection.yml");
    fs::write(
        &path,
        r#"title: Base Process Rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
---
title: Repeated Process Rule
correlation:
  type: event_count
  rules: Base Process Rule
  group-by: Image
  timespan: 5m
  condition:
    gte: 2
"#,
    )
    .expect("write Sigma fixture");

    let initial_stats = engine_for(fixture.path()).stats();
    assert_eq!(initial_stats.unsupported_correlation_rules, 1);
    assert_eq!(initial_stats.unsupported_filter_rules, 0);

    fs::write(
        &path,
        r#"title: Reloaded Process Rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
"#,
    )
    .expect("rewrite Sigma fixture");

    let reloaded_stats = engine_for(fixture.path()).stats();
    assert_eq!(reloaded_stats.total_rules, 1);
    assert_eq!(reloaded_stats.unsupported_rules.len(), 0);
    assert_eq!(reloaded_stats.unsupported_correlation_rules, 0);
    assert_eq!(reloaded_stats.unsupported_filter_rules, 0);
}
