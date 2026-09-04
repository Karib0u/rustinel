use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;

use rustinel::engine::{Engine, EngineStats, UnsupportedRuleKind};
use rustinel::models::{
    EventCategory, EventFields, MatchDebugLevel, MatchDebugLevel::Off, NormalizedEvent,
    ProcessCreationFields,
};
use rustinel::sensor::Platform;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

const CORPUS_DIR_ENV: &str = "RUSTINEL_SIGMA_CORPUS_DIR";
const SUMMARY_PATH_ENV: &str = "RUSTINEL_SIGMA_COMPAT_OUTPUT";
const CORPUS_REPOSITORY: &str = "https://github.com/SigmaHQ/sigma";
const CORPUS_ROOTS: &[&str] = &[
    "rules",
    "rules-compliance",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
];

#[derive(Debug, PartialEq, Eq, Serialize)]
struct CompatibilitySummary {
    schema_version: u32,
    corpus: CorpusIdentity,
    platforms: BTreeMap<String, PlatformSummary>,
    run_errors: BTreeMap<String, String>,
    panics: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct CorpusIdentity {
    repository: String,
    commit: String,
    roots: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
struct PlatformSummary {
    rule_files_found: usize,
    verdicts: BTreeMap<String, BTreeMap<String, usize>>,
    rules_by_category: BTreeMap<String, usize>,
    rules_by_logsource: BTreeMap<String, usize>,
    deferred_logsources: BTreeMap<String, usize>,
    unknown_logsources: BTreeMap<String, usize>,
    failures: Vec<RuleFailure>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
struct RuleFailure {
    source: String,
    error: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct CompatibilityBaseline {
    schema_version: u32,
    corpus: CorpusIdentity,
    platforms: BTreeMap<String, PlatformBaseline>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct PlatformBaseline {
    rule_files_found: usize,
    verdicts: BTreeMap<String, BTreeMap<String, usize>>,
}

impl CompatibilitySummary {
    fn baseline(&self) -> CompatibilityBaseline {
        CompatibilityBaseline {
            schema_version: self.schema_version,
            corpus: self.corpus.clone(),
            platforms: self
                .platforms
                .iter()
                .map(|(platform, summary)| {
                    (
                        platform.clone(),
                        PlatformBaseline {
                            rule_files_found: summary.rule_files_found,
                            verdicts: summary.verdicts.clone(),
                        },
                    )
                })
                .collect(),
        }
    }
}

fn engine_for(platform: Platform, match_debug: MatchDebugLevel) -> Engine {
    Engine::new_for_platform_with_match_debug(platform, match_debug)
}

fn scan_platform(corpus_dir: &Path, platform: Platform) -> anyhow::Result<PlatformSummary> {
    let mut engine = engine_for(platform, Off);
    for root in CORPUS_ROOTS {
        engine.load_rules(corpus_dir.join(root))?;
    }

    let EngineStats {
        total_rules,
        rule_files_found,
        rules_by_category,
        rules_by_logsource,
        deferred_logsource_rules,
        unknown_logsource_rules,
        failed_rules,
        unsupported_rules,
        skipped_product_rules,
        skipped_deferred_rules,
        skipped_unknown_logsource_rules,
        inactive_collector_rules,
    } = engine.stats();

    anyhow::ensure!(
        inactive_collector_rules <= total_rules,
        "inactive collector count {inactive_collector_rules} exceeds loaded count {total_rules}"
    );
    let active_rules = total_rules - inactive_collector_rules;

    let mut verdicts = BTreeMap::new();
    verdicts.insert(
        "loaded".to_string(),
        BTreeMap::from([
            ("active_collector".to_string(), active_rules),
            ("inactive_collector".to_string(), inactive_collector_rules),
        ]),
    );
    verdicts.insert(
        "skipped".to_string(),
        BTreeMap::from([
            ("deferred_logsource".to_string(), skipped_deferred_rules),
            ("product_mismatch".to_string(), skipped_product_rules),
            (
                "unknown_logsource".to_string(),
                skipped_unknown_logsource_rules,
            ),
        ]),
    );
    verdicts.insert(
        "unsupported".to_string(),
        BTreeMap::from([("unresolved_reference".to_string(), unsupported_rules.len())]),
    );
    verdicts.insert(
        "failed".to_string(),
        BTreeMap::from([("rule_file".to_string(), failed_rules.len())]),
    );

    let unsupported_count = unsupported_rules
        .iter()
        .filter(|rule| rule.kind == UnsupportedRuleKind::UnresolvedReference)
        .count();
    anyhow::ensure!(
        unsupported_count == unsupported_rules.len(),
        "an unsupported Sigma document has an unknown reason"
    );

    let accounted_rule_files = total_rules
        + skipped_product_rules
        + skipped_deferred_rules
        + skipped_unknown_logsource_rules
        + unsupported_count
        + failed_rules.len();
    anyhow::ensure!(
        accounted_rule_files == rule_files_found,
        "{accounted_rule_files} of {rule_files_found} rule files have a known verdict and reason"
    );

    let failures = failed_rules
        .into_iter()
        .map(|(source, error)| RuleFailure {
            source: relative_source(corpus_dir, &source),
            error,
        })
        .collect();

    Ok(PlatformSummary {
        rule_files_found,
        verdicts,
        rules_by_category: rules_by_category.into_iter().collect(),
        rules_by_logsource: rules_by_logsource.into_iter().collect(),
        deferred_logsources: deferred_logsource_rules.into_iter().collect(),
        unknown_logsources: unknown_logsource_rules.into_iter().collect(),
        failures,
    })
}

fn relative_source(corpus_dir: &Path, source: &str) -> String {
    Path::new(source)
        .strip_prefix(corpus_dir)
        .unwrap_or_else(|_| Path::new(source))
        .display()
        .to_string()
}

fn checkout_commit(corpus_dir: &Path) -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["-C", &corpus_dir.display().to_string(), "rev-parse", "HEAD"])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "git rev-parse failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else {
        "non-string panic payload".to_string()
    }
}

fn summary_path() -> PathBuf {
    env::var_os(SUMMARY_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/sigma-compatibility.json"))
}

fn write_summary(path: &Path, summary: &CompatibilitySummary) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(summary)?),
    )?;
    Ok(())
}

fn process_event(timestamp: &str) -> NormalizedEvent {
    NormalizedEvent {
        timestamp: timestamp.to_string(),
        platform: Platform::Linux,
        provider: "test".to_string(),
        category: EventCategory::Process,
        event_id: 1,
        event_id_string: "1".to_string(),
        opcode: 1,
        fields: EventFields::ProcessCreation(ProcessCreationFields {
            image: Some("/usr/bin/curl".to_string()),
            command_line: None,
            process_id: Some("1234".to_string()),
            process_start_time: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: Some("alice".to_string()),
        }),
        process_context: None,
    }
}

#[test]
fn multi_document_collection_and_correlation_are_accounted_for() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("collection.yml"),
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
"#,
    )
    .expect("write collection fixture");

    let mut engine = engine_for(Platform::Linux, Off);
    engine
        .load_rules(fixture.path())
        .expect("multi-document collection should load");
    let stats = engine.stats();

    assert_eq!(stats.rule_files_found, 1);
    assert_eq!(stats.total_rules, 1);
    assert!(stats.unsupported_rules.is_empty());
    assert!(stats.failed_rules.is_empty());

    let first = engine.check_event(&process_event("2026-01-01T00:00:00Z"));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].rule_name, "Base Process Rule");

    let second = engine.check_event(&process_event("2026-01-01T00:00:01Z"));
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].rule_name, "Base Process Rule");
    assert_eq!(second[1].rule_name, "Repeated Process Rule");
}

#[test]
#[ignore = "requires the pinned SigmaHQ checkout"]
fn pinned_sigmahq_corpus_matches_baseline() {
    let corpus_dir = PathBuf::from(
        env::var_os(CORPUS_DIR_ENV)
            .unwrap_or_else(|| panic!("{CORPUS_DIR_ENV} must point to the SigmaHQ checkout")),
    );
    let output_path = summary_path();
    let expected: CompatibilityBaseline =
        serde_json::from_str(include_str!("../compatibility/sigmahq-baseline.json"))
            .expect("compatibility baseline should be valid JSON");

    let mut actual = CompatibilitySummary {
        schema_version: expected.schema_version,
        corpus: CorpusIdentity {
            repository: CORPUS_REPOSITORY.to_string(),
            commit: String::new(),
            roots: CORPUS_ROOTS
                .iter()
                .map(|root| (*root).to_string())
                .collect(),
        },
        platforms: BTreeMap::new(),
        run_errors: BTreeMap::new(),
        panics: BTreeMap::new(),
    };

    match checkout_commit(&corpus_dir) {
        Ok(commit) => actual.corpus.commit = commit,
        Err(error) => {
            actual
                .run_errors
                .insert("corpus_checkout".to_string(), error.to_string());
        }
    }

    for (name, platform) in [
        ("windows", Platform::Windows),
        ("linux", Platform::Linux),
        ("macos", Platform::MacOS),
    ] {
        match catch_unwind(AssertUnwindSafe(|| scan_platform(&corpus_dir, platform))) {
            Ok(Ok(summary)) => {
                actual.platforms.insert(name.to_string(), summary);
            }
            Ok(Err(error)) => {
                actual
                    .run_errors
                    .insert(name.to_string(), error.to_string());
            }
            Err(payload) => {
                actual
                    .panics
                    .insert(name.to_string(), panic_message(payload));
            }
        }
    }

    write_summary(&output_path, &actual).expect("write machine-readable compatibility summary");

    assert!(
        actual.run_errors.is_empty(),
        "compatibility run errors were recorded in {}",
        output_path.display()
    );
    assert!(
        actual.panics.is_empty(),
        "compatibility panics were recorded in {}",
        output_path.display()
    );
    assert!(
        actual
            .platforms
            .values()
            .all(|summary| summary.failures.is_empty()),
        "Sigma parser or compiler errors were recorded in {}",
        output_path.display()
    );
    assert!(
        actual.baseline() == expected,
        "SigmaHQ compatibility counts drifted; inspect {} and update the baseline only with an explanation",
        output_path.display()
    );
}
