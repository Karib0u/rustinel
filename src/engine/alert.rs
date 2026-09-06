//! Mapping an RSigma [`EvaluationResult`] onto Rustinel's [`Alert`].

use std::collections::HashMap;

use rsigma_eval::{EvaluationResult, MatcherKind};
use rsigma_parser::Level as RsLevel;

use super::{Engine, MatchRank};
use crate::models::{
    Alert, AlertSeverity, CorrelationMatchDetails, DetectionEngine, MatchDebugLevel, MatchDetails,
    NormalizedEvent, SigmaFieldMatch, SigmaKeywordMatch, SigmaMatchDetails,
};

pub(crate) fn severity_from_level(level: Option<RsLevel>) -> AlertSeverity {
    match level {
        Some(RsLevel::Critical) => AlertSeverity::Critical,
        Some(RsLevel::High) => AlertSeverity::High,
        Some(RsLevel::Medium) => AlertSeverity::Medium,
        _ => AlertSeverity::Low,
    }
}

/// Rank a detection under the single-alert selection policy.
pub(crate) fn result_rank(result: &EvaluationResult) -> MatchRank<'_> {
    MatchRank::new(
        severity_from_level(result.header.level),
        result.header.rule_id.as_deref(),
        &result.header.rule_title,
    )
}

fn matcher_kind_str(kind: MatcherKind) -> &'static str {
    match kind {
        MatcherKind::Exact => "exact",
        MatcherKind::Contains => "contains",
        MatcherKind::StartsWith => "startswith",
        MatcherKind::EndsWith => "endswith",
        MatcherKind::Regex => "regex",
        MatcherKind::OneOf => "one_of",
        MatcherKind::Cidr => "cidr",
        MatcherKind::Numeric => "numeric",
        MatcherKind::Exists => "exists",
        MatcherKind::FieldRef => "fieldref",
        MatcherKind::Null => "null",
        MatcherKind::Bool => "bool",
        MatcherKind::Expand => "expand",
        MatcherKind::Timestamp => "timestamp",
        MatcherKind::Keyword => "keyword",
    }
}

fn value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

impl Engine {
    pub(crate) fn build_alert(&self, result: EvaluationResult, event: &NormalizedEvent) -> Alert {
        let severity = severity_from_level(result.header.level);
        let rule_id = result
            .header
            .rule_id
            .as_deref()
            .map(|id| format!("sigma::{id}"));
        let rule_description = self
            .store
            .description_for(result.header.rule_id.as_deref(), &result.header.rule_title);
        let match_details = self.build_match_details(&result);

        Alert {
            severity,
            rule_name: result.header.rule_title.clone(),
            rule_description,
            rule_id,
            engine: DetectionEngine::Sigma,
            event: event.clone(),
            match_details,
        }
    }

    fn build_match_details(&self, result: &EvaluationResult) -> Option<MatchDetails> {
        if let Some(correlation) = result.as_correlation() {
            return Some(MatchDetails {
                summary: format!("correlation rule '{}' fired", result.header.rule_title),
                sigma: None,
                correlation: Some(CorrelationMatchDetails {
                    correlation_type: correlation.correlation_type.as_str().to_string(),
                    group_key: correlation.group_key.clone(),
                    aggregated_value: correlation.aggregated_value,
                    timespan_secs: correlation.timespan_secs,
                }),
                yara: None,
            });
        }

        if matches!(self.match_debug, MatchDebugLevel::Off) {
            return None;
        }
        let detection = result.as_detection()?;

        let selection_results: HashMap<String, bool> = detection
            .matched_selections
            .iter()
            .map(|selection| (selection.clone(), true))
            .collect();
        let include_values = matches!(self.match_debug, MatchDebugLevel::Full);

        let matches: Vec<SigmaFieldMatch> = detection
            .matched_fields
            .iter()
            .filter(|field_match| field_match.field != "keyword")
            .map(|field_match| {
                let matcher = field_match
                    .matcher
                    .map(matcher_kind_str)
                    .unwrap_or_default();
                SigmaFieldMatch {
                    selection: field_match.selection.clone().unwrap_or_default(),
                    field: field_match.field.clone(),
                    matcher: matcher.to_string(),
                    pattern_type: matcher.to_string(),
                    pattern: field_match.pattern.clone().unwrap_or_default(),
                    case_sensitive: field_match.case_sensitive,
                    value: include_values
                        .then(|| value_to_string(&field_match.value))
                        .flatten(),
                }
            })
            .collect();

        let keyword_matches: Vec<SigmaKeywordMatch> = detection
            .matched_fields
            .iter()
            .filter(|field_match| field_match.field == "keyword")
            .map(|field_match| SigmaKeywordMatch {
                selection: field_match.selection.clone().unwrap_or_default(),
                pattern_type: "keyword".to_string(),
                keyword: field_match.pattern.clone().unwrap_or_default(),
                field: None,
                value: include_values
                    .then(|| value_to_string(&field_match.value))
                    .flatten(),
            })
            .collect();

        let summary = format!("rule '{}' matched", result.header.rule_title);
        let condition = self
            .store
            .condition_for(result.header.rule_id.as_deref(), &result.header.rule_title);

        Some(MatchDetails {
            summary,
            sigma: Some(SigmaMatchDetails {
                condition,
                selection_results,
                matches,
                keyword_matches,
            }),
            correlation: None,
            yara: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventCategory, EventFields, ProcessCreationFields};
    use crate::sensor::Platform;

    const RULE: &str = r#"title: Test image rule
id: test-image-rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: tool.exe
  condition: selection
level: high
"#;

    fn engine_with_image_rule(match_debug: MatchDebugLevel) -> Engine {
        let dir = tempfile::tempdir().expect("temporary rule directory");
        std::fs::write(dir.path().join("rule.yml"), RULE).expect("write rule");
        let mut engine = Engine::new_for_platform_with_match_debug(Platform::Windows, match_debug);
        engine.load_rules(dir.path()).expect("rules should load");
        engine
    }

    fn process_event(image: &str) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: "2026-08-16T12:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image.to_string()),
                image_source: None,
                command_line: None,
                process_id: None,
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
            }),
            process_context: None,
        }
    }

    #[test]
    fn alert_without_match_details_remains_complete() {
        let engine = engine_with_image_rule(MatchDebugLevel::Off);
        let event = process_event(r"C:\Program Files\Example\tool.exe");

        let alert = engine
            .check_event(&event)
            .into_iter()
            .next()
            .expect("matching event produces an alert");

        assert_eq!(alert.rule_name, "Test image rule");
        assert_eq!(alert.rule_id.as_deref(), Some("sigma::test-image-rule"));
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.match_details.is_none());
        assert_eq!(alert.event.get_field("Image"), event.get_field("Image"));
    }

    #[test]
    fn full_match_details_name_the_matched_field() {
        let engine = engine_with_image_rule(MatchDebugLevel::Full);
        let event = process_event(r"C:\Program Files\Example\tool.exe");

        let alert = engine
            .check_event(&event)
            .into_iter()
            .next()
            .expect("matching event produces an alert");
        let details = alert.match_details.expect("full details are present");
        let sigma = details.sigma.expect("Sigma details are present");

        assert!(sigma
            .matches
            .iter()
            .any(|field_match| field_match.field == "Image" && field_match.matcher == "contains"));
        assert!(sigma.selection_results.contains_key("selection"));
        assert_eq!(sigma.condition.as_deref(), Some("selection"));
    }
}
