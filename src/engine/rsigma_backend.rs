//! RSigma-backed detection engine wiring.
//!
//! Compiled only with the `rsigma-engine` feature. Provides the RSigma
//! variants of [`Engine::load_rule`] and [`Engine::check_event`] plus the rule
//! store, while reusing Rustinel's shared logsource classification
//! ([`Engine::rule_load_decision`]) and event routing
//! ([`Engine::sigma_logsources_for_event`]) so platform filtering and
//! per-logsource bucketing behave exactly as the built-in backend.
//!
//! Rules are parsed with `rsigma-parser`, compiled into one `rsigma_eval::Engine`
//! per normalized `LogSourceKey`, and matched with `rsigma-eval`. Results are
//! mapped back onto Rustinel's [`Alert`] so the ECS output, hot reload, and
//! IOC/YARA paths are untouched.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use rsigma_eval::{Engine as RsEngine, EvaluationResult, MatchDetailLevel, MatcherKind};
use rsigma_parser::{
    parse_sigma_yaml, Level as RsLevel, LogSource as RsLogSource, SigmaRule as RsRule,
};

use super::{Engine, LogSourceKey, MatchRank, RuleLoadDecision, UnsupportedRuleKind};
use crate::engine::rsigma_adapter::RsigmaEvent;
use crate::models::{
    Alert, AlertSeverity, DetectionEngine, MatchDebugLevel, MatchDetails, NormalizedEvent,
    SigmaFieldMatch, SigmaKeywordMatch, SigmaMatchDetails,
};

/// Per-logsource RSigma engines plus rule descriptions.
///
/// Keyed by the same normalized `LogSourceKey` buckets Rustinel's routing
/// produces, so an event's candidate logsources select the same rule set the
/// built-in backend would consult.
#[derive(Default)]
pub(crate) struct RsigmaStore {
    engines: HashMap<LogSourceKey, RsEngine>,
    counts: HashMap<LogSourceKey, usize>,
    /// Rule id (and title) to description. RSigma's result header omits the
    /// description, so it is captured at load time for `Alert::rule_description`.
    descriptions: HashMap<String, String>,
}

impl RsigmaStore {
    /// Per-logsource loaded-rule counts, for engine stats.
    pub(crate) fn counts(&self) -> &HashMap<LogSourceKey, usize> {
        &self.counts
    }

    fn add_rule(
        &mut self,
        key: &LogSourceKey,
        rule: &RsRule,
        match_detail: MatchDetailLevel,
    ) -> Result<()> {
        let engine = self.engines.entry(key.clone()).or_insert_with(|| {
            let mut engine = RsEngine::new();
            // Rustinel keeps the NormalizedEvent on the alert and enriches
            // process context itself, so the engine never duplicates it.
            engine.set_include_event(false);
            engine.set_match_detail(match_detail);
            engine
        });
        engine
            .add_rule(rule)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        *self.counts.entry(key.clone()).or_default() += 1;

        if let Some(description) = &rule.description {
            if let Some(id) = &rule.id {
                self.descriptions.insert(id.clone(), description.clone());
            }
            self.descriptions
                .insert(rule.title.clone(), description.clone());
        }
        Ok(())
    }

    fn description_for(&self, rule_id: Option<&str>, rule_title: &str) -> Option<String> {
        rule_id
            .and_then(|id| self.descriptions.get(id))
            .or_else(|| self.descriptions.get(rule_title))
            .cloned()
    }
}

/// Normalize an `rsigma-parser` logsource into Rustinel's routing key.
fn logsource_key(logsource: &RsLogSource) -> LogSourceKey {
    LogSourceKey {
        product: LogSourceKey::normalize_value(logsource.product.as_deref()),
        service: LogSourceKey::normalize_value(logsource.service.as_deref()),
        category: LogSourceKey::normalize_value(logsource.category.as_deref()),
    }
}

fn match_detail_level(debug: MatchDebugLevel) -> MatchDetailLevel {
    match debug {
        MatchDebugLevel::Off => MatchDetailLevel::Off,
        MatchDebugLevel::Summary => MatchDetailLevel::Summary,
        MatchDebugLevel::Full => MatchDetailLevel::Full,
    }
}

fn severity_from_level(level: Option<RsLevel>) -> AlertSeverity {
    match level {
        Some(RsLevel::Critical) => AlertSeverity::Critical,
        Some(RsLevel::High) => AlertSeverity::High,
        Some(RsLevel::Medium) => AlertSeverity::Medium,
        _ => AlertSeverity::Low,
    }
}

/// Rank a detection under the shared single-alert selection policy.
fn result_rank(result: &EvaluationResult) -> MatchRank<'_> {
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

fn document_identity(id: Option<&str>, title: &str) -> String {
    match id {
        Some(id) => format!("id '{id}', title '{title}'"),
        None => format!("title '{title}'"),
    }
}

impl Engine {
    /// RSigma variant of the single-file rule loader.
    ///
    /// Parses the file with `rsigma-parser` (which natively expands
    /// `action: global`/`reset`/`repeat`), applies Rustinel's platform/logsource
    /// load decision to each rule, and compiles accepted rules into the
    /// per-logsource RSigma engines.
    pub(crate) fn load_rule_rsigma<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).context("Failed to read rule file")?;
        let collection = parse_sigma_yaml(&content).map_err(|err| anyhow::anyhow!("{err}"))?;

        for error in &collection.errors {
            self.failed_rules
                .push((path.display().to_string(), error.clone()));
        }

        for correlation in &collection.correlations {
            self.record_unsupported_rule(
                path,
                UnsupportedRuleKind::Correlation,
                document_identity(correlation.id.as_deref(), &correlation.title),
                "RSigma correlation documents are parsed but stateful correlation evaluation is not integrated into Rustinel; support remains tracked by issue #143",
            );
        }
        for filter in &collection.filters {
            self.record_unsupported_rule(
                path,
                UnsupportedRuleKind::Filter,
                document_identity(filter.id.as_deref(), &filter.title),
                "RSigma filter documents are parsed but filter application is not integrated into Rustinel's stateless event matcher",
            );
        }

        let match_detail = match_detail_level(self.match_debug);
        for rule in &collection.rules {
            let logsource = logsource_key(&rule.logsource);
            let decision = self.rule_load_decision(&logsource);
            self.record_skip_for_logsource(decision, &logsource);

            if !matches!(decision, RuleLoadDecision::Load { .. }) {
                continue;
            }

            self.rsigma.add_rule(&logsource, rule, match_detail)?;
            self.rule_count += 1;
        }

        Ok(())
    }

    /// RSigma variant of the inline detection check.
    ///
    /// Routes the event to candidate logsources exactly as the built-in
    /// backend, then evaluates the RSigma engine for each candidate bucket and
    /// maps the best detection to an [`Alert`].
    ///
    /// "Best" is the same [`MatchRank`] policy the built-in backend applies, so
    /// a low-severity rule cannot shadow a higher-severity match on either
    /// backend, and the outcome does not depend on rule load order.
    pub(crate) fn check_event_rsigma(&self, event: &NormalizedEvent) -> Option<Alert> {
        let candidate_logsources = Self::sigma_logsources_for_event(event);
        let adapter = RsigmaEvent::new(event);
        let mut best: Option<EvaluationResult> = None;

        for logsource in candidate_logsources {
            let Some(engine) = self.rsigma.engines.get(&logsource) else {
                continue;
            };

            for result in engine
                .evaluate(&adapter)
                .into_iter()
                .filter(EvaluationResult::is_detection)
            {
                let is_better = match &best {
                    Some(current) => result_rank(&result) < result_rank(current),
                    None => true,
                };
                if is_better {
                    best = Some(result);
                }
            }
        }

        best.map(|result| self.rsigma_alert(result, event))
    }

    fn rsigma_alert(&self, result: EvaluationResult, event: &NormalizedEvent) -> Alert {
        let severity = severity_from_level(result.header.level);
        let rule_id = result
            .header
            .rule_id
            .as_deref()
            .map(|id| format!("sigma::{id}"));
        let rule_description = self
            .rsigma
            .description_for(result.header.rule_id.as_deref(), &result.header.rule_title);
        let match_details = self.rsigma_match_details(&result);

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

    fn rsigma_match_details(&self, result: &EvaluationResult) -> Option<MatchDetails> {
        if matches!(self.match_debug, MatchDebugLevel::Off) {
            return None;
        }
        let detection = result.as_detection()?;

        let selection_results: HashMap<String, bool> = detection
            .matched_selections
            .iter()
            .map(|selection| (selection.clone(), true))
            .collect();

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
                    value: value_to_string(&field_match.value),
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
                value: value_to_string(&field_match.value),
            })
            .collect();

        let summary = format!("rule '{}' matched", result.header.rule_title);

        Some(MatchDetails {
            summary,
            sigma: Some(SigmaMatchDetails {
                condition: None,
                selection_results,
                matches,
                keyword_matches,
            }),
            yara: None,
        })
    }
}
