//! The compiled Sigma rule store.
//!
//! Rustinel keeps one RSigma correlation engine for the complete loaded
//! collection. Its inner detection engine still exposes logsource routing, but
//! the correlation state and all referenced rules share one owner.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use anyhow::Result;
use rsigma_eval::{CorrelationConfig, CorrelationEngine, EvaluationResult, MatchDetailLevel};
use rsigma_parser::SigmaCollection;

use super::logsource::logsource_key;
use super::LogSourceKey;
use crate::models::MatchDebugLevel;

/// Compiled RSigma rules, correlation state, counts, and rule metadata.
///
/// Deliberately not `Default`: the engine has to be built through
/// [`RuleStore::new`], which applies the match-detail and event-inclusion
/// settings a bare `CorrelationEngine` would silently miss.
pub(crate) struct RuleStore {
    engine: Mutex<CorrelationEngine>,
    counts: HashMap<LogSourceKey, usize>,
    /// Rule id or title to description. RSigma result headers do not carry the
    /// description, so it is captured when the collection is loaded.
    descriptions: HashMap<String, String>,
    /// Rule id or title to the raw detection condition. RSigma result headers
    /// do not carry it, so it is captured for match-debug output.
    conditions: HashMap<String, String>,
    /// `(effective_id, title)` pairs assigned to named rules that had no ID.
    /// RSigma uses the ID field to route detection results into correlations,
    /// so these IDs are removed again before Rustinel builds an alert.
    synthetic_detection_ids: std::collections::HashSet<(String, String)>,
}

impl RuleStore {
    pub(crate) fn new(match_debug: MatchDebugLevel) -> Self {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        // Rustinel keeps the NormalizedEvent on the alert and enriches process
        // context itself, so RSigma does not need to copy the event into every
        // detection result.
        engine.set_include_event(false);
        engine.set_match_detail(match_detail_level(match_debug));

        Self {
            engine: Mutex::new(engine),
            counts: HashMap::new(),
            descriptions: HashMap::new(),
            conditions: HashMap::new(),
            synthetic_detection_ids: std::collections::HashSet::new(),
        }
    }

    /// Lock the shared engine for detection and correlation processing.
    ///
    /// A poisoned lock is recovered rather than propagated. This mutex is taken
    /// for every event, so panicking on poison would turn one panic anywhere
    /// under the lock into a permanent Sigma outage for the rest of the
    /// process's life. Correlation windows may be left mid-update, which costs
    /// at most an inaccurate aggregate; losing detection entirely is worse.
    pub(crate) fn lock(&self) -> MutexGuard<'_, CorrelationEngine> {
        self.engine.lock().unwrap_or_else(|poisoned| {
            tracing::warn!(
                "Sigma correlation engine mutex was poisoned by an earlier panic; \
                 continuing with the recovered state"
            );
            poisoned.into_inner()
        })
    }

    /// Per-logsource loaded-rule counts, for engine stats.
    pub(crate) fn counts(&self) -> &HashMap<LogSourceKey, usize> {
        &self.counts
    }

    /// Add one complete, already-filtered Sigma collection.
    pub(crate) fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        // RSigma resolves correlation references by the result's rule ID first.
        // Give an ID-less named rule its name as an internal ID so correlations
        // that use that name also work. The ID is restored before alert mapping.
        let mut compiled_collection = collection.clone();
        let mut synthetic_ids = Vec::new();
        for rule in &mut compiled_collection.rules {
            if rule.id.is_none() {
                if let Some(name) = rule.name.as_deref().filter(|name| !name.is_empty()) {
                    rule.id = Some(name.to_string());
                    synthetic_ids.push((name.to_string(), rule.title.clone()));
                }
            }
        }

        let mut engine = self.lock();
        engine
            .add_collection(&compiled_collection)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        drop(engine);
        self.synthetic_detection_ids.extend(synthetic_ids);

        for rule in &collection.rules {
            *self
                .counts
                .entry(logsource_key(&rule.logsource))
                .or_default() += 1;
            self.remember_description(rule.id.as_deref(), &rule.title, &rule.description);
            if let Some(condition) = rule.detection.condition_strings.first() {
                self.remember_condition(rule.id.as_deref(), &rule.title, condition);
            }
        }
        for correlation in &collection.correlations {
            self.remember_description(
                correlation.id.as_deref(),
                &correlation.title,
                &correlation.description,
            );
        }

        Ok(())
    }

    fn remember_description(
        &mut self,
        id: Option<&str>,
        title: &str,
        description: &Option<String>,
    ) {
        let Some(description) = description else {
            return;
        };

        if let Some(id) = id {
            self.descriptions
                .insert(id.to_string(), description.clone());
        }
        self.descriptions
            .insert(title.to_string(), description.clone());
    }

    fn remember_condition(&mut self, id: Option<&str>, title: &str, condition: &str) {
        if let Some(id) = id {
            self.conditions
                .insert(id.to_string(), condition.to_string());
        }
        self.conditions
            .insert(title.to_string(), condition.to_string());
    }

    pub(crate) fn description_for(
        &self,
        rule_id: Option<&str>,
        rule_title: &str,
    ) -> Option<String> {
        rule_id
            .and_then(|id| self.descriptions.get(id))
            .or_else(|| self.descriptions.get(rule_title))
            .cloned()
    }

    pub(crate) fn condition_for(&self, rule_id: Option<&str>, rule_title: &str) -> Option<String> {
        rule_id
            .and_then(|id| self.conditions.get(id))
            .or_else(|| self.conditions.get(rule_title))
            .cloned()
    }

    pub(crate) fn restore_synthetic_detection_id(&self, result: &mut EvaluationResult) {
        if !result.is_detection() {
            return;
        }

        if let Some(id) = result.header.rule_id.as_deref() {
            if self
                .synthetic_detection_ids
                .contains(&(id.to_string(), result.header.rule_title.clone()))
            {
                result.header.rule_id = None;
            }
        }
    }
}

fn match_detail_level(debug: MatchDebugLevel) -> MatchDetailLevel {
    match debug {
        MatchDebugLevel::Off => MatchDetailLevel::Off,
        MatchDebugLevel::Summary => MatchDetailLevel::Summary,
        MatchDebugLevel::Full => MatchDetailLevel::Full,
    }
}
