//! Loading Sigma rules from disk.
//!
//! The directory walk parses each file into one accumulated
//! [`rsigma_parser::SigmaCollection`]. Rustinel filters detection rules before
//! passing the complete collection to one [`rsigma_eval::CorrelationEngine`].
//! Keeping the collection intact until that call lets correlations and filters
//! resolve rules across files and logsource buckets.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rsigma_parser::{
    parse_sigma_yaml, ConditionOperator, CorrelationCondition, CorrelationRule, CorrelationType,
    FilterRule, FilterRuleTarget, SigmaCollection, SigmaRule,
};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::utils::rule_dirs::{RuleCollision, RuleDirectoryReport, RuleDirectoryRole};

use super::logsource::{logsource_key, normalize_logsource_in_place};
use super::{Engine, RuleLoadDecision, UnsupportedRuleKind};

fn document_identity(id: Option<&str>, title: &str) -> String {
    match id {
        Some(id) => format!("id '{id}', title '{title}'"),
        None => format!("title '{title}'"),
    }
}

/// Source paths for documents after the parser has grouped them by type.
/// `SigmaCollection` intentionally does not retain this information.
#[derive(Default)]
struct DocumentSources {
    rules: std::collections::HashMap<String, String>,
    correlations: std::collections::HashMap<String, String>,
    filters: std::collections::HashMap<String, String>,
    /// Temporal correlations whose source omitted `condition`. The parser AST
    /// otherwise makes omission indistinguishable from an explicit `gte: 1`.
    temporal_without_condition: HashSet<String>,
}

impl DocumentSources {
    fn extend(&mut self, other: DocumentSources) {
        self.rules.extend(other.rules);
        self.correlations.extend(other.correlations);
        self.filters.extend(other.filters);
        self.temporal_without_condition
            .extend(other.temporal_without_condition);
    }

    fn add_collection(
        &mut self,
        source_path: &str,
        content: &str,
        collection: &SigmaCollection,
    ) -> Result<Vec<String>> {
        let mut diagnostics = Vec::new();
        for rule in &collection.rules {
            self.rules.insert(
                document_identity(rule.id.as_deref(), &rule.title),
                source_path.to_string(),
            );
        }
        for correlation in &collection.correlations {
            self.correlations.insert(
                document_identity(correlation.id.as_deref(), &correlation.title),
                source_path.to_string(),
            );
        }
        for filter in &collection.filters {
            self.filters.insert(
                document_identity(filter.id.as_deref(), &filter.title),
                source_path.to_string(),
            );
        }

        // Preserve whether the source omitted the temporal condition before
        // the parser replaces that omission with its current default.
        for document in yaml_serde::Deserializer::from_str(content) {
            let value = yaml_serde::Value::deserialize(document)
                .context("Failed to inspect parsed Sigma document")?;
            if let Some(level) = value.get("level") {
                if level.as_str().is_none() {
                    diagnostics.push(format!(
                        "invalid level {level:?}, expected a string containing one of: informational, low, medium, high, critical"
                    ));
                }
            }
            let Some(correlation) = value.get("correlation") else {
                continue;
            };
            if correlation.get("type").and_then(|value| value.as_str()) != Some("temporal")
                || correlation.get("condition").is_some()
            {
                continue;
            }

            let Some(title) = value.get("title").and_then(|value| value.as_str()) else {
                continue;
            };
            let id = value.get("id").and_then(|value| value.as_str());
            self.temporal_without_condition
                .insert(document_identity(id, title));
        }

        Ok(diagnostics)
    }

    fn rule_path(&self, rule: &SigmaRule) -> String {
        self.rules
            .get(&document_identity(rule.id.as_deref(), &rule.title))
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    fn correlation_path(&self, correlation: &CorrelationRule) -> String {
        self.correlations
            .get(&document_identity(
                correlation.id.as_deref(),
                &correlation.title,
            ))
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    fn filter_path(&self, filter: &FilterRule) -> String {
        self.filters
            .get(&document_identity(filter.id.as_deref(), &filter.title))
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    fn temporal_condition_was_omitted(&self, correlation: &CorrelationRule) -> bool {
        self.temporal_without_condition.contains(&document_identity(
            correlation.id.as_deref(),
            &correlation.title,
        ))
    }
}

impl Engine {
    pub fn load_rules<P: AsRef<Path>>(&mut self, rules_dir: P) -> Result<()> {
        self.load_rules_with_trust(rules_dir, None)
    }

    pub fn load_rules_with_trust<P: AsRef<Path>>(
        &mut self,
        rules_dir: P,
        trust: Option<&crate::utils::trust::RuleTrust>,
    ) -> Result<()> {
        self.load_rule_dirs_with_trust(rules_dir.as_ref(), &[], trust)
    }

    /// Load the managed pack directory and then each local directory into one
    /// rule set. Every directory is trust-checked before anything is read, and
    /// any failure rejects the whole load. A local rule that reuses the `id` of
    /// a rule from an earlier directory replaces it and is recorded as a
    /// collision.
    pub fn load_rule_dirs_with_trust(
        &mut self,
        pack_dir: &Path,
        local_dirs: &[PathBuf],
        trust: Option<&crate::utils::trust::RuleTrust>,
    ) -> Result<()> {
        let directories = std::iter::once((pack_dir, RuleDirectoryRole::Pack))
            .chain(
                local_dirs
                    .iter()
                    .map(|dir| (dir.as_path(), RuleDirectoryRole::Local)),
            )
            .collect::<Vec<_>>();

        let mut collection = SigmaCollection::new();
        let mut sources = DocumentSources::default();
        let mut reports = Vec::new();
        let mut collisions = Vec::new();

        for (dir, role) in directories {
            let mut report = RuleDirectoryReport::new(dir, role);
            if !dir.exists() {
                info!("Rules directory does not exist: {:?}", dir);
                reports.push(report);
                continue;
            }

            crate::utils::trust::verify_rule_input(dir, trust).with_context(|| {
                format!("{} Sigma rules directory {}", role.as_str(), dir.display())
            })?;
            info!(
                role = role.as_str(),
                "Loading Sigma rules from: {:?} (recursive)", dir
            );

            let files_before = self.rule_files_found;
            let mut dir_collection = SigmaCollection::new();
            let mut dir_sources = DocumentSources::default();
            self.collect_rules_recursive(dir, &mut dir_collection, &mut dir_sources)
                .with_context(|| {
                    format!("{} Sigma rules directory {}", role.as_str(), dir.display())
                })?;
            report.files = self.rule_files_found - files_before;

            if role == RuleDirectoryRole::Local {
                for rule in &dir_collection.rules {
                    let Some(id) = rule.id.as_deref() else {
                        continue;
                    };
                    let overridden = collection
                        .rules
                        .iter()
                        .find(|earlier| earlier.id.as_deref() == Some(id))
                        .map(|earlier| sources.rule_path(earlier));
                    let Some(overridden) = overridden else {
                        continue;
                    };
                    collection
                        .rules
                        .retain(|earlier| earlier.id.as_deref() != Some(id));
                    let collision = RuleCollision {
                        rule_id: id.to_string(),
                        overridden,
                        winner: dir_sources.rule_path(rule),
                    };
                    warn!(
                        rule_id = %collision.rule_id,
                        overridden = %collision.overridden,
                        winner = %collision.winner,
                        "Local Sigma rule replaces a rule with the same id"
                    );
                    collisions.push(collision);
                }
            }

            collection.rules.extend(dir_collection.rules);
            collection.correlations.extend(dir_collection.correlations);
            collection.filters.extend(dir_collection.filters);
            sources.extend(dir_sources);
            reports.push(report);
        }

        let loaded_sources = self.load_collection(collection, sources)?;
        for source in &loaded_sources {
            let owner = reports
                .iter_mut()
                .filter(|report| Path::new(source).starts_with(&report.path))
                .max_by_key(|report| report.path.components().count());
            if let Some(report) = owner {
                report.rules += 1;
            }
        }
        for report in &reports {
            info!(
                role = report.role.as_str(),
                path = ?report.path,
                files = report.files,
                rules = report.rules,
                exists = report.exists,
                "Sigma rules directory loaded"
            );
        }
        self.directories = reports;
        self.collisions = collisions;
        let rules_dir = pack_dir;

        let stats = self.stats();
        info!("Loaded {} Sigma rules total", stats.total_rules);
        for (logsource, count) in &stats.rules_by_logsource {
            info!("  Logsource '{}': {} rules", logsource, count);
        }
        info!(
            "Skipped rules - deferred: {}, unknown_logsource: {}, product_mismatch: {}, inactive_collectors: {}; dropped documents with unresolved references: {}",
            stats.skipped_deferred_rules,
            stats.skipped_unknown_logsource_rules,
            stats.skipped_product_rules,
            stats.inactive_collector_rules,
            stats.unsupported_rules.len()
        );

        // Inert rules are the quiet failure: they load, they inflate the rule
        // count, and they can never match. Name the telemetry they wait on.
        if let Some(categories) = stats.inactive_collector_summary() {
            warn!(
                inert_rules = stats.inactive_collector_rules,
                categories = %categories,
                "Loaded rules have no backing collector on this platform and cannot fire"
            );
        }

        for unsupported in &stats.unsupported_rules {
            info!(
                source = %unsupported.source_path,
                kind = %unsupported.kind,
                identity = %unsupported.identity,
                reason = %unsupported.reason,
                "Sigma document was dropped"
            );
        }

        if !stats.failed_rules.is_empty() {
            warn!(
                path = ?rules_dir,
                diagnostics = stats.failed_rules.len(),
                "Some Sigma rule files had diagnostics; see the operational log for details"
            );
        }
        if !stats.unsupported_rules.is_empty() {
            warn!(
                path = ?rules_dir,
                dropped_documents = stats.unsupported_rules.len(),
                "Some Sigma documents were dropped; see the operational log for details"
            );
        }

        if self.rule_files_found > 0 && self.rule_count == 0 && stats.unsupported_rules.is_empty() {
            warn!("Sigma rules found but none compiled successfully");
        }

        Ok(())
    }

    fn collect_rules_recursive(
        &mut self,
        dir: &Path,
        collection: &mut SigmaCollection,
        sources: &mut DocumentSources,
    ) -> Result<()> {
        let entries = fs::read_dir(dir).context("Failed to read directory")?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                self.collect_rules_recursive(&path, collection, sources)?;
            } else if matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("yml" | "yaml")
            ) {
                self.rule_files_found += 1;
                match Self::parse_rule_file(&path, collection, sources) {
                    Ok(errors) => {
                        let path_str = path.display().to_string();
                        for error in errors {
                            info!(
                                source = %path_str,
                                diagnostic = %error,
                                "Sigma rule loaded with a metadata diagnostic"
                            );
                            self.failed_rules.push((path_str.clone(), error));
                        }
                        debug!("Parsed rule file: {:?}", path);
                    }
                    Err(error) => {
                        let path_str = path.display().to_string();
                        let error_message = error.to_string();
                        info!("Failed to load rule {:?}: {}", path, error_message);
                        self.failed_rules.push((path_str, error_message));
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_rule_file(
        path: &Path,
        collection: &mut SigmaCollection,
        sources: &mut DocumentSources,
    ) -> Result<Vec<String>> {
        let content = fs::read_to_string(path).context("Failed to read rule file")?;
        let parsed = parse_sigma_yaml(&content).map_err(|err| anyhow::anyhow!("{err}"))?;
        let source_path = path.display().to_string();
        let mut errors = parsed.errors.clone();

        errors.extend(sources.add_collection(&source_path, &content, &parsed)?);
        collection.rules.extend(parsed.rules);
        collection.correlations.extend(parsed.correlations);
        collection.filters.extend(parsed.filters);
        Ok(errors)
    }

    fn load_collection(
        &mut self,
        parsed: SigmaCollection,
        sources: DocumentSources,
    ) -> Result<Vec<String>> {
        let mut collection = SigmaCollection::new();
        let mut loaded_sources = Vec::new();
        let mut loaded_rule_keys = HashSet::new();
        let mut filter_rule_keys = HashSet::new();

        for mut rule in parsed.rules {
            let logsource = logsource_key(&rule.logsource);
            let decision = self.rule_load_decision(&logsource);
            self.record_skip_for_logsource(decision, &logsource);

            if !matches!(decision, RuleLoadDecision::Load { .. }) {
                continue;
            }

            // Route on the same normalized logsource the decision above used.
            normalize_logsource_in_place(&mut rule.logsource);
            // Keep a bad but parseable rule from making the final batched
            // compilation reject every valid rule in the directory.
            if let Err(error) = rsigma_eval::compile_rule(&rule) {
                self.failed_rules.push((
                    sources.rule_path(&rule),
                    format!(
                        "{}: {error}",
                        document_identity(rule.id.as_deref(), &rule.title)
                    ),
                ));
                continue;
            }
            add_detection_keys(&mut loaded_rule_keys, &rule);
            add_filter_keys(&mut filter_rule_keys, &rule);
            loaded_sources.push(sources.rule_path(&rule));
            collection.rules.push(rule);
        }

        let mut correlations =
            retain_correlations(self, parsed.correlations, &sources, &loaded_rule_keys);
        normalize_implicit_temporal_conditions(&mut correlations, &sources);
        let mut filters = retain_filters(self, parsed.filters, &sources, &filter_rule_keys);
        for filter in &mut filters {
            if let Some(logsource) = filter.logsource.as_mut() {
                normalize_logsource_in_place(logsource);
            }
        }
        collection.correlations = correlations;
        collection.filters = filters;

        self.store.add_collection(&collection)?;
        self.rule_count += collection.rules.len();
        Ok(loaded_sources)
    }

    fn record_unresolved_reference(&mut self, source_path: &str, identity: String) {
        self.record_unsupported_source(
            source_path,
            UnsupportedRuleKind::UnresolvedReference,
            identity,
            "references a rule not loaded on this platform",
        );
    }

    fn record_unsupported_source(
        &mut self,
        source_path: &str,
        kind: UnsupportedRuleKind,
        identity: String,
        reason: &str,
    ) {
        self.unsupported_rules.push(super::UnsupportedRule {
            source_path: source_path.to_string(),
            kind,
            identity,
            reason: reason.to_string(),
        });
    }
}

fn normalize_implicit_temporal_conditions(
    correlations: &mut [CorrelationRule],
    sources: &DocumentSources,
) {
    for correlation in correlations {
        if correlation.correlation_type != CorrelationType::Temporal
            || !sources.temporal_condition_was_omitted(correlation)
        {
            continue;
        }

        let required_rules = correlation
            .rules
            .iter()
            .collect::<HashSet<_>>()
            .len()
            .max(1) as u64;
        correlation.condition = CorrelationCondition::Threshold {
            predicates: vec![(ConditionOperator::Gte, required_rules)],
            field: None,
            percentile: None,
        };
    }
}

fn add_detection_keys(keys: &mut HashSet<String>, rule: &SigmaRule) {
    if let Some(id) = &rule.id {
        keys.insert(id.clone());
    }
    if let Some(name) = &rule.name {
        keys.insert(name.clone());
    }
}

fn add_filter_keys(keys: &mut HashSet<String>, rule: &SigmaRule) {
    add_detection_keys(keys, rule);
    keys.insert(rule.title.clone());
}

fn add_correlation_keys(keys: &mut HashSet<String>, rule: &CorrelationRule) {
    if let Some(id) = &rule.id {
        keys.insert(id.clone());
    }
    if let Some(name) = &rule.name {
        keys.insert(name.clone());
    }
}

fn retain_correlations(
    engine: &mut Engine,
    correlations: Vec<CorrelationRule>,
    sources: &DocumentSources,
    loaded_rule_keys: &HashSet<String>,
) -> Vec<CorrelationRule> {
    let mut keep = vec![true; correlations.len()];

    // A correlation may refer to another correlation. Remove invalid
    // correlations to a fixed point so a dependent correlation is dropped when
    // its target was dropped for an unresolved detection reference. Start with
    // every correlation identifier known so valid cycles reach RSigma's cycle
    // validator instead of being misreported as unresolved references.
    loop {
        let mut known = loaded_rule_keys.clone();
        for (index, correlation) in correlations.iter().enumerate() {
            if keep[index] {
                add_correlation_keys(&mut known, correlation);
            }
        }

        let mut changed = false;
        for (index, correlation) in correlations.iter().enumerate() {
            if keep[index]
                && correlation
                    .rules
                    .iter()
                    .any(|reference| !known.contains(reference))
            {
                keep[index] = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    correlations
        .into_iter()
        .enumerate()
        .filter_map(|(index, correlation)| {
            if keep[index] {
                Some(correlation)
            } else {
                let source_path = sources.correlation_path(&correlation);
                engine.record_unresolved_reference(
                    &source_path,
                    document_identity(correlation.id.as_deref(), &correlation.title),
                );
                None
            }
        })
        .collect()
}

fn retain_filters(
    engine: &mut Engine,
    filters: Vec<FilterRule>,
    sources: &DocumentSources,
    loaded_rule_keys: &HashSet<String>,
) -> Vec<FilterRule> {
    filters
        .into_iter()
        .filter_map(|filter| {
            let source_path = sources.filter_path(&filter);
            let identity = document_identity(filter.id.as_deref(), &filter.title);
            let FilterRuleTarget::Specific(references) = &filter.rules else {
                // A filter only removes matches, so accepting an untargeted one
                // would let a single file silence every rule in the tree.
                warn!(
                    source = %source_path,
                    identity = %identity,
                    "Sigma filter does not list its target rules and was not loaded"
                );
                engine.record_unsupported_source(
                    &source_path,
                    UnsupportedRuleKind::UntargetedFilter,
                    identity,
                    "filter does not list target rules; name each rule id or title under filter.rules",
                );
                return None;
            };

            if references
                .iter()
                .any(|reference| loaded_rule_keys.contains(reference))
            {
                info!(
                    source = %source_path,
                    identity = %identity,
                    targets = %references.join(", "),
                    "Sigma filter loaded"
                );
                Some(filter)
            } else {
                engine.record_unresolved_reference(&source_path, identity);
                None
            }
        })
        .collect()
}
