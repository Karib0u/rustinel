use std::collections::HashMap;
use std::fmt;

use super::Engine;

/// Why a parsed Sigma document was left out of the active collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedRuleKind {
    /// The document names a detection or correlation rule that was not kept.
    UnresolvedReference,
}

impl fmt::Display for UnsupportedRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvedReference => f.write_str("unresolved_reference"),
        }
    }
}

/// Context for a parsed Sigma document that was dropped because one or more of
/// its referenced rules were not loaded for the active platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedRule {
    pub source_path: String,
    pub kind: UnsupportedRuleKind,
    pub identity: String,
    pub reason: String,
}

impl Engine {
    pub fn stats(&self) -> EngineStats {
        let mut rules_by_category: HashMap<String, usize> = HashMap::new();
        for (logsource, count) in self.store.counts() {
            let category = logsource
                .category
                .clone()
                .unwrap_or_else(|| "<none>".to_string());
            *rules_by_category.entry(category).or_default() += count;
        }
        let rules_by_logsource = self
            .store
            .counts()
            .iter()
            .map(|(key, count)| (key.display(), *count))
            .collect::<HashMap<String, usize>>();

        EngineStats {
            total_rules: self.rule_count,
            rule_files_found: self.rule_files_found,
            rules_by_category,
            rules_by_logsource,
            deferred_logsource_rules: self
                .deferred_logsource_counts
                .iter()
                .map(|(key, count)| (key.display(), *count))
                .collect(),
            unknown_logsource_rules: self
                .unknown_logsource_counts
                .iter()
                .map(|(key, count)| (key.display(), *count))
                .collect(),
            failed_rules: self.failed_rules.clone(),
            unsupported_rules: self.unsupported_rules.clone(),
            skipped_product_rules: self.skipped_product_rules,
            skipped_deferred_rules: self.skipped_deferred_rules,
            skipped_unknown_logsource_rules: self.skipped_unknown_logsource_rules,
            inactive_collector_rules: self.inactive_collector_rules,
        }
    }
}

pub struct EngineStats {
    pub total_rules: usize,
    pub rule_files_found: usize,
    #[allow(dead_code)] // Used by companion binaries outside the library crate.
    pub rules_by_category: HashMap<String, usize>,
    pub rules_by_logsource: HashMap<String, usize>,
    #[allow(dead_code)] // Used by companion binaries outside the library crate.
    pub deferred_logsource_rules: HashMap<String, usize>,
    #[allow(dead_code)] // Used by companion binaries outside the library crate.
    pub unknown_logsource_rules: HashMap<String, usize>,
    #[allow(dead_code)] // Used by validation binaries outside this crate.
    pub failed_rules: Vec<(String, String)>,
    /// Parsed documents dropped because their references do not resolve.
    pub unsupported_rules: Vec<UnsupportedRule>,
    pub skipped_product_rules: usize,
    pub skipped_deferred_rules: usize,
    pub skipped_unknown_logsource_rules: usize,
    pub inactive_collector_rules: usize,
}
