use super::*;
use std::fmt;

/// The kind of Sigma document that the RSigma parser accepted but Rustinel
/// does not currently evaluate at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedRuleKind {
    Correlation,
    Filter,
}

impl fmt::Display for UnsupportedRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Correlation => f.write_str("correlation"),
            Self::Filter => f.write_str("filter"),
        }
    }
}

/// Context for a parsed Sigma document that was not loaded by the active
/// runtime because its document type is not supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedRule {
    pub source_path: String,
    pub kind: UnsupportedRuleKind,
    pub identity: String,
    pub reason: String,
}

impl Engine {
    pub fn stats(&self) -> EngineStats {
        let builtin_counts = || {
            let mut by_category: HashMap<String, usize> = HashMap::new();
            for (logsource, rules) in &self.rules_by_logsource {
                let category = logsource
                    .category
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string());
                *by_category.entry(category).or_default() += rules.len();
            }
            let by_logsource = self
                .rules_by_logsource
                .iter()
                .map(|(k, v)| (k.display(), v.len()))
                .collect::<HashMap<String, usize>>();
            (by_category, by_logsource)
        };

        let (rules_by_category, rules_by_logsource) = match self.engine_kind {
            SigmaEngineKind::Builtin => builtin_counts(),
            #[cfg(feature = "rsigma-engine")]
            SigmaEngineKind::Rsigma => {
                let mut by_category: HashMap<String, usize> = HashMap::new();
                for (logsource, count) in self.rsigma.counts() {
                    let category = logsource
                        .category
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string());
                    *by_category.entry(category).or_default() += count;
                }
                let by_logsource = self
                    .rsigma
                    .counts()
                    .iter()
                    .map(|(k, v)| (k.display(), *v))
                    .collect::<HashMap<String, usize>>();
                (by_category, by_logsource)
            }
            #[cfg(not(feature = "rsigma-engine"))]
            SigmaEngineKind::Rsigma => builtin_counts(),
        };

        let unsupported_correlation_rules = self
            .unsupported_rules
            .iter()
            .filter(|rule| rule.kind == UnsupportedRuleKind::Correlation)
            .count();
        let unsupported_filter_rules = self
            .unsupported_rules
            .iter()
            .filter(|rule| rule.kind == UnsupportedRuleKind::Filter)
            .count();

        EngineStats {
            total_rules: self.rule_count,
            rule_files_found: self.rule_files_found,
            rules_by_category,
            rules_by_logsource,
            deferred_logsource_rules: self
                .deferred_logsource_counts
                .iter()
                .map(|(k, v)| (k.display(), *v))
                .collect(),
            unknown_logsource_rules: self
                .unknown_logsource_counts
                .iter()
                .map(|(k, v)| (k.display(), *v))
                .collect(),
            failed_rules: self.failed_rules.clone(),
            unsupported_rules: self.unsupported_rules.clone(),
            unsupported_correlation_rules,
            unsupported_filter_rules,
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
    /// Parsed documents that the active runtime cannot evaluate.
    pub unsupported_rules: Vec<UnsupportedRule>,
    pub unsupported_correlation_rules: usize,
    pub unsupported_filter_rules: usize,
    pub skipped_product_rules: usize,
    pub skipped_deferred_rules: usize,
    pub skipped_unknown_logsource_rules: usize,
    pub inactive_collector_rules: usize,
}
