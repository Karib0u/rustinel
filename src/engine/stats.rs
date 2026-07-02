use super::*;

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
    pub skipped_product_rules: usize,
    pub skipped_deferred_rules: usize,
    pub skipped_unknown_logsource_rules: usize,
    pub inactive_collector_rules: usize,
}
