use super::*;

impl Engine {
    pub fn load_rules<P: AsRef<Path>>(&mut self, rules_dir: P) -> Result<()> {
        let rules_dir = rules_dir.as_ref();

        if !rules_dir.exists() {
            warn!("Rules directory does not exist: {:?}", rules_dir);
            return Ok(());
        }

        info!("Loading Sigma rules from: {:?} (recursive)", rules_dir);

        // Recursively load all rules
        self.load_rules_recursive(rules_dir)?;

        info!("Loaded {} Sigma rules total", self.rule_count);
        for (logsource, count) in self.stats().rules_by_logsource {
            info!("  Logsource '{}': {} rules", logsource, count);
        }
        info!(
            "Skipped rules - deferred: {}, unknown_logsource: {}, product_mismatch: {}, inactive_collectors: {}",
            self.skipped_deferred_rules,
            self.skipped_unknown_logsource_rules,
            self.skipped_product_rules,
            self.inactive_collector_rules
        );

        if self.rule_files_found > 0 && self.rule_count == 0 {
            warn!("Sigma rules found but none compiled successfully");
        }

        Ok(())
    }

    /// Recursively load rules from a directory and its subdirectories
    pub(crate) fn load_rules_recursive<P: AsRef<Path>>(&mut self, dir: P) -> Result<()> {
        let dir = dir.as_ref();

        let entries = fs::read_dir(dir).context("Failed to read directory")?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Recursively process subdirectories
                self.load_rules_recursive(&path)?;
            } else if let Some(ext) = path.extension() {
                // Only process .yml and .yaml files
                if ext == "yml" || ext == "yaml" {
                    self.rule_files_found += 1;
                    match self.load_rule(&path) {
                        Ok(()) => {
                            debug!("Loaded rule: {:?}", path);
                        }
                        Err(e) => {
                            let path_str = path.display().to_string();
                            let err_msg = format!("{}", e);
                            warn!("Failed to load rule {:?}: {}", path, e);
                            self.failed_rules.push((path_str, err_msg));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse Sigma rule documents from YAML content.
    ///
    /// Ordinary multi-document YAML files load one rule per document. Files
    /// starting with `action: global` keep the existing template expansion
    /// behavior. Other collection actions are only supported by the RSigma
    /// backend and are rejected here with document context.
    pub fn parse_rule_documents(content: &str) -> Result<Vec<SigmaRule>> {
        let mut documents = Vec::new();
        for (index, doc) in serde_yaml::Deserializer::from_str(content).enumerate() {
            let document_number = index + 1;
            let value = serde_yaml::Value::deserialize(doc)
                .with_context(|| format!("Failed to parse YAML document {document_number}"))?;

            if !value.is_null() {
                documents.push((document_number, value));
            }
        }

        if documents.is_empty() {
            return Err(anyhow::anyhow!("No YAML documents found"));
        }

        let is_global = documents
            .first()
            .and_then(|(_, doc)| doc.get("action"))
            .and_then(|v| v.as_str())
            .map(|s| s == "global")
            .unwrap_or(false);

        if is_global && documents.len() > 1 {
            let global_metadata = &documents[0].1;
            let mut rules = Vec::with_capacity(documents.len() - 1);

            for (document_number, doc) in &documents[1..] {
                let mut merged = global_metadata.clone();

                if let Some(logsource) = doc.get("logsource") {
                    merged["logsource"] = logsource.clone();
                }
                if let Some(detection) = doc.get("detection") {
                    merged["detection"] = detection.clone();
                }

                if let Some(mapping) = merged.as_mapping_mut() {
                    mapping.remove(serde_yaml::Value::String("action".to_string()));
                }

                rules.push(
                    serde_yaml::from_value(merged).with_context(|| {
                        format!(
                            "Failed to parse merged global sub-rule from YAML document {document_number}"
                        )
                    })?,
                );
            }

            return Ok(rules);
        }

        let mut rules = Vec::with_capacity(documents.len());
        for (document_number, doc) in documents {
            if let Some(action) = doc.get("action").and_then(|v| v.as_str()) {
                return Err(anyhow::anyhow!(
                    "Unsupported Sigma collection action '{action}' in YAML document {document_number}; the built-in backend only supports 'global'"
                ));
            }

            rules.push(
                serde_yaml::from_value(doc)
                    .with_context(|| format!("Failed to parse YAML document {document_number}"))?,
            );
        }

        Ok(rules)
    }

    /// Load a single rule file, dispatching to the active backend.
    pub(crate) fn load_rule<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        match self.engine_kind {
            SigmaEngineKind::Builtin => self.load_rule_builtin(path),
            #[cfg(feature = "rsigma-engine")]
            SigmaEngineKind::Rsigma => self.load_rule_rsigma(path),
            // Unreachable in practice: startup validation rejects `rsigma`
            // without the feature. Fall back to the built-in matcher rather
            // than panic if it is ever constructed directly.
            #[cfg(not(feature = "rsigma-engine"))]
            SigmaEngineKind::Rsigma => self.load_rule_builtin(path),
        }
    }

    /// Load a single rule file with the built-in matcher (supports
    /// multi-document YAML for "action: global" rules).
    pub(crate) fn load_rule_builtin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let content = fs::read_to_string(path.as_ref()).context("Failed to read rule file")?;

        for rule in Self::parse_rule_documents(&content)? {
            let logsource = Self::normalized_logsource(&rule);
            let decision = self.rule_load_decision(&logsource);
            self.record_skip_for_logsource(decision, &logsource);

            if !matches!(decision, RuleLoadDecision::Load { .. }) {
                continue;
            }

            let compiled = self.compile_rule(rule)?;
            let key = compiled.logsource.clone();
            self.rules_by_logsource
                .entry(key)
                .or_default()
                .push(compiled);
            self.rule_count += 1;
        }

        Ok(())
    }

    /// Compile a Sigma rule into efficient matching patterns
    pub(crate) fn compile_rule(&self, rule: SigmaRule) -> Result<CompiledRule> {
        let logsource = Self::normalized_logsource(&rule);

        let mut patterns: HashMap<String, Vec<FieldPattern>> = HashMap::new();
        let mut selections: HashMap<String, Selection> = HashMap::new();

        // Parse detection selections
        for (selection_id, selection_value) in &rule.detection.selections {
            // Skip condition keys
            if selection_id == "condition" {
                continue;
            }

            let mut field_criteria = Vec::new();
            let mut keywords = Vec::new();
            let mut alternative_field_criteria = Vec::new();

            // Check if this is a sequence selection (YAML list)
            if let Some(seq) = selection_value.as_sequence() {
                // Sequence can be:
                // - list of strings (keywords)
                // - list of maps (OR between each map)
                // - mixed (keywords + maps)
                for item in seq {
                    if let Some(s) = item.as_str() {
                        keywords.push(self.parse_string_pattern(s));
                    } else if let Some(fields) = item.as_mapping() {
                        let criteria =
                            self.compile_field_criteria_from_mapping(fields, &mut patterns)?;
                        if !criteria.is_empty() {
                            alternative_field_criteria.push(criteria);
                        }
                    }
                }
            } else if let Some(fields) = selection_value.as_mapping() {
                // Field-based selection
                field_criteria = self.compile_field_criteria_from_mapping(fields, &mut patterns)?;
            }

            // Store the compiled selection
            selections.insert(
                selection_id.clone(),
                Selection {
                    field_criteria,
                    keywords,
                    alternative_field_criteria,
                },
            );
        }

        let mut transpiled_condition = None;
        let mut condition_tree = None;
        if let Some(condition) = rule.detection.condition.as_deref() {
            let selection_keys: Vec<String> = selections.keys().cloned().collect();
            let transpiled = self.transpile_sigma_condition(condition, &selection_keys);
            let tree = build_operator_tree(&transpiled).with_context(|| {
                format!(
                    "Failed to compile Sigma condition for rule '{}': {}",
                    rule.title, condition
                )
            })?;
            transpiled_condition = Some(transpiled);
            condition_tree = Some(tree);
        }

        Ok(CompiledRule {
            rule,
            patterns,
            selections,
            logsource,
            transpiled_condition,
            condition_tree,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Engine;

    fn rule_yaml(title: &str, event_id: u32) -> String {
        format!(
            r#"
title: {title}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: {event_id}
  condition: selection
"#
        )
    }

    #[test]
    fn parse_single_document_rule() {
        let rules = Engine::parse_rule_documents(&rule_yaml("Single Rule", 1)).unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].title, "Single Rule");
    }

    #[test]
    fn parse_global_multi_document_rule_expands_sub_rules() {
        let yaml = r#"
action: global
title: Global Rule
logsource:
  product: windows
  category: process_creation
---
detection:
  selection:
    EventID: 1
  condition: selection
---
detection:
  selection:
    EventID: 2
  condition: selection
"#;

        let rules = Engine::parse_rule_documents(yaml).unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].title, "Global Rule");
        assert_eq!(rules[1].title, "Global Rule");
        assert_eq!(rules[0].detection.selections["selection"]["EventID"], 1);
        assert_eq!(rules[1].detection.selections["selection"]["EventID"], 2);
    }

    #[test]
    fn parse_independent_multi_document_rules_loads_each_document() {
        let yaml = format!(
            "{}\n---\n{}",
            rule_yaml("First Rule", 1),
            rule_yaml("Second Rule", 2)
        );

        let rules = Engine::parse_rule_documents(&yaml).unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].title, "First Rule");
        assert_eq!(rules[1].title, "Second Rule");
    }

    #[test]
    fn parse_many_independent_documents_loads_all_rules() {
        let yaml = format!(
            "{}\n---\n{}\n---\n{}",
            rule_yaml("First Rule", 1),
            rule_yaml("Second Rule", 2),
            rule_yaml("Third Rule", 3)
        );

        let rules = Engine::parse_rule_documents(&yaml).unwrap();
        let titles: Vec<_> = rules.iter().map(|rule| rule.title.as_str()).collect();

        assert_eq!(titles, ["First Rule", "Second Rule", "Third Rule"]);
    }

    #[test]
    fn parse_later_invalid_document_reports_document_number() {
        let yaml = format!(
            "{}\n---\ntitle: Broken Rule\nlogsource:\n  product: windows\n",
            rule_yaml("First Rule", 1)
        );

        let error = Engine::parse_rule_documents(&yaml).unwrap_err().to_string();

        assert!(error.contains("YAML document 2"));
    }

    #[test]
    fn parse_later_malformed_yaml_reports_document_number() {
        let yaml = format!("{}\n---\ntitle: [broken\n", rule_yaml("First Rule", 1));

        let error = Engine::parse_rule_documents(&yaml).unwrap_err().to_string();

        assert!(error.contains("YAML document 2"));
    }

    #[test]
    fn parse_unsupported_collection_action_reports_document_number() {
        let yaml = format!("{}\n---\naction: reset\n", rule_yaml("First Rule", 1));

        let error = Engine::parse_rule_documents(&yaml).unwrap_err().to_string();

        assert!(error.contains("Unsupported Sigma collection action 'reset'"));
        assert!(error.contains("YAML document 2"));
    }
}
