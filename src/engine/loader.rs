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
        for (logsource, rules) in &self.rules_by_logsource {
            info!(
                "  Logsource '{}': {} rules",
                logsource.display(),
                rules.len()
            );
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

    /// Parse Sigma rule documents from YAML content, expanding `action: global` files.
    pub fn parse_rule_documents(content: &str) -> Result<Vec<SigmaRule>> {
        let documents: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(content)
            .map(serde_yaml::Value::deserialize)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse YAML documents")?;

        if documents.is_empty() {
            return Err(anyhow::anyhow!("No YAML documents found"));
        }

        let is_global = documents
            .first()
            .and_then(|doc| doc.get("action"))
            .and_then(|v| v.as_str())
            .map(|s| s == "global")
            .unwrap_or(false);

        if is_global && documents.len() > 1 {
            let global_metadata = &documents[0];
            let mut rules = Vec::with_capacity(documents.len() - 1);

            for doc in &documents[1..] {
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
                    serde_yaml::from_value(merged)
                        .context("Failed to parse merged global sub-rule")?,
                );
            }

            return Ok(rules);
        }

        Ok(vec![
            serde_yaml::from_value(documents[0].clone()).context("Failed to parse YAML")?
        ])
    }

    /// Load a single rule file (supports multi-document YAML for "action: global" rules)
    pub(crate) fn load_rule<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
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
