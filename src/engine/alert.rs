use super::*;

impl Engine {
    pub(crate) fn truncate_str(s: &str, max_len: usize) -> (String, bool) {
        if s.len() <= max_len {
            return (s.to_string(), false);
        }

        if max_len <= 3 {
            let mut end = max_len;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            return (s[..end].to_string(), true);
        }

        let limit = max_len - 3;
        let mut end = limit;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut out = s[..end].to_string();
        out.push_str("...");
        (out, true)
    }

    pub(crate) fn pattern_descriptor(pattern: &FieldPattern) -> (String, String, Option<bool>) {
        match pattern {
            FieldPattern::Exact(s, cased) => ("exact".to_string(), s.clone(), Some(*cased)),
            FieldPattern::Contains(s, cased) => ("contains".to_string(), s.clone(), Some(*cased)),
            FieldPattern::StartsWith(s, cased) => {
                ("startswith".to_string(), s.clone(), Some(*cased))
            }
            FieldPattern::EndsWith(s, cased) => ("endswith".to_string(), s.clone(), Some(*cased)),
            FieldPattern::Regex(re) => ("regex".to_string(), re.as_str().to_string(), None),
            FieldPattern::FieldRef(other) => ("fieldref".to_string(), other.clone(), None),
            FieldPattern::OneOf(values) => ("one_of".to_string(), values.join(", "), None),
            FieldPattern::Cidr(net) => ("cidr".to_string(), net.to_string(), None),
            FieldPattern::Numeric(value, op) => {
                let op_str = match op {
                    NumericOp::Lt => "<",
                    NumericOp::Gt => ">",
                    NumericOp::Le => "<=",
                    NumericOp::Ge => ">=",
                };
                ("numeric".to_string(), format!("{} {}", op_str, value), None)
            }
            FieldPattern::Null => ("null".to_string(), "null".to_string(), None),
            FieldPattern::NotNull => ("not_null".to_string(), "not_null".to_string(), None),
        }
    }

    pub(crate) fn collect_keyword_matches(
        &self,
        event: &NormalizedEvent,
        selection_id: &str,
        keywords: &[FieldPattern],
        level: MatchDebugLevel,
        keyword_matches: &mut Vec<SigmaKeywordMatch>,
        truncated: &mut bool,
    ) -> bool {
        let mut matched = false;
        let values = event.all_field_values_with_keys();

        for pattern in keywords {
            let (pattern_type, pattern_value, _) = Self::pattern_descriptor(pattern);
            let (pattern_value, pattern_truncated) =
                Self::truncate_str(&pattern_value, MAX_PATTERN_LEN);
            if pattern_truncated {
                *truncated = true;
            }

            for (field, value) in &values {
                if self.matches_pattern(value, pattern, None) {
                    matched = true;
                    if keyword_matches.len() >= MAX_SIGMA_KEYWORD_MATCHES {
                        *truncated = true;
                        return matched;
                    }

                    let value = if matches!(level, MatchDebugLevel::Full) {
                        let (val, val_truncated) = Self::truncate_str(value, MAX_MATCH_VALUE_LEN);
                        if val_truncated {
                            *truncated = true;
                        }
                        Some(val)
                    } else {
                        None
                    };

                    keyword_matches.push(SigmaKeywordMatch {
                        selection: selection_id.to_string(),
                        pattern_type: pattern_type.clone(),
                        keyword: pattern_value.clone(),
                        field: Some((*field).to_string()),
                        value,
                    });
                }
            }
        }

        matched
    }

    pub(crate) fn collect_field_matches(
        &self,
        event: &NormalizedEvent,
        selection_id: &str,
        criteria: &[FieldCriterion],
        level: MatchDebugLevel,
        matches: &mut Vec<SigmaFieldMatch>,
        truncated: &mut bool,
    ) {
        for criterion in criteria {
            if matches.len() >= MAX_SIGMA_MATCHES {
                *truncated = true;
                return;
            }

            let matcher = if matches!(criterion.matcher, PatternMatcher::All) {
                "all"
            } else {
                "any"
            };

            let field_value = event.get_field(&criterion.field);

            match field_value {
                Some(value) => {
                    for pattern in &criterion.patterns {
                        if !self.matches_pattern(value, pattern, Some(event)) {
                            continue;
                        }

                        if matches.len() >= MAX_SIGMA_MATCHES {
                            *truncated = true;
                            return;
                        }

                        let (pattern_type, pattern_value, case_sensitive) =
                            Self::pattern_descriptor(pattern);
                        let (pattern_value, pattern_truncated) =
                            Self::truncate_str(&pattern_value, MAX_PATTERN_LEN);
                        if pattern_truncated {
                            *truncated = true;
                        }

                        let value = if matches!(level, MatchDebugLevel::Full) {
                            let (val, val_truncated) =
                                Self::truncate_str(value, MAX_MATCH_VALUE_LEN);
                            if val_truncated {
                                *truncated = true;
                            }
                            Some(val)
                        } else {
                            None
                        };

                        matches.push(SigmaFieldMatch {
                            selection: selection_id.to_string(),
                            field: criterion.field.clone(),
                            matcher: matcher.to_string(),
                            pattern_type,
                            pattern: pattern_value,
                            case_sensitive,
                            value,
                        });
                    }
                }
                None => {
                    for pattern in &criterion.patterns {
                        if !self.matches_pattern_null(pattern) {
                            continue;
                        }

                        if matches.len() >= MAX_SIGMA_MATCHES {
                            *truncated = true;
                            return;
                        }

                        let (pattern_type, pattern_value, case_sensitive) =
                            Self::pattern_descriptor(pattern);
                        let (pattern_value, pattern_truncated) =
                            Self::truncate_str(&pattern_value, MAX_PATTERN_LEN);
                        if pattern_truncated {
                            *truncated = true;
                        }

                        matches.push(SigmaFieldMatch {
                            selection: selection_id.to_string(),
                            field: criterion.field.clone(),
                            matcher: matcher.to_string(),
                            pattern_type,
                            pattern: pattern_value,
                            case_sensitive,
                            value: None,
                        });
                    }
                }
            }
        }
    }

    pub(crate) fn build_sigma_summary(
        &self,
        rule: &CompiledRule,
        level: MatchDebugLevel,
        matches: &[SigmaFieldMatch],
        keyword_matches: &[SigmaKeywordMatch],
        truncated: bool,
    ) -> String {
        let mut parts = Vec::new();
        let mut summary_truncated = truncated;

        if let Some(condition) = &rule.rule.detection.condition {
            let (cond, cond_truncated) = Self::truncate_str(condition, MAX_PATTERN_LEN);
            if cond_truncated {
                summary_truncated = true;
            }
            parts.push(format!("condition matched: {}", cond));
        }

        if let Some(first_match) = matches.first() {
            let mut detail = format!(
                "{} matched {} {} '{}'",
                first_match.selection,
                first_match.field,
                first_match.pattern_type,
                first_match.pattern
            );
            if matches!(level, MatchDebugLevel::Full) {
                if let Some(value) = &first_match.value {
                    detail.push_str(&format!(" with value '{}'", value));
                }
            }
            parts.push(detail);
        } else if let Some(first_keyword) = keyword_matches.first() {
            let mut detail = format!(
                "{} keyword {} '{}'",
                first_keyword.selection, first_keyword.pattern_type, first_keyword.keyword
            );
            if let Some(field) = &first_keyword.field {
                detail.push_str(&format!(" in {}", field));
            }
            if matches!(level, MatchDebugLevel::Full) {
                if let Some(value) = &first_keyword.value {
                    detail.push_str(&format!(" with value '{}'", value));
                }
            }
            parts.push(detail);
        }

        if parts.is_empty() {
            parts.push("rule matched".to_string());
        }

        let mut summary = parts.join("; ");
        if summary_truncated {
            summary.push_str(" (truncated)");
        }

        summary
    }

    pub(crate) fn build_sigma_match_details(
        &self,
        event: &NormalizedEvent,
        rule: &CompiledRule,
        selection_results: &HashMap<String, bool>,
    ) -> Option<MatchDetails> {
        if matches!(self.match_debug, MatchDebugLevel::Off) {
            return None;
        }

        let level = self.match_debug;
        let mut matches = Vec::new();
        let mut keyword_matches = Vec::new();
        let mut truncated = false;

        for (selection_id, selection) in &rule.selections {
            let matched = selection_results
                .get(selection_id)
                .copied()
                .unwrap_or(false);
            if !matched {
                continue;
            }

            if !selection.keywords.is_empty() {
                self.collect_keyword_matches(
                    event,
                    selection_id,
                    &selection.keywords,
                    level,
                    &mut keyword_matches,
                    &mut truncated,
                );
            }

            if !selection.alternative_field_criteria.is_empty() {
                for criteria in &selection.alternative_field_criteria {
                    if self.check_field_criteria_group(event, criteria) {
                        self.collect_field_matches(
                            event,
                            selection_id,
                            criteria,
                            level,
                            &mut matches,
                            &mut truncated,
                        );
                        if matches.len() >= MAX_SIGMA_MATCHES {
                            break;
                        }
                    }
                }
            }

            if !selection.field_criteria.is_empty()
                && self.check_field_criteria_group(event, &selection.field_criteria)
            {
                self.collect_field_matches(
                    event,
                    selection_id,
                    &selection.field_criteria,
                    level,
                    &mut matches,
                    &mut truncated,
                );
            }
        }

        let summary = self.build_sigma_summary(rule, level, &matches, &keyword_matches, truncated);

        Some(MatchDetails {
            summary,
            sigma: Some(SigmaMatchDetails {
                condition: rule.rule.detection.condition.clone(),
                selection_results: selection_results.clone(),
                matches,
                keyword_matches,
            }),
            yara: None,
        })
    }

    /// Check an event against loaded rules with the built-in matcher.
    /// OPTIMIZED: Uses zero-copy field access instead of HashMap creation
    ///
    /// Every candidate rule is evaluated and the winner is chosen by
    /// [`MatchRank`], so a broad low-severity rule can never shadow a more
    /// specific high-severity one.
    pub(crate) fn check_event_builtin(&self, event: &NormalizedEvent) -> Option<Alert> {
        let candidate_logsources = Self::sigma_logsources_for_event(event);

        // PERFORMANCE: Pass event directly - no HashMap allocation!
        // This eliminates 10,000+ heap allocations per second

        let mut best: Option<(MatchRank<'_>, &CompiledRule, HashMap<String, bool>)> = None;

        for logsource in candidate_logsources {
            let Some(rules) = self.rules_by_logsource.get(&logsource) else {
                continue;
            };

            tracing::trace!(
                "Checking event against {} rule(s) in logsource '{}'",
                rules.len(),
                logsource.display()
            );

            // Check each rule
            for compiled_rule in rules {
                tracing::trace!("========================================");
                tracing::trace!("Evaluating rule: '{}'", compiled_rule.rule.title);
                tracing::trace!("Rule ID: {:?}", compiled_rule.rule.id);

                // NOTE: Detailed field logging removed for performance (avoid HashMap allocation)
                // Use get_field() or all_field_values() if debugging specific fields

                let selection_results = self.evaluate_selections(event, compiled_rule);

                tracing::trace!("Selection evaluation results:");
                for (sel_id, result) in &selection_results {
                    tracing::trace!("  {} = {}", sel_id, result);
                }

                let is_match = if compiled_rule.condition_tree.is_some() {
                    // NEW LOGIC PIPELINE: Rule has explicit condition
                    tracing::trace!(
                        "Rule '{}': Using condition-based evaluation: '{}'",
                        compiled_rule.rule.title,
                        compiled_rule
                            .rule
                            .detection
                            .condition
                            .as_deref()
                            .unwrap_or_default()
                    );

                    // Phase 3: Evaluate precompiled condition tree.
                    let condition_result =
                        self.check_compiled_condition(compiled_rule, &selection_results);
                    tracing::trace!("Final condition result: {}", condition_result);
                    condition_result
                } else {
                    // LEGACY LOGIC: No explicit condition, use simple AND logic (implied OR)
                    // This is the default behavior for older Sigma rules
                    tracing::trace!(
                        "Rule '{}': Using legacy AND/OR evaluation (no condition)",
                        compiled_rule.rule.title
                    );

                    let any_match = selection_results.values().any(|&v| v);
                    tracing::trace!("Legacy evaluation (any selection matches): {}", any_match);
                    any_match
                };

                if is_match {
                    tracing::trace!("✓ Rule '{}' MATCHED!", compiled_rule.rule.title);

                    let rank = MatchRank::new(
                        severity_from_sigma_level(compiled_rule.rule.level.as_deref()),
                        compiled_rule.rule.id.as_deref(),
                        &compiled_rule.rule.title,
                    );

                    if best
                        .as_ref()
                        .is_none_or(|(best_rank, _, _)| rank < *best_rank)
                    {
                        best = Some((rank, compiled_rule, selection_results));
                    }
                } else {
                    tracing::trace!("✗ Rule '{}' did NOT match", compiled_rule.rule.title);
                }
            }
        }

        let (_, compiled_rule, selection_results) = best?;
        let rule_id = compiled_rule
            .rule
            .id
            .as_ref()
            .map(|id| format!("sigma::{}", id));

        Some(Alert {
            severity: severity_from_sigma_level(compiled_rule.rule.level.as_deref()),
            rule_name: compiled_rule.rule.title.clone(),
            rule_description: compiled_rule.rule.description.clone(),
            rule_id,
            engine: DetectionEngine::Sigma,
            event: event.clone(),
            match_details: self.build_sigma_match_details(event, compiled_rule, &selection_results),
        })
    }

    pub(crate) fn sigma_logsources_for_event(event: &NormalizedEvent) -> Vec<LogSourceKey> {
        let mut ordered = Vec::new();
        let mut seen = HashSet::new();

        for alias in Self::concrete_logsource_aliases_for_event(event) {
            for candidate in Self::logsource_subsets(&alias) {
                if seen.insert(candidate.clone()) {
                    ordered.push(candidate);
                }
            }
        }

        ordered
    }

    pub(crate) fn concrete_logsource_aliases_for_event(
        event: &NormalizedEvent,
    ) -> Vec<LogSourceKey> {
        let mut aliases = Vec::new();

        match event.category {
            EventCategory::Process => {
                aliases.push(LogSourceKey::from_parts(
                    Some(platform_product(event.platform)),
                    Some("sysmon"),
                    Some("process_creation"),
                ));
            }
            EventCategory::Network => {
                aliases.push(LogSourceKey::from_parts(
                    Some(platform_product(event.platform)),
                    Some("sysmon"),
                    Some("network_connection"),
                ));
                aliases.push(LogSourceKey::from_parts(
                    None,
                    Some("connection"),
                    Some("network"),
                ));
            }
            EventCategory::File => {
                for category in Self::sigma_file_categories_for_event(event) {
                    aliases.push(LogSourceKey::from_parts(
                        Some(platform_product(event.platform)),
                        Some("sysmon"),
                        Some(category),
                    ));
                }
            }
            EventCategory::Registry => {
                for category in Self::sigma_registry_categories_for_event(event) {
                    aliases.push(LogSourceKey::from_parts(
                        Some(platform_product(event.platform)),
                        Some("sysmon"),
                        Some(category),
                    ));
                }
            }
            EventCategory::Dns => {
                match event.platform {
                    Platform::Windows => {
                        aliases.push(LogSourceKey::from_parts(
                            Some("windows"),
                            Some("dns-client"),
                            Some("dns_query"),
                        ));
                        aliases.push(LogSourceKey::from_parts(
                            Some("windows"),
                            Some("dns"),
                            Some("dns_query"),
                        ));
                    }
                    Platform::Linux => {
                        aliases.push(LogSourceKey::from_parts(
                            Some("linux"),
                            Some("sysmon"),
                            Some("dns_query"),
                        ));
                    }
                    Platform::MacOS => {
                        aliases.push(LogSourceKey::from_parts(
                            Some("macos"),
                            Some("sysmon"),
                            Some("dns_query"),
                        ));
                    }
                }

                aliases.push(LogSourceKey::from_parts(None, None, Some("dns")));
                aliases.push(LogSourceKey::from_parts(None, Some("dns"), Some("network")));
            }
            EventCategory::ImageLoad => {
                aliases.push(LogSourceKey::from_parts(
                    Some(platform_product(event.platform)),
                    Some("sysmon"),
                    Some("image_load"),
                ));
            }
            EventCategory::Scripting => {
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("powershell"),
                    Some("ps_script"),
                ));
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("powershell-classic"),
                    Some("ps_script"),
                ));
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("microsoft-windows-powershell"),
                    Some("ps_script"),
                ));
            }
            EventCategory::PowerShellModule => {
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("powershell"),
                    Some("ps_module"),
                ));
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("powershell-classic"),
                    Some("ps_module"),
                ));
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("microsoft-windows-powershell"),
                    Some("ps_module"),
                ));
            }
            EventCategory::Wmi => {
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("wmi"),
                    Some("wmi_event"),
                ));
            }
            EventCategory::Service => {
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("system"),
                    Some("service_creation"),
                ));
            }
            EventCategory::Task => {
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("taskscheduler"),
                    Some("task_creation"),
                ));
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("task scheduler"),
                    Some("task_creation"),
                ));
            }
            // The Security channel is addressed by channel alone: its Sigma
            // rules carry no category and select on `EventID` instead.
            EventCategory::Security => {
                aliases.push(LogSourceKey::from_parts(
                    Some("windows"),
                    Some("security"),
                    None,
                ));
            }
        }

        aliases
    }

    pub(crate) fn logsource_subsets(logsource: &LogSourceKey) -> Vec<LogSourceKey> {
        let mut subsets = Vec::new();
        let fields = [
            logsource.product.as_deref(),
            logsource.service.as_deref(),
            logsource.category.as_deref(),
        ];

        for mask in [0b111, 0b110, 0b101, 0b011, 0b100, 0b010, 0b001] {
            let product = if mask & 0b001 != 0 { fields[0] } else { None };
            let service = if mask & 0b010 != 0 { fields[1] } else { None };
            let category = if mask & 0b100 != 0 { fields[2] } else { None };

            subsets.push(LogSourceKey::from_parts(product, service, category));
        }

        subsets
    }

    /// Map a file event to its Sigma logsource categories.
    ///
    /// `file_change` corresponds to Sysmon Event ID 2, *file creation time
    /// changed* — timestomping — not "the file was written". Rules in that
    /// category are written against timestamp manipulation, so routing plain
    /// writes there makes any rule that keys only on `TargetFilename` fire on
    /// ordinary file activity. Writes are therefore reported under the base
    /// `file_event` family only.
    ///
    /// The numbering comes from `sensor::FILE_EVENT_NORMALIZATION`, which is
    /// the single table every platform sensor maps its file actions through.
    pub(crate) fn sigma_file_categories_for_event(event: &NormalizedEvent) -> Vec<&'static str> {
        match event.event_id {
            2 => vec!["file_event", "file_change"],
            11 => vec!["file_event", "file_create"],
            23 => vec!["file_delete"],
            65 => vec!["file_event"],
            71 => vec!["file_event", "file_rename"],
            _ => match event.opcode {
                2 => vec!["file_event", "file_change"],
                64 => vec!["file_event", "file_create"],
                65 | 80 => vec!["file_event"],
                70 | 72 => vec!["file_delete"],
                71 => vec!["file_event", "file_rename"],
                _ => vec!["file_event"],
            },
        }
    }

    pub(crate) fn sigma_registry_categories_for_event(
        event: &NormalizedEvent,
    ) -> Vec<&'static str> {
        let mut categories = vec!["registry_event"];

        match event.opcode {
            36 => categories.push("registry_add"),
            39 => categories.push("registry_set"),
            38 | 41 => categories.push("registry_delete"),
            _ => {}
        }

        categories
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProcessCreationFields;

    fn process_event(image: String) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: "2026-08-16T12:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: crate::models::EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image),
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

    fn engine_with_image_rule(match_debug: MatchDebugLevel) -> Engine {
        let mut engine = Engine::new_for_platform_with_logging_level_and_match_debug(
            Platform::Windows,
            "warn",
            match_debug,
            SigmaEngineKind::Builtin,
        );
        let rule: SigmaRule = serde_yaml::from_str(
            r#"
title: Test image rule
id: test-image-rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: tool.exe
  condition: selection
level: high
"#,
        )
        .expect("test rule parses");
        let compiled = engine.compile_rule(rule).expect("test rule compiles");
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);
        engine
    }

    #[test]
    fn alert_without_match_details_remains_complete() {
        let engine = engine_with_image_rule(MatchDebugLevel::Off);
        let event = process_event(r"C:\Program Files\Example\tool.exe".to_string());

        let alert = engine
            .check_event_builtin(&event)
            .expect("matching event produces an alert");

        assert_eq!(alert.rule_name, "Test image rule");
        assert_eq!(alert.rule_id.as_deref(), Some("sigma::test-image-rule"));
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.match_details.is_none());
        assert_eq!(alert.event.get_field("Image"), event.get_field("Image"));
    }

    #[test]
    fn full_match_details_truncate_long_unicode_values_safely() {
        let engine = engine_with_image_rule(MatchDebugLevel::Full);
        let image = format!(r"C:\{}\tool.exe", "é".repeat(MAX_MATCH_VALUE_LEN));

        let alert = engine
            .check_event_builtin(&process_event(image))
            .expect("matching event produces an alert");
        let details = alert.match_details.expect("full details are present");
        let sigma = details.sigma.expect("Sigma details are present");
        let value = sigma.matches[0]
            .value
            .as_deref()
            .expect("full details include the matched value");

        assert!(value.ends_with("..."));
        assert!(value.len() <= MAX_MATCH_VALUE_LEN);
        assert!(details.summary.ends_with("(truncated)"));
    }
}
