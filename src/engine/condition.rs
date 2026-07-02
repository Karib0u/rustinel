use super::*;

// ============================================================================
// Lazy-initialized Regular Expressions
// ============================================================================
// These regexes are compiled once at first use and reused throughout the program.
// Using LazyLock ensures thread-safe initialization without runtime panics.

/// Regex for aggregation patterns like "1 of selection*" or "all of filter*"
static AGGREGATION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(1|all) of ([a-zA-Z_][a-zA-Z0-9_]*)\*")
        .expect("AGGREGATION_REGEX pattern is valid")
});

/// Regex for replacing "AND" keywords (case-sensitive)
static AND_UPPERCASE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAND\b").expect("AND_UPPERCASE_REGEX pattern is valid"));

/// Regex for replacing "and" keywords (lowercase)
static AND_LOWERCASE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\band\b").expect("AND_LOWERCASE_REGEX pattern is valid"));

/// Regex for replacing "OR" keywords (case-sensitive)
static OR_UPPERCASE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bOR\b").expect("OR_UPPERCASE_REGEX pattern is valid"));

/// Regex for replacing "or" keywords (lowercase)
static OR_LOWERCASE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bor\b").expect("OR_LOWERCASE_REGEX pattern is valid"));

/// Regex for replacing "NOT" keywords (case-sensitive)
static NOT_UPPERCASE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bNOT\b").expect("NOT_UPPERCASE_REGEX pattern is valid"));

/// Regex for replacing "not" keywords (lowercase)
static NOT_LOWERCASE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnot\b").expect("NOT_LOWERCASE_REGEX pattern is valid"));

/// Compiled selection with field criteria and keywords
impl Engine {
    pub(crate) fn transpile_sigma_condition(
        &self,
        condition: &str,
        selection_keys: &[String],
    ) -> String {
        let mut result = condition.to_string();

        // Handle aggregation keywords first (they need access to selection keys)
        // "1 of them" -> "(sel1 || sel2 || sel3)"
        if result.contains("1 of them") {
            let or_expression = format!("({})", selection_keys.join(" || "));
            result = result.replace("1 of them", &or_expression);
        }

        // "all of them" -> "(sel1 && sel2 && sel3)"
        if result.contains("all of them") {
            let and_expression = format!("({})", selection_keys.join(" && "));
            result = result.replace("all of them", &and_expression);
        }

        // Handle pattern-based aggregations like "1 of selection*"
        // Find all occurrences of "X of pattern*"
        for cap in AGGREGATION_REGEX.captures_iter(&result.clone()) {
            let quantifier = &cap[1];
            let pattern = &cap[2];

            // Find all selection keys matching the pattern
            let matching_keys: Vec<String> = selection_keys
                .iter()
                .filter(|k| k.starts_with(pattern))
                .cloned()
                .collect();

            if !matching_keys.is_empty() {
                let replacement = if quantifier == "1" {
                    format!("({})", matching_keys.join(" || "))
                } else {
                    // "all"
                    format!("({})", matching_keys.join(" && "))
                };

                let full_match = &cap[0];
                result = result.replace(full_match, &replacement);
            }
        }

        // Replace Sigma boolean operators with standard operators
        // Use word boundaries to avoid replacing within identifiers
        result = AND_UPPERCASE_REGEX.replace_all(&result, "&&").to_string();
        result = AND_LOWERCASE_REGEX.replace_all(&result, "&&").to_string();

        result = OR_UPPERCASE_REGEX.replace_all(&result, "||").to_string();
        result = OR_LOWERCASE_REGEX.replace_all(&result, "||").to_string();

        result = NOT_UPPERCASE_REGEX.replace_all(&result, "!").to_string();
        result = NOT_LOWERCASE_REGEX.replace_all(&result, "!").to_string();

        result
    }

    /// Phase 3: Evaluate the transpiled condition using evalexpr
    #[allow(dead_code)] // Kept for dedicated transpiler/evaluator unit tests.
    pub(crate) fn check_condition(
        &self,
        condition_str: &str,
        results: &HashMap<String, bool>,
    ) -> bool {
        let mut context = HashMapContext::<DefaultNumericTypes>::new();

        // Load selection results into evaluation context
        for (key, value) in results {
            if let Err(e) = context.set_value(key.clone(), (*value).into()) {
                warn!("Failed to set context value for '{}': {}", key, e);
                return false;
            }
        }

        // Get all selection keys for transpilation
        let selection_keys: Vec<String> = results.keys().cloned().collect();

        // Transpile Sigma syntax to evalexpr-compatible syntax
        let eval_friendly_condition =
            self.transpile_sigma_condition(condition_str, &selection_keys);

        tracing::trace!(
            "Original condition: '{}' -> Transpiled: '{}'",
            condition_str,
            eval_friendly_condition
        );

        // Evaluate the boolean expression
        match eval_boolean_with_context(&eval_friendly_condition, &context) {
            Ok(val) => {
                tracing::trace!("Condition evaluation result: {}", val);
                val
            }
            Err(e) => {
                match self.rule_logic_error_log_level {
                    RuleLogicErrorLogLevel::Off => {}
                    RuleLogicErrorLogLevel::Debug => {
                        debug!(
                            "Rule logic evaluation error for condition '{}': {}",
                            eval_friendly_condition, e
                        );
                    }
                    RuleLogicErrorLogLevel::Warn => {
                        warn!(
                            "Rule logic evaluation error for condition '{}': {}",
                            eval_friendly_condition, e
                        );
                    }
                }
                false
            }
        }
    }

    pub(crate) fn check_compiled_condition(
        &self,
        compiled_rule: &CompiledRule,
        results: &HashMap<String, bool>,
    ) -> bool {
        let Some(tree) = compiled_rule.condition_tree.as_ref() else {
            return false;
        };

        let mut context = HashMapContext::<DefaultNumericTypes>::new();
        for (key, value) in results {
            if let Err(e) = context.set_value(key.clone(), (*value).into()) {
                warn!("Failed to set context value for '{}': {}", key, e);
                return false;
            }
        }

        match tree.eval_boolean_with_context(&context) {
            Ok(val) => {
                tracing::trace!("Condition evaluation result: {}", val);
                val
            }
            Err(e) => {
                let condition = compiled_rule
                    .transpiled_condition
                    .as_deref()
                    .unwrap_or("<missing>");
                match self.rule_logic_error_log_level {
                    RuleLogicErrorLogLevel::Off => {}
                    RuleLogicErrorLogLevel::Debug => {
                        debug!(
                            "Rule logic evaluation error for condition '{}': {}",
                            condition, e
                        );
                    }
                    RuleLogicErrorLogLevel::Warn => {
                        warn!(
                            "Rule logic evaluation error for condition '{}': {}",
                            condition, e
                        );
                    }
                }
                false
            }
        }
    }
}
