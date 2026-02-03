//! Sigma detection engine module
//!
//! Integrates Sigma rule engine and handles rule loading.
//! Checks normalized events against Sigma rules filtered by logsource.

mod handler;

pub use handler::SigmaDetectionHandler;

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use evalexpr::*;
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;
use tracing::{debug, info, warn};

use crate::models::{Alert, AlertSeverity, DetectionEngine, EventCategory, NormalizedEvent};

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

// ============================================================================
// Data Structures
// ============================================================================

/// Sigma rule structure (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    /// Rule title
    pub title: String,

    /// Rule ID
    #[serde(default)]
    pub id: Option<String>,

    /// Rule description
    #[serde(default)]
    pub description: Option<String>,

    /// Rule status
    #[serde(default)]
    pub status: Option<String>,

    /// Rule author
    #[serde(default)]
    pub author: Option<String>,

    /// Rule references
    #[serde(default)]
    pub references: Vec<String>,

    /// Log source definition
    pub logsource: LogSource,

    /// Detection definition
    pub detection: Detection,

    /// Rule level/severity
    #[serde(default)]
    pub level: Option<String>,

    /// Rule tags
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Sigma log source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// Category (e.g., process_creation, network_connection)
    #[serde(default)]
    pub category: Option<String>,

    /// Product (e.g., windows)
    #[serde(default)]
    pub product: Option<String>,

    /// Service (e.g., sysmon)
    #[serde(default)]
    pub service: Option<String>,
}

/// Detection definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Condition string for boolean logic evaluation
    #[serde(default)]
    pub condition: Option<String>,

    /// Selection criteria (can be multiple selections)
    #[serde(flatten)]
    pub selections: HashMap<String, serde_yaml::Value>,
}

/// Numeric comparison operator
#[derive(Debug, Clone, Copy)]
pub enum NumericOp {
    /// Less than
    Lt,
    /// Greater than
    Gt,
    /// Less than or equal
    Le,
    /// Greater than or equal
    Ge,
}

/// Pattern matcher type (determines how matching is performed)
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Auto-detect based on pattern (wildcard or exact)
    Default,
    /// Contains substring
    Contains,
    /// Starts with prefix
    StartsWith,
    /// Ends with suffix
    EndsWith,
    /// All values must match
    All,
    /// Base64 with offset variations
    Base64Offset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleLogicErrorLogLevel {
    Off,
    Debug,
    Warn,
}

impl RuleLogicErrorLogLevel {
    fn from_logging_level(level: &str) -> Self {
        let normalized = level.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "debug" | "trace" => Self::Debug,
            "warn" | "warning" => Self::Warn,
            _ => Self::Off,
        }
    }
}

/// Compiled selection with field criteria and keywords
#[derive(Debug, Clone)]
pub struct Selection {
    /// Field-based criteria (AND logic between fields, OR within values)
    pub field_criteria: Vec<FieldCriterion>,
    /// Keyword-based criteria (match ANY string in ANY field)
    pub keywords: Vec<FieldPattern>,
    /// Alternative field criteria groups (OR between groups, AND within a group)
    pub alternative_field_criteria: Vec<Vec<FieldCriterion>>,
}

/// Field criterion with patterns and matcher
#[derive(Debug, Clone)]
pub struct FieldCriterion {
    /// Field name
    pub field: String,
    /// Patterns to match (OR logic)
    pub patterns: Vec<FieldPattern>,
    /// Pattern matcher type
    pub matcher: PatternMatcher,
}

/// Compiled Sigma rule with regex patterns
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Original rule
    pub rule: SigmaRule,

    /// Compiled field patterns (legacy, kept for backward compatibility)
    #[allow(dead_code)]
    pub patterns: HashMap<String, Vec<FieldPattern>>,

    /// Compiled selections (new structure)
    pub selections: HashMap<String, Selection>,

    /// Logsource category
    pub category: String,
}

/// Field pattern for matching
#[derive(Debug, Clone)]
pub enum FieldPattern {
    /// Exact match (value, case_sensitive)
    Exact(String, bool),

    /// Contains substring (value, case_sensitive)
    Contains(String, bool),

    /// Starts with (value, case_sensitive)
    StartsWith(String, bool),

    /// Ends with (value, case_sensitive)
    EndsWith(String, bool),

    /// Regex match
    Regex(Regex),

    /// Field reference (compare with another field)
    FieldRef(String),

    /// Any of multiple values
    #[allow(dead_code)]
    OneOf(Vec<String>),

    /// CIDR network match
    Cidr(IpNetwork),

    /// Numeric comparison
    Numeric(f64, NumericOp),

    /// Null/missing field check
    Null,

    /// Not null/field exists check
    NotNull,
}

/// Sigma detection engine
pub struct Engine {
    /// Compiled rules indexed by category
    rules_by_category: HashMap<String, Vec<CompiledRule>>,

    /// Total number of loaded rules
    rule_count: usize,

    /// Failed rule paths and error messages (for diagnostics)
    failed_rules: Vec<(String, String)>,

    /// Controls logging for rule logic evaluation errors.
    rule_logic_error_log_level: RuleLogicErrorLogLevel,
}

impl Engine {
    /// Creates a new engine instance
    pub fn new() -> Self {
        Self::new_with_rule_logic_error_log_level(RuleLogicErrorLogLevel::Warn)
    }

    /// Creates a new engine instance that derives rule-logic error logging
    /// behavior from the provided logging level string.
    pub fn new_with_logging_level(logging_level: &str) -> Self {
        let level = RuleLogicErrorLogLevel::from_logging_level(logging_level);
        Self::new_with_rule_logic_error_log_level(level)
    }

    fn new_with_rule_logic_error_log_level(level: RuleLogicErrorLogLevel) -> Self {
        Self {
            rules_by_category: HashMap::new(),
            rule_count: 0,
            failed_rules: Vec::new(),
            rule_logic_error_log_level: level,
        }
    }

    /// Transform string to UTF-16LE wide format (null bytes interleaved)
    fn to_wide(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 2);
        for c in s.chars() {
            result.push(c);
            result.push('\0');
        }
        result
    }

    /// Transform string to UTF-16BE format (Big Endian - null bytes first)
    fn to_utf16be(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 2);
        for c in s.chars() {
            result.push('\0');
            result.push(c);
        }
        result
    }

    /// Convert Sigma wildcard pattern to proper regex with escape handling
    /// Handles: \* -> literal asterisk, \? -> literal question mark, \\ -> literal backslash
    fn convert_sigma_wildcard_to_regex(pattern: &str) -> String {
        let mut regex = String::new();
        let mut chars = pattern.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' {
                // Check next char for escaping
                if let Some(&next) = chars.peek() {
                    match next {
                        '*' | '?' => {
                            // It's an escaped wildcard (literal * or ?)
                            regex.push_str(&regex::escape(&next.to_string()));
                            chars.next(); // Consume the wildcard
                        }
                        '\\' => {
                            // It's an escaped backslash (literal \)
                            regex.push_str("\\\\");
                            chars.next(); // Consume the second backslash
                        }
                        _ => {
                            // Just a backslash (not special)
                            regex.push_str("\\\\");
                        }
                    }
                } else {
                    // Trailing backslash
                    regex.push_str("\\\\");
                }
            } else if c == '*' {
                regex.push_str(".*");
            } else if c == '?' {
                regex.push('.');
            } else {
                // Regular char, escape it for regex safety (e.g. dots, brackets)
                regex.push_str(&regex::escape(&c.to_string()));
            }
        }
        regex
    }

    /// Apply windash modifier: convert dashes/slashes to character class
    /// Replaces '-' and '/' with [-/–—―] (dash, slash, en dash, em dash, horizontal bar)
    fn apply_windash(pattern: &str) -> String {
        let dash_set = "[-/–—―]";
        // Escape the string first to treat it literally
        let escaped = regex::escape(pattern);
        // Replace escaped dashes/slashes with the character class
        // regex::escape converts '-' to "\\-" and '/' to '/'
        escaped.replace("\\-", dash_set).replace("/", dash_set)
    }

    /// Generate Base64 permutations with offsets (0, 1, 2 byte shifts)
    fn to_base64_permutations(s: &str) -> Vec<String> {
        let mut results = Vec::new();

        // Standard encoding (no offset)
        results.push(general_purpose::STANDARD.encode(s));

        // Offset by 1 byte (prepend single null byte)
        let mut offset1 = vec![0u8];
        offset1.extend_from_slice(s.as_bytes());
        let encoded = general_purpose::STANDARD.encode(&offset1);
        // Skip first 4 chars (encoding of the null byte prefix)
        if encoded.len() > 4 {
            results.push(encoded[4..].to_string());
        }

        // Offset by 2 bytes (prepend two null bytes)
        let mut offset2 = vec![0u8, 0u8];
        offset2.extend_from_slice(s.as_bytes());
        let encoded = general_purpose::STANDARD.encode(&offset2);
        // Skip first 4 chars
        if encoded.len() > 4 {
            results.push(encoded[4..].to_string());
        }

        results
    }

    /// Parse field key with modifiers (e.g., "Image|endswith" -> ("Image", ["endswith"]))
    fn parse_field_key<'a>(&self, key: &'a str) -> (&'a str, Vec<&'a str>) {
        let parts: Vec<&str> = key.split('|').collect();
        // split() always returns at least one element, so parts[0] is safe
        // If there's only one part, return empty modifiers
        if parts.len() == 1 {
            (parts[0], vec![])
        } else {
            (parts[0], parts[1..].to_vec())
        }
    }

    /// Determine pattern matcher from modifiers
    fn get_pattern_matcher(&self, modifiers: &[&str]) -> PatternMatcher {
        if modifiers.contains(&"all") {
            return PatternMatcher::All;
        }

        if modifiers.contains(&"base64offset") {
            return PatternMatcher::Base64Offset;
        }

        for modifier in modifiers {
            match *modifier {
                "contains" => return PatternMatcher::Contains,
                "startswith" => return PatternMatcher::StartsWith,
                "endswith" => return PatternMatcher::EndsWith,
                _ => {}
            }
        }
        PatternMatcher::Default
    }

    /// Load rules from a directory (recursively scans subdirectories)
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
        for (category, rules) in &self.rules_by_category {
            info!("  Category '{}': {} rules", category, rules.len());
        }

        Ok(())
    }

    /// Recursively load rules from a directory and its subdirectories
    fn load_rules_recursive<P: AsRef<Path>>(&mut self, dir: P) -> Result<()> {
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

    /// Load a single rule file (supports multi-document YAML for "action: global" rules)
    fn load_rule<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let content = fs::read_to_string(path.as_ref()).context("Failed to read rule file")?;

        // Parse all YAML documents in the file (handles multi-document YAML)
        let documents: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(&content)
            .map(serde_yaml::Value::deserialize)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse YAML documents")?;

        if documents.is_empty() {
            return Err(anyhow::anyhow!("No YAML documents found"));
        }

        // Check if this is a global rule (action: global)
        let is_global = documents
            .first()
            .and_then(|doc| doc.get("action"))
            .and_then(|v| v.as_str())
            .map(|s| s == "global")
            .unwrap_or(false);

        if is_global && documents.len() > 1 {
            // Global rule: first document has metadata, rest have logsource + detection
            let global_metadata = &documents[0];

            // Process each sub-rule (starting from document 1)
            for doc in &documents[1..] {
                // Merge global metadata with sub-rule
                let mut merged = global_metadata.clone();

                // Override with sub-rule's logsource and detection
                if let Some(logsource) = doc.get("logsource") {
                    merged["logsource"] = logsource.clone();
                }
                if let Some(detection) = doc.get("detection") {
                    merged["detection"] = detection.clone();
                }

                // Remove the "action: global" field from merged rule
                if let Some(mapping) = merged.as_mapping_mut() {
                    mapping.remove(serde_yaml::Value::String("action".to_string()));
                }

                // Deserialize the merged document
                let rule: SigmaRule = serde_yaml::from_value(merged)
                    .context("Failed to parse merged global sub-rule")?;

                // Compile and add the rule
                let compiled = self.compile_rule(rule)?;
                let category = compiled.category.clone();
                self.rules_by_category
                    .entry(category)
                    .or_default()
                    .push(compiled);

                self.rule_count += 1;
            }
        } else {
            // Single rule or non-global multi-document (process first document only)
            let rule: SigmaRule =
                serde_yaml::from_value(documents[0].clone()).context("Failed to parse YAML")?;

            // Compile the rule
            let compiled = self.compile_rule(rule)?;

            // Add to appropriate category
            let category = compiled.category.clone();
            self.rules_by_category
                .entry(category)
                .or_default()
                .push(compiled);

            self.rule_count += 1;
        }

        Ok(())
    }

    /// Compile a Sigma rule into efficient matching patterns
    fn compile_rule(&self, rule: SigmaRule) -> Result<CompiledRule> {
        let category = rule
            .logsource
            .category
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

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

        Ok(CompiledRule {
            rule,
            patterns,
            selections,
            category,
        })
    }

    /// Compile a mapping of field -> value into field criteria
    fn compile_field_criteria_from_mapping(
        &self,
        fields: &serde_yaml::Mapping,
        patterns: &mut HashMap<String, Vec<FieldPattern>>,
    ) -> Result<Vec<FieldCriterion>> {
        let mut field_criteria = Vec::new();

        for (field_key, field_value) in fields {
            if let Some(field_key_str) = field_key.as_str() {
                // Parse modifiers from the field key
                let (field_name, modifiers) = self.parse_field_key(field_key_str);

                // Parse the field value with modifiers
                let field_patterns = self.parse_field_value(field_value, &modifiers)?;

                // Determine the pattern matcher from modifiers
                let matcher = self.get_pattern_matcher(&modifiers);

                // Create field criterion
                field_criteria.push(FieldCriterion {
                    field: field_name.to_string(),
                    patterns: field_patterns.clone(),
                    matcher,
                });

                // Also populate legacy patterns for backward compatibility
                patterns
                    .entry(field_name.to_string())
                    .or_default()
                    .extend(field_patterns);
            }
        }

        Ok(field_criteria)
    }

    /// Parse field value into patterns with modifiers
    fn parse_field_value(
        &self,
        value: &serde_yaml::Value,
        modifiers: &[&str],
    ) -> Result<Vec<FieldPattern>> {
        let mut patterns = Vec::new();

        // 1. Detect modifiers
        let is_cased = modifiers.contains(&"cased");
        let is_re = modifiers.contains(&"re");
        let is_windash = modifiers.contains(&"windash");
        let is_fieldref = modifiers.contains(&"fieldref");
        let is_exists = modifiers.contains(&"exists");
        let is_cidr = modifiers.contains(&"cidr");

        // Transformation modifiers
        let has_base64 = modifiers.contains(&"base64");
        let has_base64offset = modifiers.contains(&"base64offset");
        let has_wide = modifiers.contains(&"wide")
            || modifiers.contains(&"utf16le")
            || modifiers.contains(&"utf16");
        let has_utf16be = modifiers.contains(&"utf16be");

        // Comparison modifiers
        let numeric_op = if modifiers.contains(&"lt") {
            Some(NumericOp::Lt)
        } else if modifiers.contains(&"gt") {
            Some(NumericOp::Gt)
        } else if modifiers.contains(&"lte") || modifiers.contains(&"le") {
            Some(NumericOp::Le)
        } else if modifiers.contains(&"gte") || modifiers.contains(&"ge") {
            Some(NumericOp::Ge)
        } else {
            None
        };

        // 2. Handle 'exists' modifier explicitly
        if is_exists {
            if let Some(b) = value.as_bool() {
                return Ok(vec![if b {
                    FieldPattern::NotNull
                } else {
                    FieldPattern::Null
                }]);
            } else if let Some(s) = value.as_str() {
                if s.eq_ignore_ascii_case("true") {
                    return Ok(vec![FieldPattern::NotNull]);
                }
                if s.eq_ignore_ascii_case("false") {
                    return Ok(vec![FieldPattern::Null]);
                }
            }
        }

        // 3. Handle 'fieldref' modifier
        if is_fieldref {
            if let Some(s) = value.as_str() {
                return Ok(vec![FieldPattern::FieldRef(s.to_string())]);
            }
        }

        let append_value_patterns = |value: &serde_yaml::Value,
                                     patterns: &mut Vec<FieldPattern>|
         -> Result<()> {
            match value {
                serde_yaml::Value::Null => {
                    patterns.push(FieldPattern::Null);
                }
                serde_yaml::Value::String(s) => {
                    if s.is_empty() {
                        // Empty string means "exists" check
                        patterns.push(FieldPattern::NotNull);
                    } else if is_cidr {
                        // Parse as CIDR
                        if let Ok(network) = s.parse::<IpNetwork>() {
                            patterns.push(FieldPattern::Cidr(network));
                        }
                    } else if let Some(op) = numeric_op {
                        // Parse as numeric
                        if let Ok(num) = s.parse::<f64>() {
                            patterns.push(FieldPattern::Numeric(num, op));
                        }
                    } else if is_re {
                        // 4. Handle explicit Regex with flags
                        let mut flags = String::new();

                        // Check for regex flags
                        if modifiers.contains(&"i") {
                            flags.push_str("(?i)");
                        }
                        if modifiers.contains(&"m") {
                            flags.push_str("(?m)");
                        }
                        if modifiers.contains(&"s") {
                            flags.push_str("(?s)");
                        }

                        // If no flags specified, regex is case-sensitive by default
                        let re_str = format!("{}{}", flags, s);
                        if let Ok(re) = Regex::new(&re_str) {
                            patterns.push(FieldPattern::Regex(re));
                        } else {
                            warn!("Invalid Regex in rule: {}", s);
                        }
                    } else if is_windash {
                        // 5. Handle Windash (Converts to Regex)
                        let windash_pattern = Self::apply_windash(s);
                        let re_str = if is_cased {
                            format!("^{}$", windash_pattern)
                        } else {
                            format!("(?i)^{}$", windash_pattern)
                        };
                        if let Ok(re) = Regex::new(&re_str) {
                            patterns.push(FieldPattern::Regex(re));
                        } else {
                            warn!("Invalid Windash pattern: {}", s);
                        }
                    } else {
                        // 6. Standard String Matching with transformations
                        let mut values = vec![s.clone()];

                        // Apply transformations in order
                        if has_wide {
                            values = values.iter().map(|v| Self::to_wide(v)).collect();
                        }
                        if has_utf16be {
                            values = values.iter().map(|v| Self::to_utf16be(v)).collect();
                        }
                        if has_base64 {
                            values = values
                                .iter()
                                .map(|v| general_purpose::STANDARD.encode(v))
                                .collect();
                        }
                        if has_base64offset {
                            let mut all_permutations = Vec::new();
                            for v in &values {
                                all_permutations.extend(Self::to_base64_permutations(v));
                            }
                            values = all_permutations;
                        }

                        // Parse each transformed value as a pattern
                        for v in values {
                            patterns.push(
                                self.parse_string_pattern_with_modifiers(&v, modifiers, is_cased),
                            );
                        }
                    }
                }
                serde_yaml::Value::Number(n) => {
                    if let Some(f) = n.as_f64() {
                        if let Some(op) = numeric_op {
                            patterns.push(FieldPattern::Numeric(f, op));
                        } else {
                            // Treat as exact match on string representation
                            patterns.push(FieldPattern::Exact(n.to_string(), is_cased));
                        }
                    }
                }
                serde_yaml::Value::Sequence(_) => {
                    // Nested sequences are not expected here, ignore.
                }
                _ => {
                    // Try to convert to string
                    if let Some(s) = value.as_str() {
                        patterns
                            .push(self.parse_string_pattern_with_modifiers(s, modifiers, is_cased));
                    }
                }
            }

            Ok(())
        };

        match value {
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    append_value_patterns(item, &mut patterns)?;
                }
            }
            _ => {
                append_value_patterns(value, &mut patterns)?;
            }
        }

        Ok(patterns)
    }

    /// Parse a string into a pattern with modifiers and case sensitivity
    fn parse_string_pattern_with_modifiers(
        &self,
        s: &str,
        modifiers: &[&str],
        is_cased: bool,
    ) -> FieldPattern {
        // Check for wildcard patterns (unless it's an escaped wildcard like \*)
        if s.contains('*') || s.contains('?') {
            // Use proper escape handling
            let pattern = Self::convert_sigma_wildcard_to_regex(s);

            // Apply case sensitivity
            let prefix = if is_cased { "" } else { "(?i)" };
            let regex_str = format!("{}^{}$", prefix, pattern);

            match Regex::new(&regex_str) {
                Ok(regex) => FieldPattern::Regex(regex),
                Err(_) => {
                    warn!("Failed to compile wildcard regex: {}", s);
                    FieldPattern::Contains(s.to_string(), is_cased)
                }
            }
        } else {
            // Explicit modifiers override auto-detection
            if modifiers.contains(&"contains") {
                FieldPattern::Contains(s.to_string(), is_cased)
            } else if modifiers.contains(&"startswith") {
                FieldPattern::StartsWith(s.to_string(), is_cased)
            } else if modifiers.contains(&"endswith") {
                FieldPattern::EndsWith(s.to_string(), is_cased)
            } else {
                // Exact match (default)
                FieldPattern::Exact(s.to_string(), is_cased)
            }
        }
    }

    /// Parse a string into a pattern (legacy method for backward compatibility)
    /// Default is case-insensitive
    fn parse_string_pattern(&self, s: &str) -> FieldPattern {
        self.parse_string_pattern_with_modifiers(s, &[], false)
    }

    /// Phase 1: Evaluate all selections in a rule against an event
    /// Returns a HashMap of selection_id -> match_result
    /// OPTIMIZED: Takes &NormalizedEvent directly for zero-copy field access
    fn evaluate_selections(
        &self,
        event: &NormalizedEvent,
        rule: &CompiledRule,
    ) -> HashMap<String, bool> {
        let mut results = HashMap::new();

        // Iterate through compiled selections
        for (selection_id, selection) in &rule.selections {
            let is_match = self.check_selection(event, selection);
            results.insert(selection_id.clone(), is_match);
        }

        results
    }

    /// Check if a selection matches an event
    /// OPTIMIZED: Takes &NormalizedEvent directly
    fn check_selection(&self, event: &NormalizedEvent, selection: &Selection) -> bool {
        // If there are keywords, check if any keyword matches anywhere in the event
        if !selection.keywords.is_empty() && self.check_keywords(event, &selection.keywords) {
            return true;
        }

        let mut has_criteria = false;

        if !selection.alternative_field_criteria.is_empty() {
            has_criteria = true;
            if selection
                .alternative_field_criteria
                .iter()
                .any(|criteria| self.check_field_criteria_group(event, criteria))
            {
                return true;
            }
        }

        if !selection.field_criteria.is_empty() {
            has_criteria = true;
            if self.check_field_criteria_group(event, &selection.field_criteria) {
                return true;
            }
        }

        if has_criteria {
            return false;
        }

        // Empty selection should not match (safety guard)
        false
    }

    /// Check if a group of field criteria matches (AND logic between fields)
    fn check_field_criteria_group(
        &self,
        event: &NormalizedEvent,
        criteria: &[FieldCriterion],
    ) -> bool {
        for criterion in criteria {
            if !self.check_field_criterion(event, criterion) {
                return false;
            }
        }

        true
    }

    /// Check if keywords match anywhere in the event
    /// OPTIMIZED: Takes &NormalizedEvent directly
    fn check_keywords(&self, event: &NormalizedEvent, keywords: &[FieldPattern]) -> bool {
        // Get all field values from the event
        let event_values = event.all_field_values();

        // Check if ANY keyword matches ANY value
        for keyword_pattern in keywords {
            for value in &event_values {
                if self.matches_pattern(value, keyword_pattern, None) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a field criterion matches
    /// OPTIMIZED: Takes &NormalizedEvent directly
    fn check_field_criterion(&self, event: &NormalizedEvent, criterion: &FieldCriterion) -> bool {
        let field_value = event.get_field(&criterion.field);

        // Handle null checks or missing fields
        let field_value = match field_value {
            Some(value) => value,
            None => {
                // Field is missing - check if any pattern matches null
                return criterion
                    .patterns
                    .iter()
                    .any(|pattern| self.matches_pattern_null(pattern));
            }
        };

        // Apply pattern matcher logic
        match criterion.matcher {
            PatternMatcher::All => {
                // ALL patterns must match
                criterion
                    .patterns
                    .iter()
                    .all(|pattern| self.matches_pattern(field_value, pattern, Some(event)))
            }
            _ => {
                // Default, Contains, StartsWith, EndsWith, Base64Offset:
                // At least ONE pattern must match (OR logic)
                criterion
                    .patterns
                    .iter()
                    .any(|pattern| self.matches_pattern(field_value, pattern, Some(event)))
            }
        }
    }

    /// Helper: Check if event matches all patterns in a selection (AND logic)
    /// Legacy method for backward compatibility - kept but not used
    #[allow(dead_code)]
    fn check_selection_patterns(
        &self,
        event: &NormalizedEvent,
        patterns: &HashMap<String, Vec<FieldPattern>>,
    ) -> bool {
        // All field patterns must match (AND logic)
        for (field_name, field_patterns) in patterns {
            let field_value = event.get_field(field_name);

            // Handle null checks or missing fields
            let field_value = match field_value {
                Some(value) => value,
                None => {
                    // Check if any pattern matches null
                    let has_null_match = field_patterns
                        .iter()
                        .any(|pattern| self.matches_pattern_null(pattern));
                    if !has_null_match {
                        return false;
                    }
                    continue;
                }
            };

            // At least one pattern must match for this field (OR within field)
            let matches = field_patterns
                .iter()
                .any(|pattern| self.matches_pattern(field_value, pattern, Some(event)));

            if !matches {
                return false;
            }
        }

        true
    }

    /// Phase 2: Transpile Sigma condition syntax to evalexpr-compatible boolean expressions
    fn transpile_sigma_condition(&self, condition: &str, selection_keys: &[String]) -> String {
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
    fn check_condition(&self, condition_str: &str, results: &HashMap<String, bool>) -> bool {
        let mut context = HashMapContext::new();

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

        debug!(
            "Original condition: '{}' -> Transpiled: '{}'",
            condition_str, eval_friendly_condition
        );

        // Evaluate the boolean expression
        match eval_boolean_with_context(&eval_friendly_condition, &context) {
            Ok(val) => {
                debug!("Condition evaluation result: {}", val);
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

    /// Check an event against loaded rules
    /// OPTIMIZED: Uses zero-copy field access instead of HashMap creation
    pub fn check_event(&self, event: &NormalizedEvent) -> Option<Alert> {
        let categories = Self::sigma_categories_for_event(event);

        // PERFORMANCE: Pass event directly - no HashMap allocation!
        // This eliminates 10,000+ heap allocations per second

        for category in categories {
            let Some(rules) = self.rules_by_category.get(category) else {
                continue;
            };

            debug!(
                "Checking event against {} rule(s) in category '{}'",
                rules.len(),
                category
            );

            // Check each rule
            for compiled_rule in rules {
                debug!("========================================");
                debug!("Evaluating rule: '{}'", compiled_rule.rule.title);
                debug!("Rule ID: {:?}", compiled_rule.rule.id);

                // NOTE: Detailed field logging removed for performance (avoid HashMap allocation)
                // Use get_field() or all_field_values() if debugging specific fields

                let is_match = if let Some(condition) = &compiled_rule.rule.detection.condition {
                    // NEW LOGIC PIPELINE: Rule has explicit condition
                    debug!(
                        "Rule '{}': Using condition-based evaluation: '{}'",
                        compiled_rule.rule.title, condition
                    );

                    // Phase 1: Evaluate all selections
                    let selection_results = self.evaluate_selections(event, compiled_rule);

                    debug!("Selection evaluation results:");
                    for (sel_id, result) in &selection_results {
                        debug!("  {} = {}", sel_id, result);
                    }

                    // Phase 3: Evaluate condition (Phase 2 is done inside check_condition)
                    let condition_result = self.check_condition(condition, &selection_results);
                    debug!("Final condition result: {}", condition_result);
                    condition_result
                } else {
                    // LEGACY LOGIC: No explicit condition, use simple AND logic (implied OR)
                    // This is the default behavior for older Sigma rules
                    debug!(
                        "Rule '{}': Using legacy AND/OR evaluation (no condition)",
                        compiled_rule.rule.title
                    );

                    // Evaluate all selections and return true if ANY match (implied OR)
                    let selection_results = self.evaluate_selections(event, compiled_rule);

                    debug!("Selection evaluation results:");
                    for (sel_id, result) in &selection_results {
                        debug!("  {} = {}", sel_id, result);
                    }

                    let any_match = selection_results.values().any(|&v| v);
                    debug!("Legacy evaluation (any selection matches): {}", any_match);
                    any_match
                };

                if is_match {
                    debug!("✓ Rule '{}' MATCHED!", compiled_rule.rule.title);

                    // Create alert
                    let severity = match compiled_rule.rule.level.as_deref() {
                        Some("critical") => AlertSeverity::Critical,
                        Some("high") => AlertSeverity::High,
                        Some("medium") => AlertSeverity::Medium,
                        _ => AlertSeverity::Low,
                    };

                    return Some(Alert {
                        severity,
                        rule_name: compiled_rule.rule.title.clone(),
                        engine: DetectionEngine::Sigma,
                        event: event.clone(),
                    });
                } else {
                    debug!("✗ Rule '{}' did NOT match", compiled_rule.rule.title);
                }
            }
        }

        None
    }

    fn sigma_categories_for_event(event: &NormalizedEvent) -> Vec<&'static str> {
        let mut categories = Vec::with_capacity(3);

        match event.category {
            EventCategory::Process => {
                // Focus on process creation; process termination rules are less common and noisy.
                categories.push("process_creation");
            }
            EventCategory::Network => {
                categories.push("network_connection");
            }
            EventCategory::File => {
                categories.push("file_event");
                match event.opcode {
                    64 | 65 => categories.push("file_create"),
                    70 | 72 => categories.push("file_delete"),
                    _ => {}
                }
            }
            EventCategory::Registry => {
                categories.push("registry_event");
                match event.opcode {
                    36 => categories.push("registry_add"),
                    39 => categories.push("registry_set"),
                    38 | 41 => categories.push("registry_delete"),
                    _ => {}
                }
            }
            EventCategory::Dns => {
                categories.push("dns_query");
            }
            EventCategory::ImageLoad => {
                categories.push("image_load");
            }
            EventCategory::Scripting => {
                categories.push("ps_script");
            }
            EventCategory::Wmi => {
                categories.push("wmi_event");
            }
            EventCategory::Service => {
                categories.push("service_creation");
            }
            EventCategory::Task => {
                categories.push("task_creation");
            }
            EventCategory::PipeEvent => {
                categories.push("pipe_created");
            }
        }

        categories
    }

    /// Check if event matches a compiled rule (legacy method, kept for backward compatibility)
    /// OPTIMIZED: Takes &NormalizedEvent directly
    #[allow(dead_code)]
    fn matches_rule(&self, event: &NormalizedEvent, rule: &CompiledRule) -> bool {
        use tracing::debug;

        // Simple AND logic: all patterns must match
        for (field_name, patterns) in &rule.patterns {
            let field_value = event.get_field(field_name);

            let field_value = match field_value {
                Some(value) => value,
                None => {
                    debug!(
                        "Rule '{}': Field '{}' not found in event",
                        rule.rule.title, field_name
                    );
                    return false;
                }
            };

            debug!(
                "Rule '{}': Checking field '{}' = '{}'",
                rule.rule.title, field_name, field_value
            );

            // Check if any pattern matches (OR within field)
            let matches = patterns.iter().any(|pattern| {
                let result = self.matches_pattern(field_value, pattern, Some(event));
                debug!(
                    "  Pattern {:?} matches '{}': {}",
                    pattern, field_value, result
                );
                result
            });

            if !matches {
                debug!(
                    "Rule '{}': No pattern matched for field '{}'",
                    rule.rule.title, field_name
                );
                return false;
            }
        }

        debug!("Rule '{}': ALL patterns matched!", rule.rule.title);
        true
    }

    /// Check if value matches pattern (value is Some)
    /// OPTIMIZED: Now accepts optional &NormalizedEvent for fieldref support
    fn matches_pattern(
        &self,
        value: &str,
        pattern: &FieldPattern,
        event: Option<&NormalizedEvent>,
    ) -> bool {
        match pattern {
            FieldPattern::Exact(s, cased) => {
                if *cased {
                    value == s
                } else {
                    value.eq_ignore_ascii_case(s)
                }
            }
            FieldPattern::Contains(s, cased) => {
                if *cased {
                    value.contains(s)
                } else {
                    // OPTIMIZED: Zero-allocation case-insensitive contains check
                    // Uses sliding window instead of allocating lowercase strings
                    if s.is_empty() {
                        return true;
                    }
                    if value.len() < s.len() {
                        return false;
                    }
                    // Check each possible position in value
                    for i in 0..=(value.len() - s.len()) {
                        // FIX: Ensure we only slice at valid UTF-8 boundaries
                        // Skip positions that would split multi-byte characters
                        if !value.is_char_boundary(i) || !value.is_char_boundary(i + s.len()) {
                            continue;
                        }

                        if value[i..i + s.len()].eq_ignore_ascii_case(s) {
                            return true;
                        }
                    }
                    false
                }
            }
            FieldPattern::StartsWith(s, cased) => {
                if *cased {
                    value.starts_with(s)
                } else {
                    // OPTIMIZED: Zero-allocation check
                    // FIX: Check boundary before slicing
                    if value.len() >= s.len() && value.is_char_boundary(s.len()) {
                        value[..s.len()].eq_ignore_ascii_case(s)
                    } else {
                        false
                    }
                }
            }
            FieldPattern::EndsWith(s, cased) => {
                if *cased {
                    value.ends_with(s)
                } else {
                    // OPTIMIZED: Zero-allocation check
                    // FIX: Check boundary before slicing
                    let start_index = value.len().saturating_sub(s.len());
                    if value.len() >= s.len() && value.is_char_boundary(start_index) {
                        value[start_index..].eq_ignore_ascii_case(s)
                    } else {
                        false
                    }
                }
            }
            FieldPattern::Regex(regex) => regex.is_match(value),
            FieldPattern::FieldRef(other_field) => {
                // Field reference: compare with another field in the same event
                if let Some(ev) = event {
                    if let Some(other_val) = ev.get_field(other_field) {
                        // Usually case-insensitive exact match for fieldref
                        return value.eq_ignore_ascii_case(other_val);
                    }
                }
                false
            }
            FieldPattern::OneOf(values) => values.iter().any(|v| value.eq_ignore_ascii_case(v)),
            FieldPattern::Cidr(network) => {
                // Try to parse value as IP address
                if let Ok(ip) = value.parse::<IpAddr>() {
                    network.contains(ip)
                } else {
                    false
                }
            }
            FieldPattern::Numeric(threshold, op) => {
                // Try to parse value as number
                if let Ok(num) = value.parse::<f64>() {
                    match op {
                        NumericOp::Lt => num < *threshold,
                        NumericOp::Gt => num > *threshold,
                        NumericOp::Le => num <= *threshold,
                        NumericOp::Ge => num >= *threshold,
                    }
                } else {
                    false
                }
            }
            FieldPattern::Null => {
                // This should be handled by check_selection_patterns when value is None
                // If we reach here with a Some value, it doesn't match
                false
            }
            FieldPattern::NotNull => {
                // Field exists (we have a value), so this matches
                true
            }
        }
    }

    /// Check if pattern matches None (field is missing)
    fn matches_pattern_null(&self, pattern: &FieldPattern) -> bool {
        matches!(pattern, FieldPattern::Null)
    }

    /// Get statistics about loaded rules
    pub fn stats(&self) -> EngineStats {
        EngineStats {
            total_rules: self.rule_count,
            rules_by_category: self
                .rules_by_category
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect(),
            failed_rules: self.failed_rules.clone(),
        }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Engine statistics
#[derive(Debug, Clone)]
pub struct EngineStats {
    pub total_rules: usize,
    pub rules_by_category: HashMap<String, usize>,
    #[allow(dead_code)] // Used by validation binaries outside this crate.
    pub failed_rules: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventFields, ProcessCreationFields};

    #[test]
    fn test_engine_creation() {
        let engine = Engine::new();
        assert_eq!(engine.rule_count, 0);
    }

    #[test]
    fn test_pattern_matching() {
        let engine = Engine::new();

        // Test exact match (case-insensitive by default)
        let pattern = FieldPattern::Exact("whoami.exe".to_string(), false);
        assert!(engine.matches_pattern("whoami.exe", &pattern, None));
        assert!(engine.matches_pattern("WHOAMI.EXE", &pattern, None));
        assert!(!engine.matches_pattern("cmd.exe", &pattern, None));

        // Test exact match (case-sensitive)
        let pattern = FieldPattern::Exact("whoami.exe".to_string(), true);
        assert!(engine.matches_pattern("whoami.exe", &pattern, None));
        assert!(!engine.matches_pattern("WHOAMI.EXE", &pattern, None));

        // Test contains (case-insensitive)
        let pattern = FieldPattern::Contains("whoami".to_string(), false);
        assert!(engine.matches_pattern("whoami.exe", &pattern, None));
        assert!(engine.matches_pattern("C:\\Windows\\System32\\whoami.exe", &pattern, None));

        // Test starts with
        let pattern = FieldPattern::StartsWith("C:\\Windows".to_string(), false);
        assert!(engine.matches_pattern("C:\\Windows\\System32\\cmd.exe", &pattern, None));
        assert!(!engine.matches_pattern("C:\\Temp\\test.exe", &pattern, None));
    }

    #[test]
    fn test_string_pattern_parsing() {
        let engine = Engine::new();

        // Wildcard pattern
        let pattern = engine.parse_string_pattern("*whoami*");
        match pattern {
            FieldPattern::Regex(_) => {}
            _ => panic!("Expected regex pattern"),
        }

        // Exact pattern (default is case-insensitive)
        let pattern = engine.parse_string_pattern("whoami.exe");
        match pattern {
            FieldPattern::Exact(s, cased) => {
                assert_eq!(s, "whoami.exe");
                assert!(!cased); // Default is case-insensitive
            }
            _ => panic!("Expected exact pattern"),
        }
    }

    #[test]
    fn test_sequence_endswith_modifier_respected() {
        let engine = Engine::new();
        let rule_yaml = r#"
title: EndsWithList
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '.exe'
      - '.com'
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        let mut engine = Engine::new();
        engine
            .rules_by_category
            .entry(compiled.category.clone())
            .or_default()
            .push(compiled);

        let mut event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some("1234".to_string()),
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        };

        assert!(engine.check_event(&event).is_some());

        if let EventFields::ProcessCreation(ref mut fields) = event.fields {
            fields.image = Some("C:\\Windows\\System32\\cmd.exe.bak".to_string());
        }

        assert!(engine.check_event(&event).is_none());
    }

    #[test]
    fn test_contains_all_modifier_requires_all_tokens() {
        let engine = Engine::new();
        let rule_yaml = r#"
title: ContainsAllTokens
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - 'foo'
      - 'bar'
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        let mut engine = Engine::new();
        engine
            .rules_by_category
            .entry(compiled.category.clone())
            .or_default()
            .push(compiled);

        let mut event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
                command_line: Some("foo baz".to_string()),
                process_id: Some("1234".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        };

        assert!(engine.check_event(&event).is_none());

        if let EventFields::ProcessCreation(ref mut fields) = event.fields {
            fields.command_line = Some("foo bar baz".to_string());
        }

        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_cased_sequence_respects_case() {
        let engine = Engine::new();
        let rule_yaml = r#"
title: CaseSensitiveList
logsource:
  category: process_creation
detection:
  selection:
    Image|cased:
      - C:\Windows\System32\cmd.exe
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        let mut engine = Engine::new();
        engine
            .rules_by_category
            .entry(compiled.category.clone())
            .or_default()
            .push(compiled);

        let mut event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("c:\\windows\\system32\\cmd.exe".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some("1234".to_string()),
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        };

        // Case should NOT match with different casing.
        assert!(engine.check_event(&event).is_none());

        if let EventFields::ProcessCreation(ref mut fields) = event.fields {
            fields.image = Some("C:\\Windows\\System32\\cmd.exe".to_string());
        }

        // Exact case should match.
        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_rule_loading() {
        let mut engine = Engine::new();

        // Try to load rules from the rules/sigma directory
        // This test will pass even if the directory doesn't exist
        let _ = engine.load_rules("rules/sigma");

        // Get stats
        let stats = engine.stats();

        // If rules loaded, verify they're categorized
        if stats.total_rules > 0 {
            assert!(
                !stats.rules_by_category.is_empty(),
                "Rules should be categorized"
            );
        }
    }

    #[test]
    fn test_event_matching() {
        use crate::models::*;

        let engine = Engine::new();

        // Create a mock normalized event for whoami.exe
        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\whoami.exe".to_string()),
                command_line: Some("whoami".to_string()),
                process_id: Some("1234".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some("TestUser".to_string()),
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        };

        // Check event (should return None since we haven't loaded rules in this test)
        let result = engine.check_event(&event);

        // In a test without rules loaded, this should be None
        assert!(result.is_none());
    }

    // ===== NEW TESTS FOR ENHANCED SIGMA LOGIC =====

    #[test]
    fn test_transpile_basic_operators() {
        let engine = Engine::new();
        let keys = vec!["sel1".to_string(), "sel2".to_string()];

        // Test AND operator
        let result = engine.transpile_sigma_condition("sel1 and sel2", &keys);
        assert_eq!(result, "sel1 && sel2");

        // Test OR operator
        let result = engine.transpile_sigma_condition("sel1 or sel2", &keys);
        assert_eq!(result, "sel1 || sel2");

        // Test NOT operator
        let result = engine.transpile_sigma_condition("not sel1", &keys);
        assert_eq!(result, "! sel1");

        // Test uppercase variants
        let result = engine.transpile_sigma_condition(
            "sel1 AND sel2 OR sel3",
            &["sel1".to_string(), "sel2".to_string(), "sel3".to_string()],
        );
        assert_eq!(result, "sel1 && sel2 || sel3");
    }

    #[test]
    fn test_transpile_1_of_them() {
        let engine = Engine::new();
        let keys = vec![
            "selection1".to_string(),
            "selection2".to_string(),
            "selection3".to_string(),
        ];

        let result = engine.transpile_sigma_condition("1 of them", &keys);
        assert!(result.contains("selection1"));
        assert!(result.contains("selection2"));
        assert!(result.contains("selection3"));
        assert!(result.contains("||"));
    }

    #[test]
    fn test_transpile_all_of_them() {
        let engine = Engine::new();
        let keys = vec!["sel1".to_string(), "sel2".to_string()];

        let result = engine.transpile_sigma_condition("all of them", &keys);
        assert!(result.contains("sel1"));
        assert!(result.contains("sel2"));
        assert!(result.contains("&&"));
    }

    #[test]
    fn test_transpile_pattern_aggregation() {
        let engine = Engine::new();
        let keys = vec![
            "selection_img".to_string(),
            "selection_cmd".to_string(),
            "other".to_string(),
        ];

        let result = engine.transpile_sigma_condition("all of selection*", &keys);
        // Should only include keys starting with "selection"
        assert!(result.contains("selection_img"));
        assert!(result.contains("selection_cmd"));
        assert!(!result.contains("other"));
        assert!(result.contains("&&"));
    }

    #[test]
    fn test_transpile_complex_expression() {
        let engine = Engine::new();
        let keys = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        let result = engine.transpile_sigma_condition("(a or b) and not c", &keys);
        assert_eq!(result, "(a || b) && ! c");
    }

    #[test]
    fn test_check_condition_simple_and() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("selection1".to_string(), true);
        results.insert("selection2".to_string(), false);

        // selection1 AND selection2 -> true AND false -> false
        let is_match = engine.check_condition("selection1 and selection2", &results);
        assert!(!is_match);

        // Both true
        results.insert("selection2".to_string(), true);
        let is_match = engine.check_condition("selection1 and selection2", &results);
        assert!(is_match);
    }

    #[test]
    fn test_check_condition_and_not() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("selection1".to_string(), true);
        results.insert("selection2".to_string(), false);

        // selection1 AND NOT selection2 -> true AND NOT false -> true AND true -> true
        let is_match = engine.check_condition("selection1 and not selection2", &results);
        assert!(is_match);

        // Now make selection2 true
        results.insert("selection2".to_string(), true);
        // selection1 AND NOT selection2 -> true AND NOT true -> true AND false -> false
        let is_match = engine.check_condition("selection1 and not selection2", &results);
        assert!(!is_match);
    }

    #[test]
    fn test_check_condition_1_of_them() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("proc_creation".to_string(), false);
        results.insert("file_event".to_string(), true);

        // 1 of them -> proc_creation OR file_event -> false OR true -> true
        let is_match = engine.check_condition("1 of them", &results);
        assert!(is_match);

        // All false
        results.insert("file_event".to_string(), false);
        let is_match = engine.check_condition("1 of them", &results);
        assert!(!is_match);
    }

    #[test]
    fn test_check_condition_parentheses() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("a".to_string(), true);
        results.insert("b".to_string(), false);
        results.insert("c".to_string(), true);

        // (a OR b) AND c -> (true OR false) AND true -> true AND true -> true
        let is_match = engine.check_condition("(a or b) and c", &results);
        assert!(is_match);

        // a OR (b AND c) -> true OR (false AND true) -> true OR false -> true
        let is_match = engine.check_condition("a or (b and c)", &results);
        assert!(is_match);
    }

    #[test]
    fn test_evaluate_selections() {
        let engine = Engine::new();

        // Create a test rule with multiple selections
        let rule_yaml = r#"
title: Test Rule
logsource:
  category: process_creation
detection:
  selection1:
    Image: "*whoami.exe"
  selection2:
    CommandLine: "*priv*"
  condition: selection1 and selection2
level: high
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        // Create event that matches selection1 but not selection2
        use crate::models::*;
        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\whoami.exe".to_string()),
                command_line: Some("whoami".to_string()),
                process_id: None,
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        };

        let results = engine.evaluate_selections(&event, &compiled);

        assert_eq!(results.get("selection1"), Some(&true));
        assert_eq!(results.get("selection2"), Some(&false));
    }
}
