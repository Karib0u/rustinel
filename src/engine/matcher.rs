use super::*;

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

impl Engine {
    pub(crate) fn to_wide(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 2);
        for c in s.chars() {
            result.push(c);
            result.push('\0');
        }
        result
    }

    /// Transform string to UTF-16BE format (Big Endian - null bytes first)
    pub(crate) fn to_utf16be(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 2);
        for c in s.chars() {
            result.push('\0');
            result.push(c);
        }
        result
    }

    /// Convert Sigma wildcard pattern to proper regex with escape handling
    /// Handles: \* -> literal asterisk, \? -> literal question mark, \\ -> literal backslash
    pub(crate) fn convert_sigma_wildcard_to_regex(pattern: &str) -> String {
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
    pub(crate) fn apply_windash(pattern: &str) -> String {
        let dash_set = "[-/–—―]";
        // Escape the string first to treat it literally
        let escaped = regex::escape(pattern);
        // Replace escaped dashes/slashes with the character class
        // regex::escape converts '-' to "\\-" and '/' to '/'
        escaped.replace("\\-", dash_set).replace("/", dash_set)
    }

    /// Generate Base64 permutations with offsets (0, 1, 2 byte shifts)
    pub(crate) fn to_base64_permutations(s: &str) -> Vec<String> {
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
    pub(crate) fn parse_field_key<'a>(&self, key: &'a str) -> (&'a str, Vec<&'a str>) {
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
    pub(crate) fn get_pattern_matcher(&self, modifiers: &[&str]) -> PatternMatcher {
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

    pub(crate) fn validate_modifiers(&self, field_name: &str, modifiers: &[&str]) -> Result<()> {
        for modifier in modifiers {
            let supported = matches!(
                *modifier,
                "contains"
                    | "startswith"
                    | "endswith"
                    | "all"
                    | "base64offset"
                    | "cased"
                    | "re"
                    | "windash"
                    | "fieldref"
                    | "exists"
                    | "cidr"
                    | "base64"
                    | "wide"
                    | "utf16"
                    | "utf16le"
                    | "utf16be"
                    | "lt"
                    | "gt"
                    | "lte"
                    | "le"
                    | "gte"
                    | "ge"
                    | "i"
                    | "m"
                    | "s"
            );

            if !supported {
                return Err(anyhow::anyhow!(
                    "Unsupported Sigma modifier '{}' on field '{}'",
                    modifier,
                    field_name
                ));
            }
        }

        Ok(())
    }
    pub(crate) fn compile_field_criteria_from_mapping(
        &self,
        fields: &serde_yaml::Mapping,
        patterns: &mut HashMap<String, Vec<FieldPattern>>,
    ) -> Result<Vec<FieldCriterion>> {
        let mut field_criteria = Vec::new();

        for (field_key, field_value) in fields {
            if let Some(field_key_str) = field_key.as_str() {
                // Parse modifiers from the field key
                let (field_name, modifiers) = self.parse_field_key(field_key_str);
                self.validate_modifiers(field_name, &modifiers)?;

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
    pub(crate) fn parse_field_value(
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
    pub(crate) fn parse_string_pattern_with_modifiers(
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
    pub(crate) fn parse_string_pattern(&self, s: &str) -> FieldPattern {
        self.parse_string_pattern_with_modifiers(s, &[], false)
    }

    /// Phase 1: Evaluate all selections in a rule against an event
    /// Returns a HashMap of selection_id -> match_result
    /// OPTIMIZED: Takes &NormalizedEvent directly for zero-copy field access
    pub(crate) fn evaluate_selections(
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
    pub(crate) fn check_selection(&self, event: &NormalizedEvent, selection: &Selection) -> bool {
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
    pub(crate) fn check_field_criteria_group(
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
    pub(crate) fn check_keywords(
        &self,
        event: &NormalizedEvent,
        keywords: &[FieldPattern],
    ) -> bool {
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
    pub(crate) fn check_field_criterion(
        &self,
        event: &NormalizedEvent,
        criterion: &FieldCriterion,
    ) -> bool {
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
    pub(crate) fn check_selection_patterns(
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

    #[allow(dead_code)]
    pub(crate) fn matches_rule(&self, event: &NormalizedEvent, rule: &CompiledRule) -> bool {
        use tracing::trace;

        // Simple AND logic: all patterns must match
        for (field_name, patterns) in &rule.patterns {
            let field_value = event.get_field(field_name);

            let field_value = match field_value {
                Some(value) => value,
                None => {
                    trace!(
                        "Rule '{}': Field '{}' not found in event",
                        rule.rule.title,
                        field_name
                    );
                    return false;
                }
            };

            trace!(
                "Rule '{}': Checking field '{}' = '{}'",
                rule.rule.title,
                field_name,
                field_value
            );

            // Check if any pattern matches (OR within field)
            let matches = patterns.iter().any(|pattern| {
                let result = self.matches_pattern(field_value, pattern, Some(event));
                trace!(
                    "  Pattern {:?} matches '{}': {}",
                    pattern,
                    field_value,
                    result
                );
                result
            });

            if !matches {
                trace!(
                    "Rule '{}': No pattern matched for field '{}'",
                    rule.rule.title,
                    field_name
                );
                return false;
            }
        }

        trace!("Rule '{}': ALL patterns matched!", rule.rule.title);
        true
    }

    /// Check if value matches pattern (value is Some)
    /// OPTIMIZED: Now accepts optional &NormalizedEvent for fieldref support
    pub(crate) fn matches_pattern(
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
    pub(crate) fn matches_pattern_null(&self, pattern: &FieldPattern) -> bool {
        matches!(pattern, FieldPattern::Null)
    }
}
