use super::*;

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
#[derive(Debug)]
pub struct CompiledRule {
    /// Original rule
    pub rule: SigmaRule,

    /// Compiled field patterns (legacy, kept for backward compatibility)
    #[allow(dead_code)]
    pub patterns: HashMap<String, Vec<FieldPattern>>,

    /// Compiled selections (new structure)
    pub selections: HashMap<String, Selection>,

    /// Normalized Sigma logsource
    pub logsource: LogSourceKey,

    /// Pre-transpiled condition expression (evalexpr syntax) when present
    pub transpiled_condition: Option<String>,

    /// Pre-compiled evalexpr condition tree for hot-path evaluation
    pub condition_tree: Option<Node>,
}
