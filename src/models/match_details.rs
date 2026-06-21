use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Debug verbosity for match details in alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchDebugLevel {
    Off,
    Summary,
    Full,
}

/// Match details attached to alerts when debug is enabled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchDetails {
    /// Human-readable explanation of why a rule matched
    pub summary: String,
    /// Sigma-specific match details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma: Option<SigmaMatchDetails>,
    /// YARA-specific match details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yara: Option<YaraMatchDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaMatchDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub selection_results: HashMap<String, bool>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matches: Vec<SigmaFieldMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub keyword_matches: Vec<SigmaKeywordMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaFieldMatch {
    pub selection: String,
    pub field: String,
    pub matcher: String,
    pub pattern_type: String,
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaKeywordMatch {
    pub selection: String,
    pub pattern_type: String,
    pub keyword: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchDetails {
    pub rules: Vec<YaraRuleMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleMatch {
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}
