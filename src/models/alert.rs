use super::{MatchDetails, NormalizedEvent};
use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !*value
}

/// Operator-facing metadata preserved from a Sigma rule.
///
/// This is intentionally a fixed subset rather than an arbitrary map. Sigma
/// custom attributes can contain large, backend-specific values; keeping the
/// alert contract explicit prevents an individual rule from making every
/// emitted alert unbounded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaRuleMetadata {
    /// Original valid Sigma level before mapping to [`AlertSeverity`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Sigma rule lifecycle status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Rule author as written in Sigma metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Rule tags, including ATT&CK classifications.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// References supplied by the rule author.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// True when metadata exceeded Rustinel's fixed alert-size limits.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

impl SigmaRuleMetadata {
    pub fn is_empty(&self) -> bool {
        self.level.is_none()
            && self.status.is_none()
            && self.author.is_none()
            && self.tags.is_empty()
            && self.references.is_empty()
            && !self.truncated
    }
}

/// Alert structure for detection hits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert severity
    pub severity: AlertSeverity,
    /// Rule name that triggered
    pub rule_name: String,
    /// Optional rule description / context (e.g., IOC comment)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_description: Option<String>,
    /// Rule ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Sigma-specific rule metadata. Absent for IOC and YARA alerts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma_metadata: Option<SigmaRuleMetadata>,
    /// Detection engine type
    pub engine: DetectionEngine,
    /// Associated event data
    pub event: NormalizedEvent,
    /// Optional debug match details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_details: Option<MatchDetails>,
}

/// Alert severity levels
///
/// The variants are ordered from least to most severe, so the derived `Ord`
/// ranks severities directly
/// (`Informational < Low < Medium < High < Critical`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Detection engine type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionEngine {
    Sigma,
    Yara,
    Ioc,
}

/// The artifact inspected for a YARA detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YaraScanSource {
    File,
    ProcessMemory,
}
