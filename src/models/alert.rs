use super::{MatchDetails, NormalizedEvent};
use serde::{Deserialize, Serialize};

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
    /// Detection engine type
    pub engine: DetectionEngine,
    /// Associated event data
    pub event: NormalizedEvent,
    /// Optional debug match details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_details: Option<MatchDetails>,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
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
