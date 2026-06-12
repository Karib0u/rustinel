//! Data models module
//!
//! Defines core data structures like NormalizedEvent and Alert.

pub mod ecs;

mod alert;
mod event;
mod fields;
mod match_details;

pub use alert::*;
pub use event::*;
pub use fields::*;
pub use match_details::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensor::Platform;
    use std::collections::HashMap;

    #[test]
    fn test_event_category() {
        assert_eq!(EventCategory::Process, EventCategory::Process);
    }

    #[test]
    fn test_alert_serialization() {
        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::Generic(HashMap::new()),
            process_context: None,
        };
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "test_rule".to_string(),
            rule_description: None,
            rule_id: None,
            engine: DetectionEngine::Sigma,
            event,
            match_details: None,
        };
        let _json = serde_json::to_string(&alert).unwrap();
    }
}
