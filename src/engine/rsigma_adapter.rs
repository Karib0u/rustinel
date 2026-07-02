//! Adapter exposing a [`NormalizedEvent`] to the RSigma evaluator.
//!
//! [`RsigmaEvent`] implements [`rsigma_eval::Event`] over a borrowed
//! [`NormalizedEvent`]. Field lookups are the detection hot path and stay
//! zero-copy by delegating to [`NormalizedEvent::get_field`], wrapping the
//! borrowed `&str` in `EventValue::Str(Cow::Borrowed(..))` with no allocation
//! or JSON conversion.
//!
//! The keyword and field-enumeration methods are cold paths (keyword-only
//! rules and the daemon field-observability surface, neither of which is on
//! Rustinel's hot path). They materialize the event's fields with serde rather
//! than the default `to_json`-based walk: `EventFields` is
//! `#[serde(untagged)]`, so the active variant serializes directly as a flat
//! object keyed by the Sigma names (`Image`, `CommandLine`, ...) that rules
//! reference. Driving these off serde keeps them in lockstep with the
//! `#[serde(rename = ...)]` attributes on the field structs instead of
//! duplicating that key list here, and avoids the default implementation's
//! nested `fields.Image`-style dotted paths that would never match a flat rule
//! field name.

use std::borrow::Cow;

use rsigma_eval::{Event, EventValue};
use serde_json::Value;

use crate::models::NormalizedEvent;

/// Borrowed [`rsigma_eval::Event`] view over a [`NormalizedEvent`].
// Constructed by the RSigma-backed engine; the evaluation wiring lands in a
// later commit of this change, so allow it to be unused until then.
#[allow(dead_code)]
pub(crate) struct RsigmaEvent<'a> {
    event: &'a NormalizedEvent,
}

impl<'a> RsigmaEvent<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(event: &'a NormalizedEvent) -> Self {
        Self { event }
    }

    /// The event's detection fields as a flat, Sigma-cased JSON object.
    ///
    /// Returns an empty map for the (unreachable in practice) case where the
    /// fields do not serialize to a JSON object.
    fn field_map(&self) -> serde_json::Map<String, Value> {
        match serde_json::to_value(&self.event.fields) {
            Ok(Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }
}

impl Event for RsigmaEvent<'_> {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        self.event
            .get_field(path)
            .map(|value| EventValue::Str(Cow::Borrowed(value)))
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        if !self.event.timestamp.is_empty() && pred(&self.event.timestamp) {
            return true;
        }
        if !self.event.event_id_string.is_empty() && pred(&self.event.event_id_string) {
            return true;
        }
        self.field_map()
            .values()
            .filter_map(Value::as_str)
            .any(pred)
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        let mut values: Vec<Cow<'_, str>> = Vec::new();
        if !self.event.timestamp.is_empty() {
            values.push(Cow::Borrowed(self.event.timestamp.as_str()));
        }
        if !self.event.event_id_string.is_empty() {
            values.push(Cow::Borrowed(self.event.event_id_string.as_str()));
        }
        for (_key, value) in self.field_map() {
            if let Value::String(text) = value {
                values.push(Cow::Owned(text));
            }
        }
        values
    }

    fn field_keys(&self) -> Vec<Cow<'_, str>> {
        let mut keys: Vec<Cow<'_, str>> =
            vec![Cow::Borrowed("timestamp"), Cow::Borrowed("EventID")];
        keys.extend(
            self.field_map()
                .into_iter()
                .map(|(key, _value)| Cow::Owned(key)),
        );
        keys
    }

    fn to_json(&self) -> Value {
        serde_json::to_value(self.event).unwrap_or(Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventCategory, EventFields, NormalizedEvent, ProcessCreationFields};
    use crate::sensor::Platform;
    use std::collections::HashMap;

    fn generic_event(pairs: &[(&str, &str)]) -> NormalizedEvent {
        let mut map = HashMap::new();
        for (key, value) in pairs {
            map.insert((*key).to_string(), (*value).to_string());
        }
        NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::Generic(map),
            process_context: None,
        }
    }

    #[test]
    fn get_field_returns_borrowed_string() {
        let event = generic_event(&[("Image", "/usr/bin/curl")]);
        let adapter = RsigmaEvent::new(&event);
        assert_eq!(
            adapter.get_field("Image"),
            Some(EventValue::Str(Cow::Borrowed("/usr/bin/curl")))
        );
        assert_eq!(adapter.get_field("Missing"), None);
    }

    #[test]
    fn any_string_value_matches_substring() {
        let event = generic_event(&[("CommandLine", "curl http://example.test")]);
        let adapter = RsigmaEvent::new(&event);
        assert!(adapter.any_string_value(&|value| value.contains("example.test")));
        assert!(!adapter.any_string_value(&|value| value.contains("nonexistent-token")));
    }

    #[test]
    fn all_string_values_include_fields_and_metadata() {
        let event = generic_event(&[("Image", "/bin/sh")]);
        let adapter = RsigmaEvent::new(&event);
        let values = adapter.all_string_values();
        assert!(values.iter().any(|value| value.as_ref() == "/bin/sh"));
        assert!(values
            .iter()
            .any(|value| value.as_ref() == "2026-01-01T00:00:00Z"));
        assert!(values.iter().any(|value| value.as_ref() == "1"));
    }

    #[test]
    fn field_keys_list_flat_sigma_names() {
        let event = generic_event(&[("Image", "/bin/sh"), ("CommandLine", "sh -c id")]);
        let adapter = RsigmaEvent::new(&event);
        let keys = adapter.field_keys();
        assert!(keys.iter().any(|key| key.as_ref() == "Image"));
        assert!(keys.iter().any(|key| key.as_ref() == "CommandLine"));
        assert!(keys.iter().any(|key| key.as_ref() == "timestamp"));
        assert!(keys.iter().any(|key| key.as_ref() == "EventID"));
    }

    #[test]
    fn typed_process_fields_expose_sigma_names() {
        let fields = ProcessCreationFields {
            image: Some("/usr/bin/curl".to_string()),
            original_file_name: None,
            product: None,
            description: None,
            target_image: None,
            command_line: Some("curl http://example.test".to_string()),
            process_id: Some("1234".to_string()),
            process_start_time: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            logon_id: None,
            logon_guid: None,
        };
        let mut event = generic_event(&[]);
        event.fields = EventFields::ProcessCreation(fields);
        let adapter = RsigmaEvent::new(&event);

        assert_eq!(
            adapter
                .get_field("CommandLine")
                .and_then(|value| value.as_str().map(Cow::into_owned)),
            Some("curl http://example.test".to_string())
        );
        let keys = adapter.field_keys();
        assert!(keys.iter().any(|key| key.as_ref() == "Image"));
        assert!(keys.iter().any(|key| key.as_ref() == "CommandLine"));
        // ProcessStartTime is numeric, so it is not a string value.
        let values = adapter.all_string_values();
        assert!(values.iter().any(|value| value.as_ref() == "/usr/bin/curl"));
        assert!(values.iter().any(|value| value.contains("example.test")));
    }
}
