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
//! Rustinel's hot path). They materialize the selected compile-time field view
//! rather than walking serialized model fields. The same mapping therefore
//! drives direct reads, keyword search, and field enumeration.

use std::borrow::Cow;

use rsigma_eval::{Event, EventValue};
use serde_json::Value;

use crate::models::{CanonicalValue, FieldView, FieldViewName, NormalizedEvent};

/// Borrowed [`rsigma_eval::Event`] view over a [`NormalizedEvent`].
pub(crate) struct RsigmaEvent<'a> {
    event: &'a NormalizedEvent,
    view: FieldView<'a>,
    /// The event's availability contract, resolved once rather than on every
    /// field read: the candidate index and rule evaluation read hundreds.
    contract: Option<&'static crate::field_availability::EventFieldContract>,
}

impl<'a> RsigmaEvent<'a> {
    pub(crate) fn new(event: &'a NormalizedEvent) -> Self {
        Self::with_view(event, FieldViewName::DEFAULT)
    }

    pub(crate) fn with_view(event: &'a NormalizedEvent, view: FieldViewName) -> Self {
        Self {
            event,
            view: event.field_view(view),
            contract: crate::field_availability::event_contract(view, event),
        }
    }

    fn view_get(&self, name: &str) -> Option<CanonicalValue<'a>> {
        self.view.get_in_contract(self.contract, name)
    }

    /// The selected detection view as a flat JSON object.
    fn field_map(&self) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        for mapping in
            self.view.mappings().iter().filter(|mapping| {
                mapping.enumerate && !matches!(mapping.name, "timestamp" | "EventID")
            })
        {
            let Some(value) = self.view_get(mapping.name) else {
                continue;
            };
            let value = match value {
                CanonicalValue::String(value) => Value::String(value.to_string()),
                CanonicalValue::Bool(value) => Value::Bool(value),
                CanonicalValue::U64(value) => Value::Number(value.into()),
            };
            map.insert(mapping.name.to_string(), value);
        }
        for (name, value) in self.view.dynamic_fields() {
            if self.view_get(name).is_some() {
                map.insert(name.to_string(), Value::String(value.to_string()));
            }
        }
        map
    }

    fn visit_dns_alias(&self, visit: &mut dyn FnMut(&str)) {
        if self.event.platform == crate::sensor::Platform::Windows
            && self.event.category == crate::models::EventCategory::Dns
            && self.event.event_id != 22
        {
            visit("22");
        }
    }

    /// Event IDs exposed to Sigma for this normalized event.
    ///
    /// Windows DNS Client rules use the provider-native IDs (3006/3008),
    /// while category-based `dns_query` rules conventionally use Sysmon 22.
    /// Keeping the native ID on the recorded event and presenting 22 as an
    /// additional match value makes both rule families satisfiable without
    /// discarding source fidelity.
    fn event_id_value(&self) -> EventValue<'_> {
        let native = EventValue::Str(Cow::Borrowed(self.event.event_id_string.as_str()));
        if self.event.platform == crate::sensor::Platform::Windows
            && self.event.category == crate::models::EventCategory::Dns
            && self.event.event_id != 22
        {
            EventValue::Array(vec![native, EventValue::Str(Cow::Borrowed("22"))])
        } else {
            native
        }
    }
}

impl Event for RsigmaEvent<'_> {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        if path == "EventID" {
            return Some(self.event_id_value());
        }

        match self.view_get(path)? {
            CanonicalValue::String(value) => Some(EventValue::Str(Cow::Borrowed(value))),
            CanonicalValue::Bool(value) => Some(EventValue::Str(Cow::Borrowed(if value {
                "true"
            } else {
                "false"
            }))),
            CanonicalValue::U64(value) => Some(EventValue::Str(Cow::Owned(value.to_string()))),
        }
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        if !self.event.timestamp.is_empty() && pred(&self.event.timestamp) {
            return true;
        }
        if !self.event.event_id_string.is_empty() && pred(&self.event.event_id_string) {
            return true;
        }
        if self.event.platform == crate::sensor::Platform::Windows
            && self.event.category == crate::models::EventCategory::Dns
            && self.event.event_id != 22
            && pred("22")
        {
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
        if self.event.platform == crate::sensor::Platform::Windows
            && self.event.category == crate::models::EventCategory::Dns
            && self.event.event_id != 22
        {
            values.push(Cow::Borrowed("22"));
        }
        for (_key, value) in self.field_map() {
            if let Value::String(text) = value {
                values.push(Cow::Owned(text));
            }
        }
        values
    }

    /// Every string the keyword index could match, without materializing the
    /// JSON field map. A superset of [`Self::all_string_values`] is sound here:
    /// the candidate index may only over-approximate.
    fn visit_string_values(&self, visit: &mut dyn FnMut(&str)) {
        if !self.event.timestamp.is_empty() {
            visit(&self.event.timestamp);
        }
        if !self.event.event_id_string.is_empty() {
            visit(&self.event.event_id_string);
        }
        self.visit_dns_alias(visit);
        self.view.visit_mapped(self.contract, |mapping, value| {
            if mapping.enumerate && !matches!(mapping.name, "timestamp" | "EventID") {
                if let CanonicalValue::String(value) = value {
                    visit(value);
                }
            }
        });
        for (name, value) in self.view.dynamic_fields() {
            if self.view_get(name).is_some() {
                visit(value);
            }
        }
    }

    /// Every name [`Self::get_field`] can resolve on this event, so the
    /// candidate index probes only fields the event actually carries: the
    /// populated view fields, then any native payload names.
    fn visit_top_level_keys(&self, visit: &mut dyn FnMut(&str)) -> bool {
        visit("EventID");
        self.view
            .visit_mapped(self.contract, |mapping, _value| visit(mapping.name));
        for (name, _value) in self.view.dynamic_fields() {
            if self.view_get(name).is_some() {
                visit(name);
            }
        }
        true
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
    use crate::models::{
        EventCategory, EventFields, ImageLoadFields, NetworkConnectionFields, NormalizedEvent,
        ProcessCreationFields, SecurityAuditFields,
    };
    use crate::sensor::Platform;
    use std::collections::HashMap;

    fn generic_event(pairs: &[(&str, &str)]) -> NormalizedEvent {
        let mut map = HashMap::new();
        for (key, value) in pairs {
            map.insert((*key).to_string(), (*value).to_string());
        }
        NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            source_seq: None,
            ingest_seq: 0,
            platform: Platform::Linux,
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::Generic(map),
            process_name: None,
            provenance: Default::default(),
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

    /// A Windows image load whose producer populated `Never` fields.
    fn image_load_with_never_fields() -> NormalizedEvent {
        let mut event = generic_event(&[]);
        event.platform = Platform::Windows;
        event.provider = "etw".to_string();
        event.category = EventCategory::ImageLoad;
        event.event_id = 7;
        event.event_id_string = "7".to_string();
        event.opcode = 10;
        event.fields = EventFields::ImageLoad(ImageLoadFields {
            hashes: None,
            imphash: None,
            image_loaded: Some(r"C:\Windows\System32\kernel32.dll".to_string()),
            process_id: Some("42".to_string()),
            image: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            signed: Some("true".to_string()),
            signature: Some("Fake Signer".to_string()),
            user: None,
        });
        event
    }

    #[test]
    fn never_fields_are_absent_from_the_sigma_field_map() {
        let event = image_load_with_never_fields();
        let adapter = RsigmaEvent::new(&event);
        let fields = adapter.field_map();
        assert!(!fields.contains_key("Signed"));
        assert!(!fields.contains_key("Signature"));
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
    fn boolean_fields_are_not_keyword_values() {
        let mut event = generic_event(&[]);
        event.category = EventCategory::Network;
        event.fields = EventFields::NetworkConnection(NetworkConnectionFields {
            destination_ip: Some("198.51.100.10".to_string()),
            source_ip: None,
            destination_port: Some("443".to_string()),
            source_port: None,
            process_id: None,
            image: None,
            user: None,
            destination_hostname: None,
            protocol: Some("tcp".to_string()),
            initiated: Some(true),
        });
        let adapter = RsigmaEvent::new(&event);

        assert_eq!(
            adapter.get_field("Initiated"),
            Some(EventValue::Str(Cow::Borrowed("true")))
        );
        assert!(!adapter.any_string_value(&|value| value == "true"));
        assert!(adapter
            .all_string_values()
            .iter()
            .all(|value| value.as_ref() != "true"));
    }

    #[test]
    fn provenance_and_short_names_are_not_sigma_fields_or_keywords() {
        let mut event = generic_event(&[("Image", "/bin/sh")]);
        event.process_name = Some("native-short-name".into());
        event
            .provenance
            .mark("Image", crate::models::Fidelity::Truncated);
        let adapter = RsigmaEvent::new(&event);
        assert!(adapter.get_field("provenance").is_none());
        assert!(adapter.get_field("process_name").is_none());
        assert!(!adapter
            .any_string_value(&|value| value == "truncated" || value == "native-short-name"));
        assert!(!adapter
            .field_keys()
            .iter()
            .any(|key| key == "provenance" || key == "process_name"));
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
            hashes: None,
            imphash: None,
            container: Default::default(),
            linux_identity: Default::default(),
            cgroup_id: None,
            exec: Default::default(),
            parent_process_id_derived: false,
            windows: Default::default(),
            image: Some("/usr/bin/curl".to_string()),
            image_source: None,
            image_truncated: Some(true),
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: Some("curl http://example.test".to_string()),
            process_id: Some("1234".to_string()),
            process_start_time: Some(123_456),
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            parent_user: None,
            current_directory: None,
            integrity_level: None,
            user: None,
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
        assert_eq!(
            adapter.get_field("ImageTruncated"),
            Some(EventValue::Str(Cow::Borrowed("true")))
        );
        assert_eq!(
            adapter.get_field("ProcessStartTime"),
            Some(EventValue::Str(Cow::Owned("123456".to_string())))
        );
        let keys = adapter.field_keys();
        assert!(keys.iter().any(|key| key.as_ref() == "Image"));
        assert!(keys.iter().any(|key| key.as_ref() == "ImageTruncated"));
        assert!(keys.iter().any(|key| key.as_ref() == "CommandLine"));
        // ProcessStartTime is numeric, so it is not a string value.
        let values = adapter.all_string_values();
        assert!(values.iter().any(|value| value.as_ref() == "/usr/bin/curl"));
        assert!(values.iter().any(|value| value.contains("example.test")));
        assert!(values.iter().all(|value| value.as_ref() != "true"));
    }

    #[test]
    fn security_audit_fields_serialize_flat_like_the_typed_variants() {
        // The Security payload is a map rather than a struct of named options.
        // The cold paths here read the fields through serde, so a nested
        // representation would produce `fields.ObjectName`-style keys that no
        // rule field name could ever match.
        let mut fields = SecurityAuditFields::default();
        fields.insert("ObjectName", r"C:\Windows\NTDS\ntds.dit");
        fields.insert("SubjectLogonId", "0x3e4");
        fields.insert("ProcessName", "-");
        fields.insert("EmptyField", "");

        let mut event = generic_event(&[]);
        event.category = EventCategory::Security;
        event.fields = EventFields::SecurityAudit(fields);
        let adapter = RsigmaEvent::new(&event);

        let keys = adapter.field_keys();
        assert!(keys.iter().any(|key| key.as_ref() == "ObjectName"));
        assert!(keys.iter().any(|key| key.as_ref() == "SubjectLogonId"));
        assert!(keys.iter().any(|key| key.as_ref() == "ProcessName"));
        assert!(keys.iter().all(|key| key.as_ref() != "EmptyField"));
        assert_eq!(
            adapter.get_field("ProcessName"),
            Some(EventValue::Str(Cow::Borrowed("-")))
        );
        assert_eq!(adapter.get_field("EmptyField"), None);
        assert!(adapter.any_string_value(&|value| value.ends_with("ntds.dit")));
    }

    /// One representative of every event shape in real Windows and Linux
    /// captures, plus shapes the captures cannot produce.
    fn event_shapes() -> Vec<NormalizedEvent> {
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/field_views");
        let mut events = Vec::new();
        for name in ["windows.ndjson", "linux.ndjson"] {
            let text = std::fs::read_to_string(fixtures.join(name)).expect("read fixture");
            for line in text.lines() {
                events.push(serde_json::from_str(line).expect("fixture event parses"));
            }
        }
        assert!(events.len() >= 31, "fixture shapes went missing");
        events.push(image_load_with_never_fields());
        events.push(generic_event(&[("Image", "/bin/sh"), ("Custom", "value")]));
        events
    }

    /// Every name a rule could select on: the view vocabulary, the event's
    /// native names, and names no event carries.
    fn candidate_names(event: &NormalizedEvent) -> Vec<String> {
        let view = event.field_view(FieldViewName::DEFAULT);
        let mut names: Vec<String> = view
            .mappings()
            .iter()
            .map(|mapping| mapping.name.to_string())
            .collect();
        names.extend(view.dynamic_fields().map(|(name, _)| name.to_string()));
        names.extend(["EventID", "Missing", "timestamp"].map(String::from));
        names
    }

    #[test]
    fn contract_resolved_once_reads_like_a_per_field_lookup() {
        for event in event_shapes() {
            let adapter = RsigmaEvent::new(&event);
            let view = event.field_view(FieldViewName::DEFAULT);
            for name in candidate_names(&event) {
                let never = matches!(
                    crate::field_availability::availability_for_view(
                        FieldViewName::DEFAULT,
                        &event,
                        &name
                    ),
                    Some(crate::field_availability::Availability::Never(_))
                );
                let expected = if never {
                    None
                } else {
                    view.get_unchecked(&name)
                };
                assert_eq!(adapter.view_get(&name), expected, "{name} on {event:?}");
                assert_eq!(view.get(&name), expected, "{name} on {event:?}");
            }
        }
    }

    #[test]
    fn top_level_keys_are_exactly_the_resolvable_names() {
        for event in event_shapes() {
            let adapter = RsigmaEvent::new(&event);
            let mut visited = std::collections::BTreeSet::new();
            assert!(adapter.visit_top_level_keys(&mut |key| {
                visited.insert(key.to_string());
            }));
            let resolvable: std::collections::BTreeSet<String> = candidate_names(&event)
                .into_iter()
                .filter(|name| adapter.get_field(name).is_some())
                .collect();
            assert_eq!(visited, resolvable, "{event:?}");
        }
    }

    #[test]
    fn visited_strings_cover_every_keyword_value() {
        for event in event_shapes() {
            let adapter = RsigmaEvent::new(&event);
            let mut visited = std::collections::BTreeSet::new();
            adapter.visit_string_values(&mut |value| {
                visited.insert(value.to_string());
            });
            for value in adapter.all_string_values() {
                assert!(visited.contains(value.as_ref()), "{value} on {event:?}");
            }
        }
    }

    /// The adapter with RSigma's default visitors, which probe every indexed
    /// field and walk `all_string_values`.
    struct FullProbe<'a>(RsigmaEvent<'a>);

    impl Event for FullProbe<'_> {
        fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
            self.0.get_field(path)
        }

        fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
            self.0.any_string_value(pred)
        }

        fn all_string_values(&self) -> Vec<Cow<'_, str>> {
            self.0.all_string_values()
        }

        fn to_json(&self) -> Value {
            self.0.to_json()
        }
    }

    /// Rules built from the shapes' own values, so the candidate index holds
    /// field, keyword, and event ID witnesses that each hit some event.
    fn rules_from_shapes(events: &[NormalizedEvent]) -> String {
        let mut rules = Vec::new();
        for event in events {
            let adapter = RsigmaEvent::new(event);
            for name in candidate_names(event) {
                let Some(EventValue::Str(value)) = adapter.get_field(&name) else {
                    continue;
                };
                let Some(token) = value
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .find(|token| token.len() >= 4)
                else {
                    continue;
                };
                let index = rules.len();
                rules.push(format!(
                    "title: field {index}\ndetection:\n  selection:\n    {name}|contains: '{token}'\n  condition: selection\n"
                ));
                rules.push(format!(
                    "title: keyword {index}\ndetection:\n  keywords:\n    - '{token}'\n  condition: keywords\n"
                ));
            }
            rules.push(format!(
                "title: event id {}\ndetection:\n  selection:\n    EventID: {}\n  condition: selection\n",
                event.event_id, event.event_id
            ));
        }
        rules.join("---\n")
    }

    #[test]
    fn candidate_index_selects_the_same_rules_as_a_full_probe() {
        let events = event_shapes();
        let collection =
            rsigma_parser::parse_sigma_yaml(&rules_from_shapes(&events)).expect("rules parse");
        let mut engine = rsigma_eval::Engine::new();
        engine.add_collection(&collection).expect("rules compile");
        let titles = |results: Vec<rsigma_eval::EvaluationResult>| {
            let mut titles: Vec<String> = results
                .into_iter()
                .map(|result| result.header.rule_title)
                .collect();
            titles.sort();
            titles
        };

        let mut matched = 0;
        for event in &events {
            let fast = titles(engine.evaluate(&RsigmaEvent::new(event)));
            let full = titles(engine.evaluate(&FullProbe(RsigmaEvent::new(event))));
            assert_eq!(fast, full, "{event:?}");
            matched += fast.len();
        }
        assert!(
            matched > events.len(),
            "the rules must actually select events"
        );
    }
}
