use super::EventFields;
use crate::sensor::Platform;
use serde::{Deserialize, Serialize};

/// Normalized event structure compatible with Sigma/Sysmon format
///
/// Deserialization is hand-written rather than derived so a recorded event comes
/// back exactly as it was written: [`EventFields`] is dispatched on the recorded
/// category instead of guessed at structurally, and the derived
/// [`event_id_string`](Self::event_id_string) cache is rebuilt from `event_id`.
/// See [`EventFields::from_recorded`].
#[derive(Debug, Clone, Serialize)]
pub struct NormalizedEvent {
    /// Event timestamp
    pub timestamp: String,
    /// Sensor platform that produced the underlying event.
    pub platform: Platform,
    /// Sensor provider name (for example `etw` or `ebpf`).
    pub provider: String,
    /// Event category (Process, Network, File, Registry, DNS, ImageLoad)
    pub category: EventCategory,
    /// Sensor-supplied compatibility event ID used by downstream detectors/output.
    pub event_id: u16,
    /// Cached string representation of event_id for zero-copy flatten()
    #[serde(skip)]
    pub event_id_string: String,
    /// Sensor-supplied action code preserved for downstream compatibility logic.
    pub opcode: u8,
    /// Event-specific fields
    pub fields: EventFields,
    /// Optional process context for non-process events (alert enrichment only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_context: Option<ProcessContext>,
}

impl<'de> Deserialize<'de> for NormalizedEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// The event exactly as it appears on the wire, with the field payload
        /// left untyped until the category has been read.
        #[derive(Deserialize)]
        struct RecordedEvent {
            timestamp: String,
            platform: Platform,
            provider: String,
            category: EventCategory,
            event_id: u16,
            opcode: u8,
            fields: serde_json::Value,
            #[serde(default)]
            process_context: Option<ProcessContext>,
        }

        let recorded = RecordedEvent::deserialize(deserializer)?;
        let fields = EventFields::from_recorded(recorded.category, recorded.fields)
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            timestamp: recorded.timestamp,
            platform: recorded.platform,
            provider: recorded.provider,
            category: recorded.category,
            event_id: recorded.event_id,
            // Rebuilt rather than read: the cache is skipped on the wire, and
            // `get_field("EventID")` reads it directly.
            event_id_string: recorded.event_id.to_string(),
            opcode: recorded.opcode,
            fields,
            process_context: recorded.process_context,
        })
    }
}

/// Cached process context used to enrich alerts for non-process events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "CommandLine", skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "ProcessStartTime", skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<u64>,

    #[serde(rename = "ParentProcessId", skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<String>,

    #[serde(rename = "ParentImage", skip_serializing_if = "Option::is_none")]
    pub parent_image: Option<String>,

    #[serde(rename = "ParentCommandLine", skip_serializing_if = "Option::is_none")]
    pub parent_command_line: Option<String>,

    #[serde(rename = "OriginalFileName", skip_serializing_if = "Option::is_none")]
    pub original_file_name: Option<String>,

    #[serde(rename = "Product", skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,

    #[serde(rename = "Description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "Company", skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,

    #[serde(rename = "FileVersion", skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,

    #[serde(rename = "CurrentDirectory", skip_serializing_if = "Option::is_none")]
    pub current_directory: Option<String>,

    #[serde(rename = "IntegrityLevel", skip_serializing_if = "Option::is_none")]
    pub integrity_level: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl NormalizedEvent {
    /// Zero-allocation field accessor
    /// Returns reference to string without creating HashMap or cloning
    /// PERFORMANCE: Replaces flatten() to eliminate heap allocations
    pub fn get_field(&self, key: &str) -> Option<&str> {
        // Fast path for common fields
        match key {
            "timestamp" => return Some(&self.timestamp),
            "EventID" => return Some(&self.event_id_string),
            _ => {}
        }

        match &self.fields {
            EventFields::ProcessCreation(f) => match key {
                "Image" => f.image.as_deref(),
                "OriginalFileName" => f.original_file_name.as_deref(),
                "Product" => f.product.as_deref(),
                "Description" => f.description.as_deref(),
                "Company" => f.company.as_deref(),
                "FileVersion" => f.file_version.as_deref(),
                "CommandLine" => f.command_line.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "ParentProcessId" => f.parent_process_id.as_deref(),
                "ParentImage" => f.parent_image.as_deref(),
                "ParentCommandLine" => f.parent_command_line.as_deref(),
                "User" => f.user.as_deref(),
                "IntegrityLevel" => f.integrity_level.as_deref(),
                "CurrentDirectory" => f.current_directory.as_deref(),
                "TargetImage" => f.target_image.as_deref(),
                _ => None,
            },
            EventFields::FileEvent(f) => match key {
                "SourceFilename" => f.source_filename.as_deref(),
                "TargetFilename" => f.target_filename.as_deref(),
                "Image" => f.image.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "User" => f.user.as_deref(),
                "CreationUtcTime" => f.creation_utc_time.as_deref(),
                "PreviousCreationUtcTime" => f.previous_creation_utc_time.as_deref(),
                "PathTruncated" => f.path_truncated.as_deref(),
                _ => None,
            },
            EventFields::NetworkConnection(f) => match key {
                "DestinationIp" => f.destination_ip.as_deref(),
                "SourceIp" => f.source_ip.as_deref(),
                "DestinationPort" => f.destination_port.as_deref(),
                "SourcePort" => f.source_port.as_deref(),
                "Image" => f.image.as_deref(),
                "User" => f.user.as_deref(),
                "DestinationHostname" => f.destination_hostname.as_deref(),
                "Protocol" => f.protocol.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                // Rules spell `Initiated` as the string `true`/`false`, which
                // is what Sysmon's own XML renders. The model keeps a boolean,
                // so the two spellings are borrowed `&'static str` rather than
                // formatted, which is what this accessor's no-allocation
                // contract requires.
                "Initiated" => f.initiated.map(|v| if v { "true" } else { "false" }),
                _ => None,
            },
            EventFields::RegistryEvent(f) => match key {
                "TargetObject" => f.target_object.as_deref(),
                "Details" => f.details.as_deref(),
                "Image" => f.image.as_deref(),
                "EventType" => f.event_type.as_deref(),
                "NewName" => f.new_name.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "User" => f.user.as_deref(),
                _ => None,
            },
            EventFields::DnsQuery(f) => match key {
                "query" => f.query_name.as_deref(),
                "answer" => f.query_results.as_deref(),
                "record_type" => f.record_type.as_deref(),
                "QueryName" => f.query_name.as_deref(),
                "QueryResults" => f.query_results.as_deref(),
                "RecordType" => f.record_type.as_deref(),
                "QueryStatus" => f.query_status.as_deref(),
                "Image" => f.image.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                _ => None,
            },
            EventFields::ImageLoad(f) => match key {
                "ImageLoaded" => f.image_loaded.as_deref(),
                "Image" => f.image.as_deref(),
                "OriginalFileName" => f.original_file_name.as_deref(),
                "Product" => f.product.as_deref(),
                "Description" => f.description.as_deref(),
                "Company" => f.company.as_deref(),
                "FileVersion" => f.file_version.as_deref(),
                "Signed" => f.signed.as_deref(),
                "Signature" => f.signature.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "User" => f.user.as_deref(),
                _ => None,
            },
            EventFields::PowerShellScript(f) => match key {
                "ScriptBlockText" => f.script_block_text.as_deref(),
                "ScriptBlockId" => f.script_block_id.as_deref(),
                "Path" => f.path.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "Image" => f.image.as_deref(),
                "User" => f.user.as_deref(),
                _ => None,
            },
            EventFields::PowerShellModule(f) => match key {
                "ContextInfo" => f.context_info.as_deref(),
                "Payload" => f.payload.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "Image" => f.image.as_deref(),
                "User" => f.user.as_deref(),
                _ => None,
            },
            EventFields::RemoteThread(f) => match key {
                "SourceProcessId" => f.source_process_id.as_deref(),
                "SourceImage" => f.source_image.as_deref(),
                "TargetProcessId" => f.target_process_id.as_deref(),
                "TargetImage" => f.target_image.as_deref(),
                "StartAddress" => f.start_address.as_deref(),
                "StartModule" => f.start_module.as_deref(),
                "StartFunction" => f.start_function.as_deref(),
                "User" => f.user.as_deref(),
                _ => None,
            },
            EventFields::WmiEvent(f) => match key {
                "Operation" => f.operation.as_deref(),
                "User" => f.user.as_deref(),
                "Query" => f.query.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "Image" => f.image.as_deref(),
                "EventNamespace" => f.event_namespace.as_deref(),
                "EventType" => f.event_type.as_deref(),
                "DestinationHostname" => f.destination_hostname.as_deref(),
                _ => None,
            },
            EventFields::ServiceCreation(f) => match key {
                "Provider_Name" => f.provider_name.as_deref(),
                "ServiceName" => f.service_name.as_deref(),
                // `ImagePath` is what the 7045 record calls the executable and
                // what every SigmaHQ service rule selects on; `ServiceFileName`
                // is the Sysmon-style name the model stores it under. The alias
                // lives here rather than in the field struct so the value is
                // carried, serialized, and keyword-searched exactly once.
                "ServiceFileName" | "ImagePath" => f.service_file_name.as_deref(),
                "ServiceType" => f.service_type.as_deref(),
                "StartType" => f.start_type.as_deref(),
                "AccountName" => f.account_name.as_deref(),
                "User" => f.user.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "Image" => f.image.as_deref(),
                _ => None,
            },
            EventFields::TaskCreation(f) => match key {
                "TaskName" => f.task_name.as_deref(),
                "TaskContent" => f.task_content.as_deref(),
                "UserName" => f.user_name.as_deref(),
                "User" => f.user.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "Image" => f.image.as_deref(),
                _ => None,
            },
            EventFields::SecurityAudit(f) => f.get(key),
            EventFields::Generic(map) => map.get(key).map(|s| s.as_str()),
        }
    }
}

/// Event categories matching ETW providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventCategory {
    Process,
    Network,
    File,
    Registry,
    Dns,
    ImageLoad,
    Scripting,
    PowerShellModule,
    Wmi,
    Service,
    Task,
    Security,
}

#[cfg(test)]
mod round_trip_tests {
    //! A recorded event must come back exactly as it went out. Replay is only
    //! as trustworthy as this: an event that changes category or loses a field
    //! on the way back in would be evaluated against different rules than the
    //! ones live protection would have used.

    use super::*;
    use crate::models::{
        FileEventFields, NetworkConnectionFields, ProcessCreationFields, ServiceCreationFields,
    };

    fn round_trip(event: &NormalizedEvent) -> NormalizedEvent {
        let line = serde_json::to_string(event).expect("event serializes");
        serde_json::from_str(&line).expect("event deserializes")
    }

    fn file_event() -> NormalizedEvent {
        NormalizedEvent {
            timestamp: "2026-08-16T09:41:03.402Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::File,
            event_id: 11,
            event_id_string: "11".to_string(),
            opcode: 64,
            fields: EventFields::FileEvent(FileEventFields {
                source_filename: None,
                target_filename: Some(r"C:\Temp\rustinel.txt".to_string()),
                process_id: Some("6120".to_string()),
                image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: None,
                path_truncated: None,
            }),
            process_context: None,
        }
    }

    #[test]
    fn a_minimal_file_event_does_not_come_back_as_a_process_event() {
        // `{"TargetFilename":..,"ProcessId":..,"Image":..}` is structurally a
        // valid process event too, because every field of every variant is
        // optional. Only the recorded category tells the two apart.
        let event = round_trip(&file_event());

        assert!(
            matches!(event.fields, EventFields::FileEvent(_)),
            "a file event must stay a file event: {:?}",
            event.fields
        );
        assert_eq!(event.category, EventCategory::File);
        assert_eq!(
            event.get_field("TargetFilename"),
            Some(r"C:\Temp\rustinel.txt"),
            "reading it back as a process event would silently drop this field"
        );
    }

    #[test]
    fn the_event_id_string_cache_is_rebuilt_on_the_way_back_in() {
        // The cache is skipped on the wire; a derived `Default` would leave it
        // empty and every `EventID` rule would stop matching.
        let event = round_trip(&file_event());

        assert_eq!(event.event_id_string, "11");
        assert_eq!(event.get_field("EventID"), Some("11"));
    }

    #[test]
    fn every_recorded_field_survives_the_round_trip() {
        let mut original = NormalizedEvent {
            timestamp: "2026-08-16T09:41:02.884Z".to_string(),
            platform: Platform::MacOS,
            provider: "esf".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("/bin/zsh".to_string()),
                original_file_name: Some("zsh".to_string()),
                product: Some("shell".to_string()),
                description: Some("Z shell".to_string()),
                company: None,
                file_version: None,
                target_image: None,
                command_line: Some("zsh -c whoami".to_string()),
                process_id: Some("7448".to_string()),
                process_start_time: Some(123_456_789),
                parent_process_id: Some("6120".to_string()),
                parent_image: Some("/usr/bin/login".to_string()),
                parent_command_line: Some("login -pf analyst".to_string()),
                current_directory: Some("/Users/analyst".to_string()),
                integrity_level: None,
                user: Some("analyst".to_string()),
            }),
            process_context: None,
        };
        original.event_id_string = original.event_id.to_string();

        let event = round_trip(&original);

        assert_eq!(event.timestamp, original.timestamp);
        assert_eq!(event.platform, Platform::MacOS);
        assert_eq!(event.provider, "esf");
        assert_eq!(event.category, EventCategory::Process);
        assert_eq!(event.event_id, 1);
        assert_eq!(event.opcode, 1);
        assert_eq!(
            serde_json::to_value(&event.fields).expect("replayed fields serialize"),
            serde_json::to_value(&original.fields).expect("original fields serialize"),
            "the same fields and values must survive the round trip"
        );
    }

    #[test]
    fn each_category_comes_back_as_the_variant_it_was_written_from() {
        // Every category a sensor can produce, with the smallest payload that
        // still carries a field, which is where structural inference is least
        // able to tell the variants apart.
        /// A category, a field it models, and the variant it must come back as.
        type Case = (EventCategory, &'static str, fn(&EventFields) -> bool);

        let cases: &[Case] = &[
            (EventCategory::Process, "Image", |f| {
                matches!(f, EventFields::ProcessCreation(_))
            }),
            (EventCategory::Network, "Image", |f| {
                matches!(f, EventFields::NetworkConnection(_))
            }),
            (EventCategory::File, "Image", |f| {
                matches!(f, EventFields::FileEvent(_))
            }),
            (EventCategory::Registry, "Image", |f| {
                matches!(f, EventFields::RegistryEvent(_))
            }),
            (EventCategory::Dns, "Image", |f| {
                matches!(f, EventFields::DnsQuery(_))
            }),
            (EventCategory::ImageLoad, "Image", |f| {
                matches!(f, EventFields::ImageLoad(_))
            }),
            (EventCategory::Scripting, "Image", |f| {
                matches!(f, EventFields::PowerShellScript(_))
            }),
            (EventCategory::PowerShellModule, "Image", |f| {
                matches!(f, EventFields::PowerShellModule(_))
            }),
            (EventCategory::Wmi, "Image", |f| {
                matches!(f, EventFields::WmiEvent(_))
            }),
            (EventCategory::Service, "Image", |f| {
                matches!(f, EventFields::ServiceCreation(_))
            }),
            (EventCategory::Task, "Image", |f| {
                matches!(f, EventFields::TaskCreation(_))
            }),
            (EventCategory::Security, "ObjectName", |f| {
                matches!(f, EventFields::SecurityAudit(_))
            }),
        ];

        for (category, field, is_expected_variant) in cases {
            let line = serde_json::json!({
                "timestamp": "2026-08-16T09:41:02.884Z",
                "platform": "linux",
                "provider": "ebpf",
                "category": category,
                "event_id": 1,
                "opcode": 1,
                "fields": { *field: "/bin/zsh" },
            })
            .to_string();

            let event: NormalizedEvent =
                serde_json::from_str(&line).expect("recorded event deserializes");

            assert!(
                is_expected_variant(&event.fields),
                "{category:?} came back as {:?}",
                event.fields
            );
            assert_eq!(event.get_field(field), Some("/bin/zsh"));
        }
    }

    fn network_event(initiated: Option<bool>) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: "2026-08-16T09:41:05.001Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Network,
            event_id: 3,
            event_id_string: "3".to_string(),
            opcode: 12,
            fields: EventFields::NetworkConnection(NetworkConnectionFields {
                destination_ip: Some("198.51.100.10".to_string()),
                source_ip: Some("10.0.0.5".to_string()),
                destination_port: Some("443".to_string()),
                source_port: Some("51324".to_string()),
                process_id: Some("4188".to_string()),
                image: Some(r"C:\Windows\System32\curl.exe".to_string()),
                user: None,
                destination_hostname: None,
                protocol: Some("tcp".to_string()),
                initiated,
            }),
            process_context: None,
        }
    }

    #[test]
    fn initiated_reads_back_as_the_string_a_sigma_rule_writes() {
        // Rules spell it `Initiated: 'true'`, so the accessor has to hand the
        // matcher a string even though the model holds a boolean.
        assert_eq!(
            network_event(Some(true)).get_field("Initiated"),
            Some("true")
        );
        assert_eq!(
            network_event(Some(false)).get_field("Initiated"),
            Some("false")
        );
        assert_eq!(network_event(None).get_field("Initiated"), None);
    }

    #[test]
    fn an_unknown_direction_stays_absent_rather_than_becoming_false() {
        // The distinction that matters: a rule asking for `Initiated: 'false'`
        // must not match an event whose sensor could not tell the direction.
        let event = round_trip(&network_event(None));
        assert_eq!(event.get_field("Initiated"), None);

        let line = serde_json::to_string(&network_event(None)).expect("event serializes");
        assert!(
            !line.contains("Initiated"),
            "an absent direction must not be written at all: {line}"
        );
    }

    #[test]
    fn initiated_survives_recording_in_both_directions() {
        for initiated in [true, false] {
            let event = network_event(Some(initiated));
            let line = serde_json::to_string(&event).expect("event serializes");
            // A JSON boolean, not the string the accessor renders: the
            // recording is the model, and ECS consumers read it as a boolean.
            assert!(
                line.contains(&format!(r#""Initiated":{initiated}"#)),
                "recorded as a boolean: {line}"
            );

            let replayed = round_trip(&event);
            match &replayed.fields {
                EventFields::NetworkConnection(f) => assert_eq!(f.initiated, Some(initiated)),
                other => panic!("network event came back as {other:?}"),
            }
        }
    }

    #[test]
    fn a_recorded_service_event_keeps_both_providers_and_the_image_path_alias() {
        // `Provider_Name` is stored; `ImagePath` is derived from the stored
        // `ServiceFileName`. A replay that lost either would silently stop
        // matching every `service: system` rule.
        let event = NormalizedEvent {
            timestamp: "2026-08-25T12:34:56.123Z".to_string(),
            platform: Platform::Windows,
            provider: "windows_event_log".to_string(),
            category: EventCategory::Service,
            event_id: 7045,
            event_id_string: "7045".to_string(),
            opcode: 0,
            fields: EventFields::ServiceCreation(ServiceCreationFields {
                provider_name: Some("Service Control Manager".to_string()),
                service_name: Some("RustinelIssue317".to_string()),
                service_file_name: Some(r"C:\Temp\evil.exe".to_string()),
                service_type: None,
                start_type: None,
                account_name: None,
                user: None,
                process_id: None,
                image: None,
            }),
            process_context: None,
        };

        let event = round_trip(&event);

        assert_eq!(
            event.provider, "windows_event_log",
            "the sensor provider must not be overwritten by the Windows one"
        );
        assert_eq!(
            event.get_field("Provider_Name"),
            Some("Service Control Manager")
        );
        assert_eq!(event.get_field("ImagePath"), Some(r"C:\Temp\evil.exe"));
        assert_eq!(
            event.get_field("ServiceFileName"),
            event.get_field("ImagePath"),
            "the alias must resolve to the same value it aliases"
        );
        // The alias is a read path, not a second stored field.
        let fields = serde_json::to_value(&event.fields).expect("service fields serialize");
        assert_eq!(
            fields
                .get("Provider_Name")
                .and_then(serde_json::Value::as_str),
            Some("Service Control Manager")
        );
        assert!(fields.get("ImagePath").is_none());
    }

    #[test]
    fn absent_process_identity_fields_are_not_synthesized() {
        let event = NormalizedEvent {
            timestamp: "2026-08-16T12:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                command_line: None,
                process_id: None,
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
            }),
            process_context: None,
        };

        let fields = serde_json::to_value(&event.fields).expect("process fields serialize");
        for field in ["ProcessId", "ParentProcessId", "User", "TargetImage"] {
            assert_eq!(event.get_field(field), None, "{field} should stay absent");
            assert!(
                fields.get(field).is_none(),
                "{field} should not appear in serialized fields"
            );
        }
    }

    #[test]
    fn unusual_paths_are_preserved_verbatim_in_field_views() {
        let image = r"\\?\C:\Program Files\ユニコード\tool.exe ";
        let current_directory = r"\\server\share\folder.with.dots\..\leaf";
        let mut event = file_event();
        event.category = EventCategory::Process;
        event.event_id = 1;
        event.event_id_string = "1".to_string();
        event.opcode = 1;
        event.fields = EventFields::ProcessCreation(ProcessCreationFields {
            image: Some(image.to_string()),
            command_line: None,
            process_id: None,
            process_start_time: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: Some(current_directory.to_string()),
            integrity_level: None,
            user: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
        });

        assert_eq!(event.get_field("Image"), Some(image));
        assert_eq!(event.get_field("CurrentDirectory"), Some(current_directory));
        let fields = serde_json::to_value(&event.fields).expect("process fields serialize");
        assert_eq!(
            fields.get("Image").and_then(serde_json::Value::as_str),
            Some(image)
        );
        assert_eq!(
            fields
                .get("CurrentDirectory")
                .and_then(serde_json::Value::as_str),
            Some(current_directory)
        );
    }
}
