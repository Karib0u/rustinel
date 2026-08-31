use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use super::EventCategory;

/// Event fields enum containing category-specific data
///
/// Serialization is untagged: the payload is the bare field object, keyed by the
/// canonical Sigma/Sysmon field names. Reading that payload back therefore needs
/// the event category to say which variant it is — see
/// [`EventFields::from_recorded`]. Structural inference is not good enough,
/// because a minimal event carries too few fields to tell the variants apart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventFields {
    ProcessCreation(ProcessCreationFields),
    FileEvent(FileEventFields),
    RegistryEvent(RegistryEventFields),
    NetworkConnection(NetworkConnectionFields),
    DnsQuery(DnsQueryFields),
    ImageLoad(ImageLoadFields),
    PowerShellScript(PowerShellScriptFields),
    PowerShellModule(PowerShellModuleFields),
    RemoteThread(RemoteThreadFields),
    WmiEvent(WmiEventFields),
    ServiceCreation(ServiceCreationFields),
    TaskCreation(TaskCreationFields),
    SecurityAudit(SecurityAuditFields),
    Generic(HashMap<String, String>),
}

impl EventFields {
    /// Rebuild the fields of a recorded event from its category and payload.
    ///
    /// Each event category maps to exactly one typed variant, mirroring the
    /// sensor payload it was normalized from. Dispatching on the category is
    /// what keeps a two-field file event from being read back as a process
    /// event, which is all an untagged structural guess could conclude from
    /// `{"Image": ..., "ProcessId": ...}`.
    ///
    /// [`EventFields::Generic`] and [`EventFields::RemoteThread`] have no
    /// category of their own and are never produced by normalization, so they
    /// never appear in a recording; a payload written from one is read back as
    /// the typed variant of its category.
    pub fn from_recorded(
        category: EventCategory,
        payload: serde_json::Value,
    ) -> Result<Self, serde_json::Error> {
        match category {
            EventCategory::Process => serde_json::from_value(payload).map(Self::ProcessCreation),
            EventCategory::Network => serde_json::from_value(payload).map(Self::NetworkConnection),
            EventCategory::File => serde_json::from_value(payload).map(Self::FileEvent),
            EventCategory::Registry => serde_json::from_value(payload).map(Self::RegistryEvent),
            EventCategory::Dns => serde_json::from_value(payload).map(Self::DnsQuery),
            EventCategory::ImageLoad => serde_json::from_value(payload).map(Self::ImageLoad),
            EventCategory::Scripting => serde_json::from_value(payload).map(Self::PowerShellScript),
            EventCategory::PowerShellModule => {
                serde_json::from_value(payload).map(Self::PowerShellModule)
            }
            EventCategory::Wmi => serde_json::from_value(payload).map(Self::WmiEvent),
            EventCategory::Service => serde_json::from_value(payload).map(Self::ServiceCreation),
            EventCategory::Task => serde_json::from_value(payload).map(Self::TaskCreation),
            EventCategory::Security => serde_json::from_value(payload).map(Self::SecurityAudit),
        }
    }
}

/// Process creation/access event fields (Sigma: process_creation, process_access)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCreationFields {
    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "OriginalFileName", skip_serializing_if = "Option::is_none")]
    pub original_file_name: Option<String>,

    #[serde(rename = "Product", skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,

    #[serde(rename = "Description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "TargetImage", skip_serializing_if = "Option::is_none")]
    pub target_image: Option<String>,

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

    #[serde(rename = "CurrentDirectory", skip_serializing_if = "Option::is_none")]
    pub current_directory: Option<String>,

    #[serde(rename = "IntegrityLevel", skip_serializing_if = "Option::is_none")]
    pub integrity_level: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(rename = "LogonId", skip_serializing_if = "Option::is_none")]
    pub logon_id: Option<String>,

    #[serde(rename = "LogonGuid", skip_serializing_if = "Option::is_none")]
    pub logon_guid: Option<String>,
}

/// File event fields (Sigma: file_access, file_delete, file_event)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventFields {
    #[serde(rename = "SourceFilename", skip_serializing_if = "Option::is_none")]
    pub source_filename: Option<String>,

    #[serde(rename = "TargetFilename", skip_serializing_if = "Option::is_none")]
    pub target_filename: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "CreationUtcTime", skip_serializing_if = "Option::is_none")]
    pub creation_utc_time: Option<String>,

    #[serde(
        rename = "PreviousCreationUtcTime",
        skip_serializing_if = "Option::is_none"
    )]
    pub previous_creation_utc_time: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Which paths on this event were cut short by the sensor's capture buffer:
    /// `"target"`, `"source"`, or `"source,target"`. Absent when both are
    /// complete.
    ///
    /// Truncation removes the end of a path, which is what `endswith` rules and
    /// extension IOCs match on, so a rule that does not fire on an event
    /// carrying this marker has not cleared the file.
    #[serde(rename = "PathTruncated", skip_serializing_if = "Option::is_none")]
    pub path_truncated: Option<String>,
}

/// Registry event fields (Sigma: registry_event, registry_add, registry_delete, registry_set)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEventFields {
    #[serde(rename = "TargetObject", skip_serializing_if = "Option::is_none")]
    pub target_object: Option<String>,

    #[serde(rename = "Details", skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "EventType", skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(rename = "NewName", skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
}

/// Network connection event fields (Sigma: network_connection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionFields {
    #[serde(rename = "DestinationIp", skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,

    #[serde(rename = "SourceIp", skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    #[serde(rename = "DestinationPort", skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<String>,

    #[serde(rename = "SourcePort", skip_serializing_if = "Option::is_none")]
    pub source_port: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(
        rename = "DestinationHostname",
        skip_serializing_if = "Option::is_none"
    )]
    pub destination_hostname: Option<String>,

    #[serde(rename = "Protocol", skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// DNS query event fields (Sigma: dns_query)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryFields {
    #[serde(rename = "QueryName", skip_serializing_if = "Option::is_none")]
    pub query_name: Option<String>,

    #[serde(rename = "QueryResults", skip_serializing_if = "Option::is_none")]
    pub query_results: Option<String>,

    #[serde(rename = "RecordType", skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,

    #[serde(rename = "QueryStatus", skip_serializing_if = "Option::is_none")]
    pub query_status: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// Image load event fields (Sigma: image_load)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageLoadFields {
    #[serde(rename = "ImageLoaded", skip_serializing_if = "Option::is_none")]
    pub image_loaded: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "OriginalFileName", skip_serializing_if = "Option::is_none")]
    pub original_file_name: Option<String>,

    #[serde(rename = "Product", skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,

    #[serde(rename = "Description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "Signed", skip_serializing_if = "Option::is_none")]
    pub signed: Option<String>,

    #[serde(rename = "Signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// PowerShell script event fields (Sigma: ps_script)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellScriptFields {
    #[serde(rename = "ScriptBlockText", skip_serializing_if = "Option::is_none")]
    pub script_block_text: Option<String>,

    #[serde(rename = "ScriptBlockId", skip_serializing_if = "Option::is_none")]
    pub script_block_id: Option<String>,

    #[serde(rename = "Path", skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// PowerShell module logging event fields (Sigma: ps_module)
///
/// `ContextInfo` and `Payload` are the two fields the `ps_module` rule family
/// reads. Both are the provider's own free-form text: `ContextInfo` is a
/// newline-separated `name = value` block (host application, command name,
/// user), and `Payload` is the parameter-binding transcript. Windows writes
/// both in the host's display language, so a rule that matches on the label
/// rather than the value only fires on an English host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellModuleFields {
    #[serde(rename = "ContextInfo", skip_serializing_if = "Option::is_none")]
    pub context_info: Option<String>,

    #[serde(rename = "Payload", skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Remote thread creation event fields (Sigma: create_remote_thread)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteThreadFields {
    #[serde(rename = "SourceProcessId", skip_serializing_if = "Option::is_none")]
    pub source_process_id: Option<String>,

    #[serde(rename = "SourceImage", skip_serializing_if = "Option::is_none")]
    pub source_image: Option<String>,

    #[serde(rename = "TargetProcessId", skip_serializing_if = "Option::is_none")]
    pub target_process_id: Option<String>,

    #[serde(rename = "TargetImage", skip_serializing_if = "Option::is_none")]
    pub target_image: Option<String>,

    #[serde(rename = "StartAddress", skip_serializing_if = "Option::is_none")]
    pub start_address: Option<String>,

    #[serde(rename = "StartModule", skip_serializing_if = "Option::is_none")]
    pub start_module: Option<String>,

    #[serde(rename = "StartFunction", skip_serializing_if = "Option::is_none")]
    pub start_function: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// WMI event fields (Sigma: wmi_event)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiEventFields {
    #[serde(rename = "Operation", skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(rename = "Query", skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "EventNamespace", skip_serializing_if = "Option::is_none")]
    pub event_namespace: Option<String>,

    #[serde(rename = "EventType", skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,

    #[serde(
        rename = "DestinationHostname",
        skip_serializing_if = "Option::is_none"
    )]
    pub destination_hostname: Option<String>,
}

/// Service creation event fields
/// Maps to Windows Event ID 7045 (A service was installed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCreationFields {
    /// Windows Event Log provider that wrote the record, as Sigma names it.
    ///
    /// This is the `<Provider Name=..>` of the originating record
    /// (`Service Control Manager` for 7045), not
    /// [`NormalizedEvent::provider`](crate::models::NormalizedEvent), which
    /// names the Rustinel sensor that collected it (`windows_event_log`).
    /// Most `service: system` rules select on `Provider_Name` alongside
    /// `EventID`, so they cannot fire without it.
    #[serde(rename = "Provider_Name", skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,

    #[serde(rename = "ServiceName", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    #[serde(rename = "ServiceFileName", skip_serializing_if = "Option::is_none")]
    pub service_file_name: Option<String>,

    #[serde(rename = "ServiceType", skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,

    #[serde(rename = "StartType", skip_serializing_if = "Option::is_none")]
    pub start_type: Option<String>,

    #[serde(rename = "AccountName", skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// Task scheduler event fields
/// Maps to Windows Event ID 106 (Task Registered)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCreationFields {
    #[serde(rename = "TaskName", skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,

    #[serde(rename = "TaskContent", skip_serializing_if = "Option::is_none")]
    pub task_content: Option<String>,

    #[serde(rename = "UserName", skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,

    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(rename = "ProcessId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,

    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// Windows Security channel audit fields (Sigma: `windows/security`).
///
/// Every other category is a single event shape, so a struct of named options
/// models it exactly. The Security channel is not: one logsource carries event
/// families whose field sets barely overlap — a logon (4624), a handle request
/// (4656), a share access (5145) and a directory service change (5136) share
/// only the `Subject*` identity block — and each family the collector grows
/// brings its own. Keeping the record as the event's own field names avoids a
/// union struct that would be `None` in almost every slot on every event.
///
/// The names and the values are Windows' own, exactly as the channel renders
/// them, because that is what Sigma rules for this logsource are written
/// against: `SubjectLogonId` matches `0x3e4`, not `996`, and `AccessList`
/// matches the raw `%%4417` access-right codes.
///
/// The set is not open-ended. `sensor::windows::event_log::security` holds one
/// allowlist per supported event ID, and that table is the single statement of
/// which fields this collector populates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecurityAuditFields {
    pub fields: BTreeMap<String, String>,
}

impl SecurityAuditFields {
    /// Read a decoded field by its Windows name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// Record a decoded field, ignoring empty values.
    ///
    /// The channel writes `-` for a property that does not apply to the
    /// instance of the event, which is not a value a rule should be able to
    /// match on, so it is dropped like an empty one.
    pub fn insert(&mut self, name: &str, value: &str) {
        if value.is_empty() || value == "-" {
            return;
        }
        self.fields.insert(name.to_string(), value.to_string());
    }

    /// The process this event is attributed to, if it carries one.
    ///
    /// The Security channel renders process IDs in hex (`0x4d8`), unlike every
    /// other field in the model that holds a decimal PID string. The raw
    /// rendering stays in [`Self::fields`] for rules to match; this is the
    /// parse the pipeline itself needs for process-cache lookups.
    pub fn process_id(&self) -> Option<u32> {
        parse_windows_process_id(self.get("ProcessId")?)
    }
}

/// Parse a process ID as the Windows Security channel renders it.
///
/// Accepts the hex form the channel emits and a plain decimal, so a value that
/// arrives already normalized is not rejected.
pub fn parse_windows_process_id(value: &str) -> Option<u32> {
    let value = value.trim();
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => value.parse::<u32>().ok(),
    }
}
