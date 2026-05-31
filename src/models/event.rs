use super::EventFields;
use crate::sensor::Platform;
use serde::{Deserialize, Serialize};

/// Normalized event structure compatible with Sigma/Sysmon format
#[derive(Debug, Clone, Serialize, Deserialize)]
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
                "CommandLine" => f.command_line.as_deref(),
                "ProcessId" => f.process_id.as_deref(),
                "ParentProcessId" => f.parent_process_id.as_deref(),
                "ParentImage" => f.parent_image.as_deref(),
                "ParentCommandLine" => f.parent_command_line.as_deref(),
                "User" => f.user.as_deref(),
                "IntegrityLevel" => f.integrity_level.as_deref(),
                "CurrentDirectory" => f.current_directory.as_deref(),
                "TargetImage" => f.target_image.as_deref(),
                "LogonId" => f.logon_id.as_deref(),
                "LogonGuid" => f.logon_guid.as_deref(),
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
                "ServiceName" => f.service_name.as_deref(),
                "ServiceFileName" => f.service_file_name.as_deref(),
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
            EventFields::Generic(map) => map.get(key).map(|s| s.as_str()),
        }
    }

    /// Helper for keyword search - collects all field values
    /// Used for rules that search across all fields
    pub fn all_field_values(&self) -> Vec<&str> {
        let mut values = vec![self.timestamp.as_str(), self.event_id_string.as_str()];

        match &self.fields {
            EventFields::ProcessCreation(f) => {
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.original_file_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.product {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.description {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.command_line {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.parent_process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.parent_image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.parent_command_line {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.current_directory {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.integrity_level {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.target_image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.logon_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.logon_guid {
                    values.push(v.as_str());
                }
            }
            EventFields::FileEvent(f) => {
                if let Some(v) = &f.source_filename {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.target_filename {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.creation_utc_time {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.previous_creation_utc_time {
                    values.push(v.as_str());
                }
            }
            EventFields::NetworkConnection(f) => {
                if let Some(v) = &f.destination_ip {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.source_ip {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.destination_port {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.source_port {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.destination_hostname {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.protocol {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
            }
            EventFields::RegistryEvent(f) => {
                if let Some(v) = &f.target_object {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.details {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.event_type {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.new_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
            }
            EventFields::DnsQuery(f) => {
                if let Some(v) = &f.query_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.query_results {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.record_type {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.query_status {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
            }
            EventFields::ImageLoad(f) => {
                if let Some(v) = &f.image_loaded {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.original_file_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.product {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.description {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.signed {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.signature {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
            }
            EventFields::PowerShellScript(f) => {
                if let Some(v) = &f.script_block_text {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.script_block_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.path {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
            }
            EventFields::RemoteThread(f) => {
                if let Some(v) = &f.source_process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.source_image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.target_process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.target_image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.start_address {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.start_module {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.start_function {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
            }
            EventFields::WmiEvent(f) => {
                if let Some(v) = &f.operation {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.query {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.event_namespace {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.event_type {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.destination_hostname {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
            }
            EventFields::ServiceCreation(f) => {
                if let Some(v) = &f.service_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.service_file_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.service_type {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.start_type {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.account_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
            }
            EventFields::TaskCreation(f) => {
                if let Some(v) = &f.task_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.task_content {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user_name {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.user {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.process_id {
                    values.push(v.as_str());
                }
                if let Some(v) = &f.image {
                    values.push(v.as_str());
                }
            }
            EventFields::Generic(map) => {
                for v in map.values() {
                    values.push(v.as_str());
                }
            }
        }

        values
    }

    /// Helper for keyword search with field names - collects all field values
    /// Used for debug match details to explain which field matched a keyword
    pub fn all_field_values_with_keys(&self) -> Vec<(&str, &str)> {
        let mut values = Vec::new();

        values.push(("timestamp", self.timestamp.as_str()));
        values.push(("EventID", self.event_id_string.as_str()));

        match &self.fields {
            EventFields::ProcessCreation(f) => {
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.original_file_name {
                    values.push(("OriginalFileName", v.as_str()));
                }
                if let Some(v) = &f.product {
                    values.push(("Product", v.as_str()));
                }
                if let Some(v) = &f.description {
                    values.push(("Description", v.as_str()));
                }
                if let Some(v) = &f.command_line {
                    values.push(("CommandLine", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
                if let Some(v) = &f.parent_process_id {
                    values.push(("ParentProcessId", v.as_str()));
                }
                if let Some(v) = &f.parent_image {
                    values.push(("ParentImage", v.as_str()));
                }
                if let Some(v) = &f.parent_command_line {
                    values.push(("ParentCommandLine", v.as_str()));
                }
                if let Some(v) = &f.current_directory {
                    values.push(("CurrentDirectory", v.as_str()));
                }
                if let Some(v) = &f.integrity_level {
                    values.push(("IntegrityLevel", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.target_image {
                    values.push(("TargetImage", v.as_str()));
                }
                if let Some(v) = &f.logon_id {
                    values.push(("LogonId", v.as_str()));
                }
                if let Some(v) = &f.logon_guid {
                    values.push(("LogonGuid", v.as_str()));
                }
            }
            EventFields::FileEvent(f) => {
                if let Some(v) = &f.source_filename {
                    values.push(("SourceFilename", v.as_str()));
                }
                if let Some(v) = &f.target_filename {
                    values.push(("TargetFilename", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.creation_utc_time {
                    values.push(("CreationUtcTime", v.as_str()));
                }
                if let Some(v) = &f.previous_creation_utc_time {
                    values.push(("PreviousCreationUtcTime", v.as_str()));
                }
            }
            EventFields::NetworkConnection(f) => {
                if let Some(v) = &f.destination_ip {
                    values.push(("DestinationIp", v.as_str()));
                }
                if let Some(v) = &f.source_ip {
                    values.push(("SourceIp", v.as_str()));
                }
                if let Some(v) = &f.destination_port {
                    values.push(("DestinationPort", v.as_str()));
                }
                if let Some(v) = &f.source_port {
                    values.push(("SourcePort", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.destination_hostname {
                    values.push(("DestinationHostname", v.as_str()));
                }
                if let Some(v) = &f.protocol {
                    values.push(("Protocol", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
            }
            EventFields::RegistryEvent(f) => {
                if let Some(v) = &f.target_object {
                    values.push(("TargetObject", v.as_str()));
                }
                if let Some(v) = &f.details {
                    values.push(("Details", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.event_type {
                    values.push(("EventType", v.as_str()));
                }
                if let Some(v) = &f.new_name {
                    values.push(("NewName", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
            }
            EventFields::DnsQuery(f) => {
                if let Some(v) = &f.query_name {
                    values.push(("query", v.as_str()));
                }
                if let Some(v) = &f.query_results {
                    values.push(("answer", v.as_str()));
                }
                if let Some(v) = &f.record_type {
                    values.push(("record_type", v.as_str()));
                }
                if let Some(v) = &f.query_name {
                    values.push(("QueryName", v.as_str()));
                }
                if let Some(v) = &f.query_results {
                    values.push(("QueryResults", v.as_str()));
                }
                if let Some(v) = &f.record_type {
                    values.push(("RecordType", v.as_str()));
                }
                if let Some(v) = &f.query_status {
                    values.push(("QueryStatus", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
            }
            EventFields::ImageLoad(f) => {
                if let Some(v) = &f.image_loaded {
                    values.push(("ImageLoaded", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.original_file_name {
                    values.push(("OriginalFileName", v.as_str()));
                }
                if let Some(v) = &f.product {
                    values.push(("Product", v.as_str()));
                }
                if let Some(v) = &f.description {
                    values.push(("Description", v.as_str()));
                }
                if let Some(v) = &f.signed {
                    values.push(("Signed", v.as_str()));
                }
                if let Some(v) = &f.signature {
                    values.push(("Signature", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
            }
            EventFields::PowerShellScript(f) => {
                if let Some(v) = &f.script_block_text {
                    values.push(("ScriptBlockText", v.as_str()));
                }
                if let Some(v) = &f.script_block_id {
                    values.push(("ScriptBlockId", v.as_str()));
                }
                if let Some(v) = &f.path {
                    values.push(("Path", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
            }
            EventFields::RemoteThread(f) => {
                if let Some(v) = &f.source_process_id {
                    values.push(("SourceProcessId", v.as_str()));
                }
                if let Some(v) = &f.source_image {
                    values.push(("SourceImage", v.as_str()));
                }
                if let Some(v) = &f.target_process_id {
                    values.push(("TargetProcessId", v.as_str()));
                }
                if let Some(v) = &f.target_image {
                    values.push(("TargetImage", v.as_str()));
                }
                if let Some(v) = &f.start_address {
                    values.push(("StartAddress", v.as_str()));
                }
                if let Some(v) = &f.start_module {
                    values.push(("StartModule", v.as_str()));
                }
                if let Some(v) = &f.start_function {
                    values.push(("StartFunction", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
            }
            EventFields::WmiEvent(f) => {
                if let Some(v) = &f.operation {
                    values.push(("Operation", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.query {
                    values.push(("Query", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
                if let Some(v) = &f.event_namespace {
                    values.push(("EventNamespace", v.as_str()));
                }
                if let Some(v) = &f.event_type {
                    values.push(("EventType", v.as_str()));
                }
                if let Some(v) = &f.destination_hostname {
                    values.push(("DestinationHostname", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
            }
            EventFields::ServiceCreation(f) => {
                if let Some(v) = &f.service_name {
                    values.push(("ServiceName", v.as_str()));
                }
                if let Some(v) = &f.service_file_name {
                    values.push(("ServiceFileName", v.as_str()));
                }
                if let Some(v) = &f.service_type {
                    values.push(("ServiceType", v.as_str()));
                }
                if let Some(v) = &f.start_type {
                    values.push(("StartType", v.as_str()));
                }
                if let Some(v) = &f.account_name {
                    values.push(("AccountName", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
            }
            EventFields::TaskCreation(f) => {
                if let Some(v) = &f.task_name {
                    values.push(("TaskName", v.as_str()));
                }
                if let Some(v) = &f.task_content {
                    values.push(("TaskContent", v.as_str()));
                }
                if let Some(v) = &f.user_name {
                    values.push(("UserName", v.as_str()));
                }
                if let Some(v) = &f.user {
                    values.push(("User", v.as_str()));
                }
                if let Some(v) = &f.process_id {
                    values.push(("ProcessId", v.as_str()));
                }
                if let Some(v) = &f.image {
                    values.push(("Image", v.as_str()));
                }
            }
            EventFields::Generic(map) => {
                for (key, value) in map {
                    values.push((key.as_str(), value.as_str()));
                }
            }
        }

        values
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
    Wmi,
    Service,
    Task,
}
