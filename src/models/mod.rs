//! Data models module
//!
//! Defines core data structures like NormalizedEvent and Alert.

pub mod ecs;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Normalized event structure compatible with Sigma/Sysmon format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    /// Event timestamp
    pub timestamp: String,
    /// Event category (Process, Network, File, Registry, DNS, ImageLoad)
    pub category: EventCategory,
    /// ETW Event ID (after Kernel->Sysmon mapping)
    pub event_id: u16,
    /// Cached string representation of event_id for zero-copy flatten()
    #[serde(skip)]
    pub event_id_string: String,
    /// ETW OpCode (e.g., 1=Start, 2=Stop, 10=ImageLoad)
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

/// Event fields enum containing category-specific data
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
    RemoteThread(RemoteThreadFields),
    WmiEvent(WmiEventFields),
    ServiceCreation(ServiceCreationFields),
    TaskCreation(TaskCreationFields),
    Generic(HashMap<String, String>),
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
}

/// DNS query event fields (Sigma: dns_query)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryFields {
    #[serde(rename = "QueryName", skip_serializing_if = "Option::is_none")]
    pub query_name: Option<String>,

    #[serde(rename = "QueryResults", skip_serializing_if = "Option::is_none")]
    pub query_results: Option<String>,

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
                "QueryName" => f.query_name.as_deref(),
                "QueryResults" => f.query_results.as_deref(),
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
                    values.push(("QueryName", v.as_str()));
                }
                if let Some(v) = &f.query_results {
                    values.push(("QueryResults", v.as_str()));
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

/// Debug verbosity for match details in alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_category() {
        assert_eq!(EventCategory::Process, EventCategory::Process);
    }

    #[test]
    fn test_alert_serialization() {
        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
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
            engine: DetectionEngine::Sigma,
            event,
            match_details: None,
        };
        let _json = serde_json::to_string(&alert).unwrap();
    }
}
