use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
