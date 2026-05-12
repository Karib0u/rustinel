use super::helpers::{basename, parse_u64};
use super::user::apply_user_fields;
use crate::models::{MatchDetails, ProcessContext};
use serde::Serialize;

#[derive(Serialize)]
pub struct DnsAnswer {
    #[serde(rename = "data")]
    pub data: String,
}

/// ECS-compliant alert structure for SIEM ingestion
#[derive(Serialize)]
pub struct EcsAlert {
    /// Event timestamp in ISO 8601 format
    #[serde(rename = "@timestamp")]
    pub timestamp: String,

    /// ECS schema version
    #[serde(rename = "ecs.version")]
    pub ecs_version: String,

    /// Event kind (always "alert" for detections)
    #[serde(rename = "event.kind")]
    pub event_kind: String,

    /// Event category for classification
    #[serde(rename = "event.category", skip_serializing_if = "Vec::is_empty")]
    pub event_category: Vec<String>,

    /// Event type (subcategory)
    #[serde(rename = "event.type", skip_serializing_if = "Vec::is_empty")]
    pub event_type: Vec<String>,

    /// Event action
    #[serde(rename = "event.action", skip_serializing_if = "Option::is_none")]
    pub event_action: Option<String>,

    /// Event code (e.g. Windows Event ID / Sysmon Event ID)
    #[serde(rename = "event.code", skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,

    /// Event severity (numeric)
    #[serde(rename = "event.severity", skip_serializing_if = "Option::is_none")]
    pub event_severity: Option<u8>,

    /// ECS module (integration name)
    #[serde(rename = "event.module")]
    pub event_module: String,

    /// ECS dataset within the module
    #[serde(rename = "event.dataset")]
    pub event_dataset: String,

    /// Source that generated the event
    #[serde(rename = "event.provider")]
    pub event_provider: String,

    /// Host OS type for the sensor that produced the event.
    #[serde(rename = "host.os.type")]
    pub host_os_type: String,

    /// Host OS family for the sensor that produced the event.
    #[serde(rename = "host.os.family")]
    pub host_os_family: String,

    /// Detection rule name
    #[serde(rename = "rule.name")]
    pub rule_name: String,

    /// Detection rule description / IOC comment
    #[serde(rename = "rule.description", skip_serializing_if = "Option::is_none")]
    pub rule_description: Option<String>,

    /// Detection severity (critical, high, medium, low)
    #[serde(rename = "edr.rule.severity")]
    pub edr_rule_severity: String,

    /// Detection engine (Sigma, Yara, Ioc)
    #[serde(rename = "edr.rule.engine")]
    pub edr_rule_engine: String,

    // ========================================================================
    // Process Fields
    // ========================================================================
    #[serde(rename = "process.executable", skip_serializing_if = "Option::is_none")]
    pub process_executable: Option<String>,

    #[serde(rename = "process.name", skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,

    #[serde(
        rename = "process.command_line",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_command_line: Option<String>,

    #[serde(rename = "process.pid", skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<u64>,

    #[serde(
        rename = "process.parent.executable",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_parent_executable: Option<String>,

    #[serde(
        rename = "process.parent.name",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_parent_name: Option<String>,

    #[serde(
        rename = "process.parent.command_line",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_parent_command_line: Option<String>,

    #[serde(rename = "process.parent.pid", skip_serializing_if = "Option::is_none")]
    pub process_parent_pid: Option<u64>,

    #[serde(
        rename = "process.working_directory",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_working_directory: Option<String>,

    #[serde(
        rename = "edr.process.integrity_level",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_process_integrity_level: Option<String>,

    #[serde(
        rename = "process.pe.original_file_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_original_file_name: Option<String>,

    #[serde(rename = "process.pe.product", skip_serializing_if = "Option::is_none")]
    pub process_product: Option<String>,

    #[serde(
        rename = "process.pe.description",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_description: Option<String>,

    #[serde(rename = "user.name", skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,

    #[serde(rename = "user.id", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    #[serde(rename = "user.domain", skip_serializing_if = "Option::is_none")]
    pub user_domain: Option<String>,

    #[serde(rename = "winlog.logon.id", skip_serializing_if = "Option::is_none")]
    pub winlog_logon_id: Option<String>,

    #[serde(rename = "winlog.logon.guid", skip_serializing_if = "Option::is_none")]
    pub winlog_logon_guid: Option<String>,

    // ========================================================================
    // Network Fields
    // ========================================================================
    #[serde(rename = "destination.ip", skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,

    #[serde(rename = "destination.port", skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,

    #[serde(rename = "source.ip", skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    #[serde(rename = "source.port", skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,

    #[serde(rename = "destination.domain", skip_serializing_if = "Option::is_none")]
    pub destination_domain: Option<String>,

    #[serde(rename = "network.transport", skip_serializing_if = "Option::is_none")]
    pub network_transport: Option<String>,

    #[serde(rename = "network.type", skip_serializing_if = "Option::is_none")]
    pub network_type: Option<String>,

    #[serde(rename = "network.protocol", skip_serializing_if = "Option::is_none")]
    pub network_protocol: Option<String>,

    #[serde(rename = "network.direction", skip_serializing_if = "Option::is_none")]
    pub network_direction: Option<String>,

    // ========================================================================
    // File Fields
    // ========================================================================
    #[serde(rename = "file.path", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    #[serde(rename = "file.name", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,

    #[serde(rename = "file.extension", skip_serializing_if = "Option::is_none")]
    pub file_extension: Option<String>,

    #[serde(rename = "file.created", skip_serializing_if = "Option::is_none")]
    pub file_created: Option<String>,

    #[serde(
        rename = "edr.file.previous_created",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_file_previous_created: Option<String>,

    #[serde(
        rename = "file.pe.original_file_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_original_file_name: Option<String>,

    #[serde(rename = "file.pe.product", skip_serializing_if = "Option::is_none")]
    pub file_product: Option<String>,

    #[serde(
        rename = "file.pe.description",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_description: Option<String>,

    #[serde(
        rename = "file.code_signature.exists",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_code_signature_exists: Option<bool>,

    #[serde(
        rename = "file.code_signature.subject_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_code_signature_subject_name: Option<String>,

    // ========================================================================
    // DLL Fields
    // ========================================================================
    #[serde(rename = "dll.name", skip_serializing_if = "Option::is_none")]
    pub dll_name: Option<String>,

    #[serde(rename = "dll.path", skip_serializing_if = "Option::is_none")]
    pub dll_path: Option<String>,

    // ========================================================================
    // Registry Fields
    // ========================================================================
    #[serde(rename = "registry.path", skip_serializing_if = "Option::is_none")]
    pub registry_path: Option<String>,

    #[serde(rename = "registry.hive", skip_serializing_if = "Option::is_none")]
    pub registry_hive: Option<String>,

    #[serde(rename = "registry.key", skip_serializing_if = "Option::is_none")]
    pub registry_key: Option<String>,

    #[serde(rename = "registry.value", skip_serializing_if = "Option::is_none")]
    pub registry_value: Option<String>,

    #[serde(
        rename = "registry.data.strings",
        skip_serializing_if = "Option::is_none"
    )]
    pub registry_data_strings: Option<Vec<String>>,

    #[serde(
        rename = "edr.registry.event_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_registry_event_type: Option<String>,

    #[serde(
        rename = "edr.registry.new_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_registry_new_name: Option<String>,

    // ========================================================================
    // DNS Fields
    // ========================================================================
    #[serde(rename = "dns.question.name", skip_serializing_if = "Option::is_none")]
    pub dns_query: Option<String>,

    #[serde(rename = "dns.answers", skip_serializing_if = "Option::is_none")]
    pub dns_answers: Option<Vec<DnsAnswer>>,

    #[serde(rename = "dns.response_code", skip_serializing_if = "Option::is_none")]
    pub dns_response_code: Option<String>,

    #[serde(rename = "dns.resolved_ip", skip_serializing_if = "Option::is_none")]
    pub dns_resolved_ip: Option<Vec<String>>,

    // ========================================================================
    // Service Persistence Fields
    // ========================================================================
    #[serde(rename = "service.name", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    #[serde(
        rename = "edr.service.executable",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_service_executable: Option<String>,

    #[serde(rename = "edr.service.type", skip_serializing_if = "Option::is_none")]
    pub edr_service_type: Option<String>,

    #[serde(
        rename = "edr.service.start_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_service_start_type: Option<String>,

    #[serde(
        rename = "edr.service.account_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_service_account_name: Option<String>,

    // ========================================================================
    // Task Scheduler Persistence Fields
    // ========================================================================
    #[serde(rename = "edr.task.name", skip_serializing_if = "Option::is_none")]
    pub edr_task_name: Option<String>,

    #[serde(rename = "edr.task.content", skip_serializing_if = "Option::is_none")]
    pub edr_task_content: Option<String>,

    #[serde(rename = "edr.task.user_name", skip_serializing_if = "Option::is_none")]
    pub edr_task_user_name: Option<String>,

    // ========================================================================
    // PowerShell Fields
    // ========================================================================
    #[serde(
        rename = "edr.powershell.script_block_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_powershell_script_block_text: Option<String>,

    #[serde(
        rename = "edr.powershell.script_block_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_powershell_script_block_id: Option<String>,

    // ========================================================================
    // WMI Fields
    // ========================================================================
    #[serde(rename = "edr.wmi.operation", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_operation: Option<String>,

    #[serde(rename = "edr.wmi.query", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_query: Option<String>,

    #[serde(rename = "edr.wmi.namespace", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_namespace: Option<String>,

    #[serde(rename = "edr.wmi.event_type", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_event_type: Option<String>,

    // ========================================================================
    // Remote Thread Fields
    // ========================================================================
    #[serde(
        rename = "edr.remote_thread.target_pid",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_target_pid: Option<u64>,

    #[serde(
        rename = "edr.remote_thread.target_image",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_target_image: Option<String>,

    #[serde(
        rename = "edr.remote_thread.start_address",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_start_address: Option<String>,

    #[serde(
        rename = "edr.remote_thread.start_module",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_start_module: Option<String>,

    #[serde(
        rename = "edr.remote_thread.start_function",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_start_function: Option<String>,

    // ========================================================================
    // Process Target Fields
    // ========================================================================
    #[serde(
        rename = "edr.process.target_image",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_process_target_image: Option<String>,

    // ========================================================================
    // Related Fields
    // ========================================================================
    #[serde(rename = "related.ip", skip_serializing_if = "Option::is_none")]
    pub related_ip: Option<Vec<String>>,

    #[serde(rename = "related.user", skip_serializing_if = "Option::is_none")]
    pub related_user: Option<Vec<String>>,

    // ========================================================================
    // Debug Match Details
    // ========================================================================
    #[serde(rename = "edr.match", skip_serializing_if = "Option::is_none")]
    pub edr_match: Option<MatchDetails>,
}

impl EcsAlert {
    pub(super) fn apply_process_context(ecs: &mut EcsAlert, context: &ProcessContext) {
        if ecs.process_executable.is_none() {
            ecs.process_executable = context.image.clone();
        }
        if ecs.process_command_line.is_none() {
            ecs.process_command_line = context.command_line.clone();
        }
        if ecs.process_pid.is_none() {
            ecs.process_pid = parse_u64(&context.process_id);
        }
        if ecs.process_parent_executable.is_none() {
            ecs.process_parent_executable = context.parent_image.clone();
        }
        if ecs.process_parent_command_line.is_none() {
            ecs.process_parent_command_line = context.parent_command_line.clone();
        }
        if ecs.process_parent_pid.is_none() {
            ecs.process_parent_pid = parse_u64(&context.parent_process_id);
        }
        if ecs.process_working_directory.is_none() {
            ecs.process_working_directory = context.current_directory.clone();
        }
        if ecs.edr_process_integrity_level.is_none() {
            ecs.edr_process_integrity_level = context.integrity_level.clone();
        }
        if ecs.process_original_file_name.is_none() {
            ecs.process_original_file_name = context.original_file_name.clone();
        }
        if ecs.process_product.is_none() {
            ecs.process_product = context.product.clone();
        }
        if ecs.process_description.is_none() {
            ecs.process_description = context.description.clone();
        }
        apply_user_fields(ecs, context.user.as_deref());
        if ecs.winlog_logon_id.is_none() {
            ecs.winlog_logon_id = context.logon_id.clone();
        }
        if ecs.winlog_logon_guid.is_none() {
            ecs.winlog_logon_guid = context.logon_guid.clone();
        }

        if ecs.process_name.is_none() {
            ecs.process_name = ecs.process_executable.as_deref().and_then(basename);
        }

        if ecs.process_parent_name.is_none() {
            ecs.process_parent_name = ecs.process_parent_executable.as_deref().and_then(basename);
        }
    }
}
