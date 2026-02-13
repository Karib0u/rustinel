//! ECS (Elastic Common Schema) alert mapping
//! https://github.com/elastic/ecs/tree/main
//! This module provides a translation layer between internal Alert structures
//! and the standardized ECS format expected by SIEM systems like Elasticsearch,
//! Splunk, and other log aggregation platforms.
//!
//! ## Design
//! - Decouples internal data models from external API contracts
//! - Ensures consistent JSON output for security alerts
//! - Supports incremental field additions without breaking changes

use crate::models::{
    Alert, AlertSeverity, EventCategory, EventFields, MatchDetails, ProcessContext,
};
use serde::Serialize;
use std::net::IpAddr;

const ECS_VERSION: &str = "9.3.0";
const EVENT_MODULE: &str = "edr";
const EVENT_PROVIDER: &str = "edr-rust";

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
    // Named Pipe (Lateral Movement) Fields
    // ========================================================================
    #[serde(rename = "edr.pipe.name", skip_serializing_if = "Option::is_none")]
    pub edr_pipe_name: Option<String>,

    #[serde(
        rename = "edr.pipe.event_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_pipe_event_type: Option<String>,

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

/// Convert internal Alert to ECS format
fn alert_severity_to_event_severity(severity: AlertSeverity) -> u8 {
    match severity {
        AlertSeverity::Low => 25,
        AlertSeverity::Medium => 50,
        AlertSeverity::High => 75,
        AlertSeverity::Critical => 100,
    }
}

fn ecs_event_category(category: EventCategory) -> Vec<String> {
    match category {
        EventCategory::Process => vec!["process".to_string()],
        EventCategory::Network => vec!["network".to_string()],
        EventCategory::File => vec!["file".to_string()],
        EventCategory::Registry => vec!["registry".to_string()],
        EventCategory::Dns => vec!["network".to_string()],
        EventCategory::ImageLoad => vec!["library".to_string()],
        EventCategory::Scripting => vec!["process".to_string()],
        EventCategory::Wmi => vec!["api".to_string()],
        EventCategory::Service => vec!["configuration".to_string()],
        EventCategory::Task => vec!["configuration".to_string()],
        EventCategory::PipeEvent => vec!["process".to_string()],
    }
}

fn ecs_event_type(category: EventCategory, opcode: u8, event_id: u16) -> Vec<String> {
    match category {
        EventCategory::Process => match opcode {
            1 => vec!["start".to_string()],
            2 => vec!["end".to_string()],
            _ => vec!["info".to_string()],
        },
        EventCategory::Network => vec!["connection".to_string()],
        EventCategory::File => match opcode {
            64 | 65 => vec!["creation".to_string()],
            70 | 72 => vec!["deletion".to_string()],
            _ => vec!["change".to_string()],
        },
        EventCategory::Registry => match opcode {
            36 => vec!["creation".to_string()],
            38 | 41 => vec!["deletion".to_string()],
            39 => vec!["change".to_string()],
            _ => vec!["change".to_string()],
        },
        EventCategory::Dns => vec!["protocol".to_string()],
        EventCategory::ImageLoad => vec!["start".to_string()],
        EventCategory::Scripting => vec!["info".to_string()],
        EventCategory::Wmi => vec!["info".to_string()],
        EventCategory::Service => {
            if event_id == 7045 {
                vec!["creation".to_string()]
            } else {
                vec!["change".to_string()]
            }
        }
        EventCategory::Task => {
            if event_id == 106 {
                vec!["creation".to_string()]
            } else {
                vec!["change".to_string()]
            }
        }
        EventCategory::PipeEvent => match opcode {
            64 => vec!["creation".to_string()],
            65 => vec!["access".to_string()],
            _ => vec!["info".to_string()],
        },
    }
}

fn ecs_event_action(category: EventCategory, opcode: u8, event_id: u16) -> Option<String> {
    let action = match category {
        EventCategory::Process => match opcode {
            1 => "process-start",
            2 => "process-end",
            _ => "process-info",
        },
        EventCategory::Network => "network-connection",
        EventCategory::File => match opcode {
            64 | 65 => "file-create",
            70 | 72 => "file-delete",
            _ => "file-change",
        },
        EventCategory::Registry => match opcode {
            36 => "registry-create",
            38 | 41 => "registry-delete",
            39 => "registry-set",
            _ => "registry-change",
        },
        EventCategory::Dns => "dns-query",
        EventCategory::ImageLoad => "image-load",
        EventCategory::Scripting => "powershell-script",
        EventCategory::Wmi => "wmi-operation",
        EventCategory::Service => {
            if event_id == 7045 {
                "service-create"
            } else {
                "service-change"
            }
        }
        EventCategory::Task => {
            if event_id == 106 {
                "task-create"
            } else {
                "task-change"
            }
        }
        EventCategory::PipeEvent => match opcode {
            64 => "pipe-create",
            65 => "pipe-connect",
            _ => "pipe-activity",
        },
    };
    Some(action.to_string())
}

fn event_dataset(category: EventCategory) -> String {
    let suffix = match category {
        EventCategory::Process => "process",
        EventCategory::Network => "network",
        EventCategory::File => "file",
        EventCategory::Registry => "registry",
        EventCategory::Dns => "dns",
        EventCategory::ImageLoad => "library",
        EventCategory::Scripting => "scripting",
        EventCategory::Wmi => "wmi",
        EventCategory::Service => "service",
        EventCategory::Task => "task",
        EventCategory::PipeEvent => "pipe",
    };
    format!("{}.{}", EVENT_MODULE, suffix)
}

fn event_provider() -> String {
    EVENT_PROVIDER.to_string()
}

fn network_direction_from_category(category: EventCategory) -> Option<String> {
    match category {
        EventCategory::Network | EventCategory::Dns => Some("egress".to_string()),
        _ => None,
    }
}

fn parse_u64(value: &Option<String>) -> Option<u64> {
    value.as_ref().and_then(|v| v.trim().parse::<u64>().ok())
}

fn parse_u16(value: &Option<String>) -> Option<u16> {
    value.as_ref().and_then(|v| v.trim().parse::<u16>().ok())
}

fn parse_bool(value: &Option<String>) -> Option<bool> {
    let normalized = value.as_ref()?.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "true" | "signed" | "valid" | "yes" => Some(true),
        "false" | "unsigned" | "invalid" | "no" => Some(false),
        _ => None,
    }
}

fn basename(path: &str) -> Option<String> {
    let trimmed = path.trim_matches('"');
    let name = trimmed.rsplit(['\\', '/']).next().unwrap_or("");
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn file_extension_from_path(path: &str) -> Option<String> {
    let name = basename(path)?;
    let (_, ext) = name.rsplit_once('.')?;
    if ext.is_empty() {
        None
    } else {
        Some(ext.to_string())
    }
}

fn network_transport_from_opcode(opcode: u8) -> Option<String> {
    match opcode {
        12 => Some("tcp".to_string()),
        15 => Some("udp".to_string()),
        _ => None,
    }
}

fn network_type_from_ip(ip: &str) -> Option<String> {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Some("ipv4".to_string()),
        Ok(IpAddr::V6(_)) => Some("ipv6".to_string()),
        Err(_) => None,
    }
}

fn split_registry_path(
    path: &str,
    event_type: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut parts = path.split('\\');
    let hive = parts.next().map(|value| value.to_string());
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return (hive, None, None);
    }

    let is_value = event_type
        .map(|value| value.to_ascii_lowercase().contains("value"))
        .unwrap_or(false);

    if is_value {
        let value = rest.last().unwrap().to_string();
        let key = rest[..rest.len() - 1].join("\\");
        let key = if key.is_empty() { None } else { Some(key) };
        (hive, key, Some(value))
    } else {
        let key = rest.join("\\");
        let key = if key.is_empty() { None } else { Some(key) };
        (hive, key, None)
    }
}

fn extract_ips(value: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for token in value.split(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':') {
        if token.is_empty() {
            continue;
        }
        if let Ok(addr) = token.parse::<IpAddr>() {
            ips.push(addr.to_string());
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

fn is_sid(value: &str) -> bool {
    value.starts_with("S-1-")
}

fn split_user(value: &str) -> (Option<String>, Option<String>, Option<String>) {
    if is_sid(value) {
        return (None, Some(value.to_string()), None);
    }

    if let Some((domain, name)) = value.split_once('\\') {
        return (Some(name.to_string()), None, Some(domain.to_string()));
    }

    (Some(value.to_string()), None, None)
}

fn apply_user_fields(ecs: &mut EcsAlert, user: Option<&str>) {
    let value = match user {
        Some(value) if !value.is_empty() => value,
        _ => return,
    };

    let (name, id, domain) = split_user(value);

    if ecs.user_id.is_none() {
        ecs.user_id = id;
    }

    if ecs.user_domain.is_none() {
        ecs.user_domain = domain;
    }

    if let Some(name) = name {
        if ecs.user_name.is_none() || ecs.user_name.as_deref().map(is_sid).unwrap_or(false) {
            ecs.user_name = Some(name);
        }
    }
}

/// Convert internal Alert to ECS format
impl From<&Alert> for EcsAlert {
    fn from(alert: &Alert) -> Self {
        let opcode = alert.event.opcode;
        let event_id = alert.event.event_id;
        let event_category = ecs_event_category(alert.event.category);
        let event_type = ecs_event_type(alert.event.category, opcode, event_id);
        let event_action = ecs_event_action(alert.event.category, opcode, event_id);
        let event_code = if !alert.event.event_id_string.is_empty() {
            Some(alert.event.event_id_string.clone())
        } else {
            Some(alert.event.event_id.to_string())
        };

        let mut ecs = EcsAlert {
            timestamp: alert.event.timestamp.clone(),
            ecs_version: ECS_VERSION.to_string(),
            event_kind: "alert".to_string(),
            event_category,
            event_type,
            event_action,
            event_code,
            event_severity: Some(alert_severity_to_event_severity(alert.severity)),
            event_module: EVENT_MODULE.to_string(),
            event_dataset: event_dataset(alert.event.category),
            event_provider: event_provider(),
            rule_name: alert.rule_name.clone(),
            rule_description: alert.rule_description.clone(),
            edr_rule_severity: format!("{:?}", alert.severity),
            edr_rule_engine: format!("{:?}", alert.engine),
            process_executable: None,
            process_name: None,
            process_command_line: None,
            process_pid: None,
            process_parent_executable: None,
            process_parent_name: None,
            process_parent_command_line: None,
            process_parent_pid: None,
            process_working_directory: None,
            edr_process_integrity_level: None,
            process_original_file_name: None,
            process_product: None,
            process_description: None,
            user_name: None,
            user_id: None,
            user_domain: None,
            winlog_logon_id: None,
            winlog_logon_guid: None,
            destination_ip: None,
            destination_port: None,
            source_ip: None,
            source_port: None,
            destination_domain: None,
            network_transport: None,
            network_type: None,
            network_protocol: None,
            network_direction: None,
            file_path: None,
            file_name: None,
            file_extension: None,
            file_created: None,
            edr_file_previous_created: None,
            file_original_file_name: None,
            file_product: None,
            file_description: None,
            file_code_signature_exists: None,
            file_code_signature_subject_name: None,
            dll_name: None,
            dll_path: None,
            registry_path: None,
            registry_hive: None,
            registry_key: None,
            registry_value: None,
            registry_data_strings: None,
            edr_registry_event_type: None,
            edr_registry_new_name: None,
            dns_query: None,
            dns_answers: None,
            dns_response_code: None,
            dns_resolved_ip: None,
            service_name: None,
            edr_service_executable: None,
            edr_service_type: None,
            edr_service_start_type: None,
            edr_service_account_name: None,
            edr_task_name: None,
            edr_task_content: None,
            edr_task_user_name: None,
            edr_pipe_name: None,
            edr_pipe_event_type: None,
            edr_powershell_script_block_text: None,
            edr_powershell_script_block_id: None,
            edr_wmi_operation: None,
            edr_wmi_query: None,
            edr_wmi_namespace: None,
            edr_wmi_event_type: None,
            edr_remote_thread_target_pid: None,
            edr_remote_thread_target_image: None,
            edr_remote_thread_start_address: None,
            edr_remote_thread_start_module: None,
            edr_remote_thread_start_function: None,
            edr_process_target_image: None,
            related_ip: None,
            related_user: None,
            edr_match: alert.match_details.clone(),
        };

        // Map internal fields to ECS based on event type
        match &alert.event.fields {
            EventFields::ProcessCreation(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_command_line = f.command_line.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                ecs.process_parent_executable = f.parent_image.clone();
                ecs.process_parent_command_line = f.parent_command_line.clone();
                ecs.process_parent_pid = parse_u64(&f.parent_process_id);
                ecs.process_working_directory = f.current_directory.clone();
                ecs.edr_process_integrity_level = f.integrity_level.clone();
                ecs.process_original_file_name = f.original_file_name.clone();
                ecs.process_product = f.product.clone();
                ecs.process_description = f.description.clone();
                apply_user_fields(&mut ecs, f.user.as_deref());
                ecs.winlog_logon_id = f.logon_id.clone();
                ecs.winlog_logon_guid = f.logon_guid.clone();
                ecs.edr_process_target_image = f.target_image.clone();
            }
            EventFields::NetworkConnection(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                ecs.destination_ip = f.destination_ip.clone();
                ecs.destination_port = parse_u16(&f.destination_port);
                ecs.source_ip = f.source_ip.clone();
                ecs.source_port = parse_u16(&f.source_port);
                ecs.destination_domain = f.destination_hostname.clone();
                ecs.network_transport = network_transport_from_opcode(opcode);
                if let Some(ip) = ecs.source_ip.as_deref().or(ecs.destination_ip.as_deref()) {
                    ecs.network_type = network_type_from_ip(ip);
                }
                apply_user_fields(&mut ecs, f.user.as_deref());
            }
            EventFields::FileEvent(f) => {
                ecs.file_path = f.target_filename.clone();
                ecs.file_created = f.creation_utc_time.clone();
                ecs.edr_file_previous_created = f.previous_creation_utc_time.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
            }
            EventFields::RegistryEvent(f) => {
                ecs.registry_path = f.target_object.clone();
                if let Some(path) = f.target_object.as_deref() {
                    let (hive, key, value) = split_registry_path(path, f.event_type.as_deref());
                    ecs.registry_hive = hive;
                    ecs.registry_key = key;
                    ecs.registry_value = value;
                }
                ecs.registry_data_strings = f.details.as_ref().map(|value| vec![value.clone()]);
                ecs.edr_registry_event_type = f.event_type.clone();
                ecs.edr_registry_new_name = f.new_name.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
                if let Some(event_type) = &f.event_type {
                    ecs.event_action = Some(event_type.clone());
                }
            }
            EventFields::DnsQuery(f) => {
                ecs.dns_query = f.query_name.clone();
                if let Some(results) = &f.query_results {
                    ecs.dns_answers = Some(vec![DnsAnswer {
                        data: results.clone(),
                    }]);
                    let ips = extract_ips(results);
                    if !ips.is_empty() {
                        ecs.dns_resolved_ip = Some(ips);
                    }
                }
                ecs.dns_response_code = f.query_status.clone();
                ecs.network_protocol = Some("dns".to_string());
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
            }
            EventFields::ImageLoad(f) => {
                ecs.file_path = f.image_loaded.clone();
                ecs.file_original_file_name = f.original_file_name.clone();
                ecs.file_product = f.product.clone();
                ecs.file_description = f.description.clone();
                ecs.file_code_signature_exists = parse_bool(&f.signed);
                ecs.file_code_signature_subject_name = f.signature.clone();
                ecs.dll_path = f.image_loaded.clone();
                ecs.dll_name = f.image_loaded.as_deref().and_then(basename);
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
            }
            EventFields::PowerShellScript(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
                ecs.file_path = f.path.clone();
                ecs.edr_powershell_script_block_text = f.script_block_text.clone();
                ecs.edr_powershell_script_block_id = f.script_block_id.clone();
            }
            EventFields::WmiEvent(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
                ecs.destination_domain = f.destination_hostname.clone();
                ecs.edr_wmi_operation = f.operation.clone();
                ecs.edr_wmi_query = f.query.clone();
                ecs.edr_wmi_namespace = f.event_namespace.clone();
                ecs.edr_wmi_event_type = f.event_type.clone();
                if let Some(operation) = &f.operation {
                    ecs.event_action = Some(operation.clone());
                }
            }
            EventFields::ServiceCreation(f) => {
                ecs.service_name = f.service_name.clone();
                ecs.edr_service_executable = f.service_file_name.clone();
                ecs.edr_service_type = f.service_type.clone();
                ecs.edr_service_start_type = f.start_type.clone();
                ecs.edr_service_account_name = f.account_name.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
            }
            EventFields::TaskCreation(f) => {
                ecs.edr_task_name = f.task_name.clone();
                ecs.edr_task_content = f.task_content.clone();
                ecs.edr_task_user_name = f.user_name.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
            }
            EventFields::PipeEvent(f) => {
                ecs.edr_pipe_name = f.pipe_name.clone();
                ecs.edr_pipe_event_type = f.event_type.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = parse_u64(&f.process_id);
                apply_user_fields(&mut ecs, f.user.as_deref());
                if let Some(event_type) = &f.event_type {
                    ecs.event_action = Some(event_type.clone());
                }
            }
            EventFields::RemoteThread(f) => {
                ecs.process_executable = f.source_image.clone();
                ecs.process_pid = parse_u64(&f.source_process_id);
                ecs.edr_remote_thread_target_pid = parse_u64(&f.target_process_id);
                ecs.edr_remote_thread_target_image = f.target_image.clone();
                ecs.edr_remote_thread_start_address = f.start_address.clone();
                ecs.edr_remote_thread_start_module = f.start_module.clone();
                ecs.edr_remote_thread_start_function = f.start_function.clone();
                apply_user_fields(&mut ecs, f.user.as_deref());
            }
            EventFields::Generic(_) => {
                // Generic events don't have structured field mapping
            }
        }

        if let Some(context) = &alert.event.process_context {
            Self::apply_process_context(&mut ecs, context);
        }

        if ecs.process_name.is_none() {
            ecs.process_name = ecs.process_executable.as_deref().and_then(basename);
        }

        if ecs.process_parent_name.is_none() {
            ecs.process_parent_name = ecs.process_parent_executable.as_deref().and_then(basename);
        }

        if ecs.network_direction.is_none() {
            ecs.network_direction = network_direction_from_category(alert.event.category);
        }

        if ecs.file_name.is_none() {
            if let Some(path) = ecs.file_path.as_deref() {
                ecs.file_name = basename(path);
            }
        }

        if ecs.file_extension.is_none() {
            if let Some(path) = ecs.file_path.as_deref() {
                ecs.file_extension = file_extension_from_path(path);
            }
        }

        let mut related_ips = Vec::new();
        if let Some(ip) = ecs.source_ip.as_ref() {
            related_ips.push(ip.clone());
        }
        if let Some(ip) = ecs.destination_ip.as_ref() {
            related_ips.push(ip.clone());
        }
        if let Some(ips) = ecs.dns_resolved_ip.as_ref() {
            related_ips.extend(ips.iter().cloned());
        }
        related_ips.sort();
        related_ips.dedup();
        if !related_ips.is_empty() {
            ecs.related_ip = Some(related_ips);
        }

        let mut related_users = Vec::new();
        if let Some(user) = ecs.user_name.as_ref() {
            related_users.push(user.clone());
        }
        if let Some(user_id) = ecs.user_id.as_ref() {
            related_users.push(user_id.clone());
        }
        related_users.sort();
        related_users.dedup();
        if !related_users.is_empty() {
            ecs.related_user = Some(related_users);
        }

        ecs
    }
}

impl EcsAlert {
    fn apply_process_context(ecs: &mut EcsAlert, context: &ProcessContext) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AlertSeverity, DetectionEngine, DnsQueryFields, EventCategory, FileEventFields,
        MatchDetails, NormalizedEvent, ProcessContext, ProcessCreationFields, RegistryEventFields,
        ServiceCreationFields,
    };
    use std::collections::HashMap;

    #[test]
    fn test_ecs_process_creation() {
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "Test Rule".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                    command_line: Some("cmd.exe /c whoami".to_string()),
                    process_id: Some("1234".to_string()),
                    parent_image: Some(r"C:\Windows\explorer.exe".to_string()),
                    user: Some("SYSTEM".to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
                    parent_process_id: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    logon_id: None,
                    logon_guid: None,
                }),
                process_context: None,
            },
            match_details: None,
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(ecs.ecs_version, ECS_VERSION);
        assert_eq!(ecs.event_kind, "alert");
        assert_eq!(ecs.event_module, EVENT_MODULE);
        assert_eq!(ecs.event_dataset, "edr.process");
        assert_eq!(ecs.event_provider, EVENT_PROVIDER);
        assert_eq!(ecs.event_category, vec!["process".to_string()]);
        assert_eq!(ecs.event_type, vec!["start".to_string()]);
        assert_eq!(ecs.event_action.as_deref(), Some("process-start"));
        assert_eq!(ecs.event_code.as_deref(), Some("1"));
        assert_eq!(ecs.event_severity, Some(75));
        assert_eq!(ecs.rule_name, "Test Rule");
        assert_eq!(ecs.edr_rule_severity, "High");
        assert_eq!(ecs.edr_rule_engine, "Sigma");
        assert_eq!(
            ecs.process_executable.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(ecs.process_pid, Some(1234));
        assert_eq!(ecs.process_name.as_deref(), Some("cmd.exe"));
        assert_eq!(ecs.user_name.as_deref(), Some("SYSTEM"));
    }

    #[test]
    fn test_ecs_service_creation() {
        let alert = Alert {
            severity: AlertSeverity::Critical,
            rule_name: "Suspicious Service".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Service,
                event_id: 7045,
                event_id_string: "7045".to_string(),
                opcode: 0,
                fields: EventFields::ServiceCreation(ServiceCreationFields {
                    service_name: Some("BackdoorSvc".to_string()),
                    service_file_name: Some(r"C:\Temp\evil.exe".to_string()),
                    service_type: Some("0x10".to_string()),
                    start_type: Some("2".to_string()),
                    account_name: Some("LocalSystem".to_string()),
                    user: Some("Administrator".to_string()),
                    process_id: None,
                    image: None,
                }),
                process_context: None,
            },
            match_details: None,
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(ecs.event_category, vec!["configuration".to_string()]);
        assert_eq!(ecs.event_type, vec!["creation".to_string()]);
        assert_eq!(ecs.service_name, Some("BackdoorSvc".to_string()));
        assert_eq!(
            ecs.edr_service_executable,
            Some(r"C:\Temp\evil.exe".to_string())
        );
        assert_eq!(ecs.edr_rule_severity, "Critical");
        assert_eq!(ecs.event_severity, Some(100));
    }

    #[test]
    fn test_ecs_process_context_fallback() {
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "Context Test".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Service,
                event_id: 7045,
                event_id_string: "7045".to_string(),
                opcode: 0,
                fields: EventFields::ServiceCreation(ServiceCreationFields {
                    service_name: Some("UpdaterSvc".to_string()),
                    service_file_name: Some(r"C:\Temp\updater.exe".to_string()),
                    service_type: None,
                    start_type: None,
                    account_name: None,
                    user: None,
                    process_id: None,
                    image: None,
                }),
                process_context: Some(ProcessContext {
                    image: Some(r"C:\Windows\System32\svchost.exe".to_string()),
                    command_line: Some("svchost.exe -k netsvcs".to_string()),
                    process_id: Some("4321".to_string()),
                    parent_process_id: Some("100".to_string()),
                    parent_image: Some(r"C:\Windows\System32\services.exe".to_string()),
                    parent_command_line: Some("services.exe".to_string()),
                    original_file_name: Some("svchost.exe".to_string()),
                    product: Some("Microsoft Windows".to_string()),
                    description: Some("Host Process".to_string()),
                    current_directory: Some(r"C:\Windows\System32".to_string()),
                    integrity_level: Some("System".to_string()),
                    user: Some(r"NT AUTHORITY\SYSTEM".to_string()),
                    logon_id: Some("0x3e7".to_string()),
                    logon_guid: Some("guid".to_string()),
                }),
            },
            match_details: None,
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(
            ecs.process_command_line,
            Some("svchost.exe -k netsvcs".to_string())
        );
        assert_eq!(
            ecs.process_parent_executable,
            Some(r"C:\Windows\System32\services.exe".to_string())
        );
        assert_eq!(
            ecs.process_original_file_name,
            Some("svchost.exe".to_string())
        );
        assert_eq!(ecs.process_pid, Some(4321));
        assert_eq!(ecs.user_name.as_deref(), Some("SYSTEM"));
        assert_eq!(ecs.user_domain.as_deref(), Some("NT AUTHORITY"));
        assert_eq!(ecs.winlog_logon_id, Some("0x3e7".to_string()));
    }

    #[test]
    fn test_ecs_registry_mapping() {
        let alert = Alert {
            severity: AlertSeverity::Medium,
            rule_name: "Registry Test".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Registry,
                event_id: 13,
                event_id_string: "13".to_string(),
                opcode: 39,
                fields: EventFields::RegistryEvent(RegistryEventFields {
                    target_object: Some(r"HKLM\Software\Test\Value".to_string()),
                    details: Some("DWORD (0x00000001)".to_string()),
                    process_id: Some("42".to_string()),
                    image: Some(r"C:\Windows\System32\reg.exe".to_string()),
                    event_type: Some("SetValue".to_string()),
                    user: Some("SYSTEM".to_string()),
                    new_name: None,
                }),
                process_context: None,
            },
            match_details: None,
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(ecs.registry_hive, Some("HKLM".to_string()));
        assert_eq!(ecs.registry_key, Some(r"Software\Test".to_string()));
        assert_eq!(ecs.registry_value, Some("Value".to_string()));
        assert_eq!(
            ecs.registry_data_strings,
            Some(vec!["DWORD (0x00000001)".to_string()])
        );
        assert_eq!(ecs.event_action, Some("SetValue".to_string()));
    }

    #[test]
    fn test_ecs_dns_mapping() {
        let alert = Alert {
            severity: AlertSeverity::Low,
            rule_name: "DNS Test".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Dns,
                event_id: 22,
                event_id_string: "22".to_string(),
                opcode: 0,
                fields: EventFields::DnsQuery(DnsQueryFields {
                    query_name: Some("example.com".to_string()),
                    query_results: Some("1.1.1.1".to_string()),
                    query_status: Some("NOERROR".to_string()),
                    process_id: None,
                    image: None,
                }),
                process_context: None,
            },
            match_details: None,
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(ecs.event_category, vec!["network".to_string()]);
        assert_eq!(ecs.event_type, vec!["protocol".to_string()]);
        assert_eq!(ecs.network_protocol, Some("dns".to_string()));
        assert_eq!(ecs.network_direction, Some("egress".to_string()));
        assert_eq!(ecs.dns_query, Some("example.com".to_string()));
        let answers = ecs.dns_answers.expect("dns.answers should be set");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, "1.1.1.1");
        assert_eq!(ecs.dns_resolved_ip, Some(vec!["1.1.1.1".to_string()]));
        assert_eq!(ecs.related_ip, Some(vec!["1.1.1.1".to_string()]));
        assert_eq!(ecs.dns_response_code, Some("NOERROR".to_string()));
    }

    #[test]
    fn test_ecs_file_enrichment() {
        let alert = Alert {
            severity: AlertSeverity::Low,
            rule_name: "File Test".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::File,
                event_id: 11,
                event_id_string: "11".to_string(),
                opcode: 64,
                fields: EventFields::FileEvent(FileEventFields {
                    target_filename: Some(r"C:\Users\alice\evil.ps1".to_string()),
                    process_id: Some("777".to_string()),
                    image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                    creation_utc_time: Some("2026-01-06T00:00:00Z".to_string()),
                    previous_creation_utc_time: None,
                    user: Some("ALICE".to_string()),
                }),
                process_context: None,
            },
            match_details: None,
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(ecs.event_dataset, "edr.file");
        assert_eq!(ecs.file_name.as_deref(), Some("evil.ps1"));
        assert_eq!(ecs.file_extension.as_deref(), Some("ps1"));
        assert_eq!(ecs.related_user, Some(vec!["ALICE".to_string()]));
    }

    #[test]
    fn test_ecs_match_details_serialization() {
        let alert = Alert {
            severity: AlertSeverity::Low,
            rule_name: "Match Details".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-02-04T00:00:00Z".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::Generic(HashMap::new()),
                process_context: None,
            },
            match_details: Some(MatchDetails {
                summary: "condition matched: selection1".to_string(),
                sigma: None,
                yara: None,
            }),
        };

        let ecs = EcsAlert::from(&alert);
        let json = serde_json::to_value(&ecs).unwrap();
        let match_obj = json.get("edr.match").unwrap();
        assert_eq!(
            match_obj.get("summary").unwrap(),
            "condition matched: selection1"
        );
    }
}
