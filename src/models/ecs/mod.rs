//! ECS (Elastic Common Schema) alert mapping
//! https://github.com/elastic/ecs/tree/main
//! This module provides a translation layer between internal Alert structures
//! and the standardized ECS format expected by SIEM systems like Elasticsearch,
//! Splunk, and other log aggregation platforms.

mod alert;
mod event;
mod helpers;
mod network;
mod registry;
mod user;

pub use alert::{DnsAnswer, EcsAlert};

use crate::models::{Alert, EventFields};
use event::{
    alert_severity_to_event_severity, ecs_event_action, ecs_event_category, ecs_event_type,
    event_dataset, event_provider, host_os_family, host_os_type, network_direction_from_category,
};
use helpers::{basename, file_extension_from_path, parse_bool, parse_u16, parse_u64};
use network::{extract_ips, network_transport_from_opcode, network_type_from_ip};
use registry::split_registry_path;
use user::apply_user_fields;

const ECS_VERSION: &str = "9.3.0";
const EVENT_MODULE: &str = "edr";

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
            event_provider: event_provider(alert),
            host_os_type: host_os_type(alert.event.platform),
            host_os_family: host_os_family(alert.event.platform),
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
                ecs.network_transport = f
                    .protocol
                    .clone()
                    .or_else(|| network_transport_from_opcode(opcode));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AlertSeverity, DetectionEngine, DnsQueryFields, EventCategory, FileEventFields,
        MatchDetails, NormalizedEvent, ProcessContext, ProcessCreationFields, RegistryEventFields,
        ServiceCreationFields,
    };
    use crate::sensor::Platform;
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
                platform: Platform::Windows,
                provider: "etw".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                    command_line: Some("cmd.exe /c whoami".to_string()),
                    process_id: Some("1234".to_string()),
                    process_start_time: None,
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
        assert_eq!(ecs.event_provider, "etw");
        assert_eq!(ecs.host_os_type, "windows");
        assert_eq!(ecs.host_os_family, "windows");
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
                platform: Platform::Windows,
                provider: "etw".to_string(),
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
                platform: Platform::Windows,
                provider: "etw".to_string(),
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
                    process_start_time: None,
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
                platform: Platform::Windows,
                provider: "etw".to_string(),
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
                platform: Platform::Linux,
                provider: "ebpf".to_string(),
                category: EventCategory::Dns,
                event_id: 22,
                event_id_string: "22".to_string(),
                opcode: 0,
                fields: EventFields::DnsQuery(DnsQueryFields {
                    query_name: Some("example.com".to_string()),
                    query_results: Some("1.1.1.1".to_string()),
                    record_type: Some("A".to_string()),
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
        assert_eq!(ecs.event_provider, "ebpf");
        assert_eq!(ecs.host_os_type, "linux");
        assert_eq!(ecs.host_os_family, "linux");
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
                platform: Platform::Windows,
                provider: "etw".to_string(),
                category: EventCategory::File,
                event_id: 11,
                event_id_string: "11".to_string(),
                opcode: 64,
                fields: EventFields::FileEvent(FileEventFields {
                    source_filename: None,
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
                platform: Platform::Windows,
                provider: "etw".to_string(),
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
