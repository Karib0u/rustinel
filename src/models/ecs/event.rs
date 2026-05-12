use super::EVENT_MODULE;
use crate::models::{Alert, AlertSeverity, EventCategory};
use crate::sensor::Platform;

pub(super) fn alert_severity_to_event_severity(severity: AlertSeverity) -> u8 {
    match severity {
        AlertSeverity::Low => 25,
        AlertSeverity::Medium => 50,
        AlertSeverity::High => 75,
        AlertSeverity::Critical => 100,
    }
}

pub(super) fn ecs_event_category(category: EventCategory) -> Vec<String> {
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
    }
}

pub(super) fn ecs_event_type(category: EventCategory, opcode: u8, event_id: u16) -> Vec<String> {
    match category {
        EventCategory::Process => match opcode {
            1 => vec!["start".to_string()],
            2 => vec!["end".to_string()],
            _ => vec!["info".to_string()],
        },
        EventCategory::Network => vec!["connection".to_string()],
        EventCategory::File => match opcode {
            64 => vec!["creation".to_string()],
            70 | 72 => vec!["deletion".to_string()],
            71 => vec!["change".to_string()],
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
    }
}

pub(super) fn ecs_event_action(
    category: EventCategory,
    opcode: u8,
    event_id: u16,
) -> Option<String> {
    let action = match category {
        EventCategory::Process => match opcode {
            1 => "process-start",
            2 => "process-end",
            _ => "process-info",
        },
        EventCategory::Network => "network-connection",
        EventCategory::File => match opcode {
            64 => "file-create",
            70 | 72 => "file-delete",
            71 => "file-rename",
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
    };
    Some(action.to_string())
}

pub(super) fn event_dataset(category: EventCategory) -> String {
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
    };
    format!("{}.{}", EVENT_MODULE, suffix)
}

pub(super) fn event_provider(alert: &Alert) -> String {
    alert.event.provider.clone()
}

pub(super) fn host_os_type(platform: Platform) -> String {
    match platform {
        Platform::Windows => "windows".to_string(),
        Platform::Linux => "linux".to_string(),
    }
}

pub(super) fn host_os_family(platform: Platform) -> String {
    match platform {
        Platform::Windows => "windows".to_string(),
        Platform::Linux => "linux".to_string(),
    }
}

pub(super) fn network_direction_from_category(category: EventCategory) -> Option<String> {
    match category {
        EventCategory::Network | EventCategory::Dns => Some("egress".to_string()),
        _ => None,
    }
}
