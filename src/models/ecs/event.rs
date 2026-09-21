use super::EVENT_MODULE;
use crate::models::{Alert, AlertSeverity, EventCategory};
use crate::sensor::Platform;

pub(super) fn alert_severity_to_event_severity(severity: AlertSeverity) -> u8 {
    match severity {
        AlertSeverity::Informational => 1,
        AlertSeverity::Low => 25,
        AlertSeverity::Medium => 50,
        AlertSeverity::High => 75,
        AlertSeverity::Critical => 100,
    }
}

pub(super) fn ecs_event_category(category: EventCategory, event_id: u16) -> Vec<String> {
    match category {
        EventCategory::Process => vec!["process".to_string()],
        EventCategory::Network => vec!["network".to_string()],
        EventCategory::File => vec!["file".to_string()],
        EventCategory::Registry => vec!["registry".to_string()],
        EventCategory::Dns => vec!["network".to_string()],
        EventCategory::ImageLoad => vec!["library".to_string()],
        EventCategory::Scripting => vec!["process".to_string()],
        EventCategory::PowerShellModule => vec!["process".to_string()],
        EventCategory::PowerShellClassicStart => vec!["process".to_string()],
        EventCategory::Wmi => vec!["api".to_string()],
        EventCategory::Service => vec!["configuration".to_string()],
        EventCategory::Task => vec!["configuration".to_string()],
        // The Security channel is one logsource carrying unrelated event
        // families, so its ECS mapping is driven by the audit event ID rather
        // than by the category. Object-access events name the kind of object
        // they touched in `ObjectType`, which the field mapper reads to refine
        // this default.
        EventCategory::Security => strings(security_event_shape(event_id).category),
    }
}

/// ECS classification of one Security audit event ID.
struct SecurityEventShape {
    category: &'static [&'static str],
    kind: &'static [&'static str],
    action: &'static str,
}

const fn shape(
    category: &'static [&'static str],
    kind: &'static [&'static str],
    action: &'static str,
) -> SecurityEventShape {
    SecurityEventShape {
        category,
        kind,
        action,
    }
}

/// One row per collected Security event ID, so an ID's category, type and
/// action are reviewed together. Action names follow Winlogbeat's Security
/// module where it has one.
const fn security_event_shape(event_id: u16) -> SecurityEventShape {
    const AUTHENTICATION: &[&str] = &["authentication"];
    const CONFIGURATION: &[&str] = &["configuration"];
    const IAM: &[&str] = &["iam"];
    const NETWORK: &[&str] = &["network"];
    match event_id {
        4624 => shape(&["authentication", "session"], &["start"], "logged-in"),
        4625 => shape(AUTHENTICATION, &["start"], "logon-failed"),
        4648 => shape(AUTHENTICATION, &["start"], "logged-in-explicit"),
        4771 => shape(AUTHENTICATION, &["start"], "kerberos-preauth-failed"),
        4776 => shape(AUTHENTICATION, &["start"], "credential-validated"),
        4656 => shape(&["file"], &["access"], "handle-requested"),
        4663 => shape(&["file"], &["access"], "object-access-attempted"),
        5145 => shape(&["file"], &["access"], "network-share-object-checked"),
        4657 => shape(&["registry"], &["change"], "registry-value-modified"),
        4697 => shape(CONFIGURATION, &["creation"], "service-installed"),
        4698 => shape(CONFIGURATION, &["creation"], "scheduled-task-created"),
        4699 => shape(CONFIGURATION, &["deletion"], "scheduled-task-deleted"),
        4700 => shape(CONFIGURATION, &["change"], "scheduled-task-enabled"),
        4701 => shape(CONFIGURATION, &["change"], "scheduled-task-disabled"),
        4702 => shape(CONFIGURATION, &["change"], "scheduled-task-updated"),
        1102 => shape(CONFIGURATION, &["deletion"], "audit-log-cleared"),
        4719 => shape(CONFIGURATION, &["change"], "changed-audit-config"),
        4817 => shape(CONFIGURATION, &["change"], "object-audit-settings-changed"),
        5447 => shape(
            CONFIGURATION,
            &["change"],
            "filtering-platform-filter-changed",
        ),
        4720 => shape(IAM, &["user", "creation"], "added-user-account"),
        4722 => shape(IAM, &["user", "change"], "enabled-user-account"),
        4724 => shape(IAM, &["user", "change"], "reset-password"),
        4726 => shape(IAM, &["user", "deletion"], "deleted-user-account"),
        4738 => shape(IAM, &["user", "change"], "modified-user-account"),
        4781 => shape(IAM, &["user", "change"], "renamed-user-account"),
        4794 => shape(IAM, &["user", "change"], "set-dsrm-password"),
        4765 => shape(IAM, &["user", "change"], "added-sid-history"),
        4766 => shape(IAM, &["user", "change"], "failed-sid-history-addition"),
        4728 | 4732 | 4756 => shape(IAM, &["group", "change"], "added-member-to-group"),
        4741 => shape(IAM, &["admin", "creation"], "added-computer-account"),
        4743 => shape(IAM, &["admin", "deletion"], "deleted-computer-account"),
        5136 => shape(IAM, &["change"], "directory-service-object-modified"),
        5156 => shape(
            NETWORK,
            &["connection", "allowed"],
            "network-connection-allowed",
        ),
        5157 => shape(
            NETWORK,
            &["connection", "denied"],
            "network-connection-blocked",
        ),
        5152 => shape(NETWORK, &["denied"], "packet-dropped"),
        6416 => shape(&["host"], &["info"], "device-recognized"),
        _ => shape(&["file"], &["access"], "security-audit"),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// ECS `event.category` for an object-access audit event, from its `ObjectType`.
///
/// Windows names the object kind rather than the ECS category, and audits the
/// same event ID over files, registry keys and process tokens alike.
pub(super) fn ecs_object_access_category(object_type: Option<&str>) -> Vec<String> {
    let category = match object_type {
        Some("Key") => "registry",
        Some("Process") | Some("Thread") | Some("Token") => "process",
        Some("SAM")
        | Some("SAM_DOMAIN")
        | Some("SAM_USER")
        | Some("SAM_GROUP")
        | Some("SAM_ALIAS")
        | Some("SAM_SERVER")
        | Some("directoryService") => "iam",
        _ => "file",
    };
    vec![category.to_string()]
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
        EventCategory::PowerShellModule => vec!["info".to_string()],
        EventCategory::PowerShellClassicStart => vec!["start".to_string()],
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
        EventCategory::Security => strings(security_event_shape(event_id).kind),
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
        EventCategory::PowerShellModule => "powershell-module",
        EventCategory::PowerShellClassicStart => "powershell-classic-start",
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
        EventCategory::Security => security_event_shape(event_id).action,
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
        EventCategory::PowerShellModule => "powershell_module",
        EventCategory::PowerShellClassicStart => "powershell_classic_start",
        EventCategory::Wmi => "wmi",
        EventCategory::Service => "service",
        EventCategory::Task => "task",
        EventCategory::Security => "security",
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
        Platform::MacOS => "macos".to_string(),
    }
}

pub(super) fn host_os_family(platform: Platform) -> String {
    match platform {
        Platform::Windows => "windows".to_string(),
        Platform::Linux => "linux".to_string(),
        // ECS uses the "darwin" OS family for macOS.
        Platform::MacOS => "darwin".to_string(),
    }
}

/// ECS `network.direction` for a category, used only when the event itself does
/// not say which way the connection went.
///
/// Network and DNS events default to `egress` because that is what every sensor
/// that cannot report a direction is actually capturing: an outbound `connect()`
/// or a query this host sent.
pub(super) fn network_direction_from_category(category: EventCategory) -> Option<String> {
    match category {
        EventCategory::Network | EventCategory::Dns => Some("egress".to_string()),
        _ => None,
    }
}

/// ECS `network.direction` for an event that carries Sysmon's `Initiated`.
///
/// This is the authoritative form and overrides the category default: an
/// accepted connection is `ingress`, and reporting it as `egress` would put a
/// Windows inbound connection on the wrong side of every direction-aware SIEM
/// query.
pub(super) fn network_direction_from_initiated(initiated: bool) -> String {
    if initiated {
        "egress".to_string()
    } else {
        "ingress".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{host_os_family, host_os_type};
    use crate::sensor::Platform;

    #[test]
    fn host_os_maps_macos_to_darwin_family() {
        assert_eq!(host_os_type(Platform::MacOS), "macos");
        assert_eq!(host_os_family(Platform::MacOS), "darwin");
    }
}
