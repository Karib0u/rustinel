//! ETW to Sigma field name mappings.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::registry_value_data::CAPTURED_DATA_PROPERTY;

/// Field mapping for a specific Sigma category.
pub struct FieldMapping {
    /// Maps Sigma field name -> ETW property name.
    pub sigma_to_etw: HashMap<&'static str, &'static str>,
}

impl FieldMapping {
    pub fn new(pairs: &[(&'static str, &'static str)]) -> Self {
        Self {
            sigma_to_etw: pairs.iter().copied().collect(),
        }
    }

    pub fn get_etw_field(&self, sigma_field: &str) -> Option<&'static str> {
        self.sigma_to_etw.get(sigma_field).copied()
    }

    #[allow(dead_code)]
    pub fn get_etw_field_or_default<'a>(&self, sigma_field: &'a str) -> &'a str {
        self.sigma_to_etw
            .get(sigma_field)
            .copied()
            .unwrap_or(sigma_field)
    }
}

static PROCESS_CREATION_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("Image", "ImageName"),
        ("OriginalFileName", "OriginalFileName"),
        ("CommandLine", "CommandLine"),
        ("ProcessId", "ProcessID"),
        ("ParentProcessId", "ParentProcessID"),
        ("ParentImage", "ParentImageName"),
        ("ParentCommandLine", "ParentCommandLine"),
        ("CurrentDirectory", "CurrentDirectory"),
        // Kernel-Process declares no `IntegrityLevel` property; the level is
        // the `MandatoryLabel` SID on the process start template, decoded by
        // `integrity_level_from_sid` (#294). `LogonID` and `LogonGUID` were
        // mapped here too and exist on no event of this provider, so they are
        // not mapped at all rather than mapped to nothing.
        ("IntegrityLevel", "MandatoryLabel"),
        ("User", "UserName"),
    ])
});

pub fn process_creation_mappings() -> &'static FieldMapping {
    &PROCESS_CREATION_MAP
}

static FILE_EVENT_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("TargetFilename", "FileName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("CreationUtcTime", "CreationTime"),
        ("PreviousCreationUtcTime", "PreviousCreationTime"),
        ("User", "UserName"),
    ])
});

pub fn file_event_mappings() -> &'static FieldMapping {
    &FILE_EVENT_MAP
}

static REGISTRY_EVENT_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        // Sysmon Event ID 13 defines `Details` as the value data, not its
        // name. When `CapturedData` is unavailable, `Details` stays absent.
        ("Details", CAPTURED_DATA_PROPERTY),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("EventType", "EventType"),
        ("User", "UserName"),
        ("NewName", "NewName"),
    ])
});

pub fn registry_event_mappings() -> &'static FieldMapping {
    &REGISTRY_EVENT_MAP
}

static DNS_QUERY_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("QueryName", "QueryName"),
        ("QueryResults", "QueryResults"),
        ("QueryStatus", "QueryStatus"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
    ])
});

pub fn dns_query_mappings() -> &'static FieldMapping {
    &DNS_QUERY_MAP
}

static NETWORK_CONNECTION_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("DestinationIp", "daddr"),
        ("SourceIp", "saddr"),
        ("DestinationPort", "dport"),
        ("SourcePort", "sport"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("User", "UserName"),
        ("DestinationHostname", "DestinationHostname"),
    ])
});

pub fn network_connection_mappings() -> &'static FieldMapping {
    &NETWORK_CONNECTION_MAP
}

static POWERSHELL_SCRIPT_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("ScriptBlockText", "ScriptBlockText"),
        ("ScriptBlockId", "ScriptBlockId"),
        ("Path", "Path"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("User", "UserName"),
    ])
});

pub fn powershell_script_mappings() -> &'static FieldMapping {
    &POWERSHELL_SCRIPT_MAP
}

/// Module logging (event 4103) has its own template: `ContextInfo`,
/// `UserData` and `Payload`. `UserData` is not mapped because no `ps_module`
/// rule reads it and it is empty on every event observed.
static POWERSHELL_MODULE_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("ContextInfo", "ContextInfo"),
        ("Payload", "Payload"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("User", "UserName"),
    ])
});

pub fn powershell_module_mappings() -> &'static FieldMapping {
    &POWERSHELL_MODULE_MAP
}

static IMAGE_LOAD_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("ImageLoaded", "ImageName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ParentImageName"),
        ("OriginalFileName", "OriginalFileName"),
        ("Signed", "Signed"),
        ("Signature", "Signature"),
        ("User", "UserName"),
    ])
});

pub fn image_load_mappings() -> &'static FieldMapping {
    &IMAGE_LOAD_MAP
}

static WMI_EVENT_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("Operation", "Operation"),
        ("User", "User"),
        ("Query", "Query"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("EventNamespace", "Namespace"),
        ("EventType", "EventType"),
        ("DestinationHostname", "DestinationHostname"),
    ])
});

pub fn wmi_event_mappings() -> &'static FieldMapping {
    &WMI_EVENT_MAP
}

static TASK_CREATION_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("TaskName", "TaskName"),
        ("TaskContent", "TaskContent"),
        ("UserName", "UserContext"),
        ("User", "User"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
    ])
});

pub fn task_creation_mappings() -> &'static FieldMapping {
    &TASK_CREATION_MAP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_creation_reads_the_properties_kernel_process_declares() {
        let mappings = process_creation_mappings();

        // `IntegrityLevel` was mapped to a property of the same name, which
        // Microsoft-Windows-Kernel-Process does not declare, so it was always
        // empty (#294). The level lives on `ProcessStart` as a SID.
        assert_eq!(
            mappings.get_etw_field("IntegrityLevel"),
            Some("MandatoryLabel")
        );

        // Mapped to `LogonID`/`LogonGUID`, which this provider declares on no
        // event. An entry here would only advertise a field nothing can fill.
        assert_eq!(mappings.get_etw_field("LogonId"), None);
        assert_eq!(mappings.get_etw_field("LogonGuid"), None);

        // Process creation has no target process. Mapping this to ImageName
        // duplicated Image and gave TargetImage a meaning it does not have.
        assert_eq!(mappings.get_etw_field("Image"), Some("ImageName"));
        assert_eq!(mappings.get_etw_field("TargetImage"), None);
    }

    #[test]
    fn powershell_module_mapping_matches_event_4103_template() {
        let mappings = powershell_module_mappings();

        assert_eq!(mappings.get_etw_field("ContextInfo"), Some("ContextInfo"));
        assert_eq!(mappings.get_etw_field("Payload"), Some("Payload"));
        assert_eq!(mappings.get_etw_field("ProcessId"), Some("ProcessID"));
        assert_eq!(mappings.get_etw_field("Image"), Some("ImageName"));
        assert_eq!(mappings.get_etw_field("User"), Some("UserName"));
        assert_eq!(mappings.get_etw_field("UserData"), None);
    }
}
