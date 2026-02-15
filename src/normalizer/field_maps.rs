//! ETW to Sigma field name mappings
//!
//! Based on YAMAGoya's CategoryFieldMapping.
//! Maps kernel ETW property names to Sigma/Sysmon standard field names.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Field mapping for a specific Sigma category
pub struct FieldMapping {
    /// Maps Sigma field name -> ETW property name
    pub sigma_to_etw: HashMap<&'static str, &'static str>,
}

impl FieldMapping {
    /// Create a new field mapping from pairs
    pub fn new(pairs: &[(&'static str, &'static str)]) -> Self {
        Self {
            sigma_to_etw: pairs.iter().copied().collect(),
        }
    }

    /// Get ETW property name for a Sigma field
    pub fn get_etw_field(&self, sigma_field: &str) -> Option<&'static str> {
        self.sigma_to_etw.get(sigma_field).copied()
    }

    /// Get ETW property name or return the sigma field name as default
    #[allow(dead_code)]
    pub fn get_etw_field_or_default<'a>(&self, sigma_field: &'a str) -> &'a str {
        self.sigma_to_etw
            .get(sigma_field)
            .copied()
            .unwrap_or(sigma_field)
    }
}

// ============================================================================
// Static Field Mappings (LazyLock for zero-allocation access)
// ============================================================================
// PERFORMANCE: These maps are initialized once and reused for all events
// Eliminates 5,000+ HashMap allocations/sec on hot path

/// Process creation/access field mappings (process_creation, process_access)
static PROCESS_CREATION_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("Image", "ImageName"),
        ("OriginalFileName", "OriginalFileName"),
        ("TargetImage", "ImageName"),
        ("CommandLine", "CommandLine"),
        ("ProcessId", "ProcessID"),
        ("ParentProcessId", "ParentProcessID"),
        ("ParentImage", "ParentImageName"),
        ("ParentCommandLine", "ParentCommandLine"),
        ("CurrentDirectory", "CurrentDirectory"),
        ("IntegrityLevel", "IntegrityLevel"),
        ("User", "UserName"),
        ("LogonId", "LogonID"),
        ("LogonGuid", "LogonGUID"),
    ])
});

pub fn process_creation_mappings() -> &'static FieldMapping {
    &PROCESS_CREATION_MAP
}

/// File access field mappings (file_access)
static FILE_ACCESS_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("TargetFilename", "FileName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("CreationUtcTime", "CreationTime"),
        ("PreviousCreationUtcTime", "PreviousCreationTime"),
        ("User", "UserName"),
    ])
});

#[allow(dead_code)]
pub fn file_access_mappings() -> &'static FieldMapping {
    &FILE_ACCESS_MAP
}

/// File delete field mappings (file_delete)
static FILE_DELETE_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("TargetFilename", "FileName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("User", "UserName"),
    ])
});

#[allow(dead_code)]
pub fn file_delete_mappings() -> &'static FieldMapping {
    &FILE_DELETE_MAP
}

/// File event field mappings (file_event)
static FILE_EVENT_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("TargetFilename", "FileName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("CreationUtcTime", "CreationTime"),
        ("User", "UserName"),
    ])
});

pub fn file_event_mappings() -> &'static FieldMapping {
    &FILE_EVENT_MAP
}

/// Registry event field mappings (registry_event)
/// Note: Uses KeyName for TargetObject (differs from add/delete/set)
static REGISTRY_EVENT_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("Details", "ValueName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("EventType", "EventType"),
        ("User", "UserName"),
        ("TargetObject", "KeyName"),
        ("NewName", "NewName"),
    ])
});

#[allow(dead_code)]
pub fn registry_event_mappings() -> &'static FieldMapping {
    &REGISTRY_EVENT_MAP
}

/// Registry add/delete/set field mappings (registry_add, registry_delete, registry_set)
/// Note: Uses RelativeName for TargetObject
static REGISTRY_MODIFY_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("TargetObject", "RelativeName"),
        ("Details", "ValueName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
        ("User", "UserName"),
    ])
});

pub fn registry_modify_mappings() -> &'static FieldMapping {
    &REGISTRY_MODIFY_MAP
}

/// DNS query field mappings (dns_query)
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

/// Network connection field mappings (network_connection)
/// Note: IP addresses need conversion from binary to string
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

/// PowerShell script field mappings (ps_script)
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

/// Image load field mappings (image_load)
/// Note: Image maps to ParentImageName (the process loading the DLL)
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

/// Remote thread creation field mappings (create_remote_thread)
static REMOTE_THREAD_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("SourceProcessId", "ProcessID"),
        ("SourceImage", "ImageName"),
        ("TargetProcessId", "TargetProcessId"),
        ("TargetImage", "TargetImage"),
        ("StartAddress", "StartAddress"),
        ("StartModule", "StartModule"),
        ("StartFunction", "StartFunction"),
        ("User", "UserName"),
    ])
});

#[allow(dead_code)]
pub fn remote_thread_mappings() -> &'static FieldMapping {
    &REMOTE_THREAD_MAP
}

/// WMI event field mappings (wmi_event)
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

/// Service creation field mappings
/// Maps Windows Event ID 7045 (Service Control Manager)
static SERVICE_CREATION_MAP: LazyLock<FieldMapping> = LazyLock::new(|| {
    FieldMapping::new(&[
        ("ServiceName", "ServiceName"),
        ("ServiceFileName", "ImagePath"),
        ("ServiceType", "ServiceType"),
        ("StartType", "StartType"),
        ("AccountName", "AccountName"),
        ("User", "UserName"),
        ("ProcessId", "ProcessID"),
        ("Image", "ImageName"),
    ])
});

pub fn service_creation_mappings() -> &'static FieldMapping {
    &SERVICE_CREATION_MAP
}

/// Task scheduler field mappings
/// Maps Windows Event ID 106 (Task Registered)
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
    fn test_process_creation_mappings() {
        let mappings = process_creation_mappings();
        assert_eq!(mappings.get_etw_field("Image"), Some("ImageName"));
        assert_eq!(mappings.get_etw_field("ProcessId"), Some("ProcessID"));
        assert_eq!(
            mappings.get_etw_field("ParentImage"),
            Some("ParentImageName")
        );
    }

    #[test]
    fn test_network_connection_mappings() {
        let mappings = network_connection_mappings();
        assert_eq!(mappings.get_etw_field("DestinationIp"), Some("daddr"));
        assert_eq!(mappings.get_etw_field("SourceIp"), Some("saddr"));
        assert_eq!(mappings.get_etw_field("DestinationPort"), Some("dport"));
    }

    #[test]
    fn test_registry_event_vs_modify() {
        let event_mappings = registry_event_mappings();
        let modify_mappings = registry_modify_mappings();

        // registry_event uses KeyName for TargetObject
        assert_eq!(
            event_mappings.get_etw_field("TargetObject"),
            Some("KeyName")
        );

        // registry_add/delete/set use RelativeName for TargetObject
        assert_eq!(
            modify_mappings.get_etw_field("TargetObject"),
            Some("RelativeName")
        );
    }

    #[test]
    fn test_image_load_parent_mapping() {
        let mappings = image_load_mappings();
        // Image maps to ParentImageName for image load events
        assert_eq!(mappings.get_etw_field("Image"), Some("ParentImageName"));
        assert_eq!(mappings.get_etw_field("ImageLoaded"), Some("ImageName"));
    }

    #[test]
    fn test_default_fallback() {
        let mappings = process_creation_mappings();
        // Field not in mapping should return the input as default
        assert_eq!(
            mappings.get_etw_field_or_default("UnknownField"),
            "UnknownField"
        );
        // Field in mapping should return mapped value
        assert_eq!(mappings.get_etw_field_or_default("Image"), "ImageName");
    }
}
