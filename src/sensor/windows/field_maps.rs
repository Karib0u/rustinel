//! ETW to Sigma field name mappings.

use std::collections::HashMap;
use std::sync::LazyLock;

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
        ("Details", "ValueName"),
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
