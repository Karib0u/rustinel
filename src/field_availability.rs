//! Machine-readable field availability for every sensor event shape.
//!
//! This is the source of truth for field-level compatibility. Keep limitations
//! here rather than in a decoder comment or a hand-maintained documentation
//! list: `doctor`, the generated compatibility baseline, and the generated
//! documentation all consume [`FIELD_AVAILABILITY`].

use semver::Version;
use serde::Serialize;

use crate::models::{EventCategory, EventFields, NormalizedEvent};
use crate::sensor::{Platform, SensorAction};

pub const SCHEMA_VERSION: u16 = 2;

/// The field had its current availability at or before the oldest supported
/// Rustinel release. Keeping this explicit at every declaration prevents a new
/// capability from silently acquiring a version floor.
const SINCE_BASELINE: Option<&str> = None;
const SINCE_1_1_0: Option<&str> = Some("1.1.0");
const SINCE_1_4_0: Option<&str> = Some("1.4.0");
const SINCE_1_4_1: Option<&str> = Some("1.4.1");
const SINCE_1_6_0: Option<&str> = Some("1.6.0");
const SINCE_1_7_0: Option<&str> = Some("1.7.0");
/// Linux DNS response decoding (#439).
///
/// TODO(release): set to the release that ships it. `validate_since_versions`
/// rejects a version newer than the crate, so this cannot name the next
/// release before the version bump.
const SINCE_DNS_RESPONSES: Option<&str> = Some("1.7.1");
/// Additional Windows Security audit event families (#479).
///
/// TODO(release): set to the release that ships it, as for
/// [`SINCE_DNS_RESPONSES`].
const SINCE_SECURITY_FAMILIES: Option<&str> = Some("1.7.1");
/// Windows `Hashes` and `Imphash` from artifact resolution (#319).
///
/// TODO(release): set to the release that ships it, as for
/// [`SINCE_DNS_RESPONSES`].
const SINCE_ARTIFACT_HASHES: Option<&str> = Some("1.7.1");
/// Linux container context (#148).
///
/// TODO(release): set to the release that ships it, as for
/// [`SINCE_DNS_RESPONSES`].
const SINCE_CONTAINER_CONTEXT: Option<&str> = Some("1.7.1");
/// Identity-checked Linux process path enrichment (#231).
///
/// TODO(release): set to the release that ships it, as for
/// [`SINCE_DNS_RESPONSES`].
const SINCE_PROCESS_PATH_ENRICHMENT: Option<&str> = Some("1.7.1");
/// Windows process identity measured by classic-record correlation (#480).
///
/// TODO(release): set to the release that ships it, as for
/// [`SINCE_DNS_RESPONSES`].
const SINCE_PROCESS_USER: Option<&str> = Some("1.7.1");
/// Native Windows Event Log or ETW manifest channel (#543).
const SINCE_WINDOWS_CHANNEL: Option<&str> = Some("1.7.1");

/// Whether a field can be present for one precise sensor event shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "availability", content = "reason", rename_all = "snake_case")]
pub enum Availability {
    /// Every emitted event of this shape carries the field.
    Always,
    /// The field is populated only when the source or bounded enrichment can
    /// supply it. The reason describes that condition.
    Conditional(&'static str),
    /// No event of this shape can carry the field.
    Never(&'static str),
}

impl Availability {
    pub const fn status(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Conditional(_) => "conditional",
            Self::Never(_) => "never",
        }
    }

    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Always => None,
            Self::Conditional(reason) | Self::Never(reason) => Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FieldContract {
    pub field: &'static str,
    /// First released version where the field reached its current
    /// availability, or `None` when that predates the supported baseline.
    pub since: Option<&'static str>,
    /// Exact value for invariant fields such as a native Windows channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<&'static str>,
    #[serde(flatten)]
    pub availability: Availability,
}

/// Availability for one `(platform, category, event id/action, provider)` key.
///
/// `provider` is the stable provider written to [`NormalizedEvent`]. `source`
/// names the native producer so ETW and Event Log contracts remain reviewable
/// without leaking provider-specific identifiers into the shared event model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventFieldContract {
    pub platform: Platform,
    pub category: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SensorAction>,
    pub provider: &'static str,
    pub source: &'static str,
    pub fields: &'static [FieldContract],
}

const fn always(field: &'static str, since: Option<&'static str>) -> FieldContract {
    FieldContract {
        field,
        since,
        value: None,
        availability: Availability::Always,
    }
}

const fn always_value(
    field: &'static str,
    since: Option<&'static str>,
    value: &'static str,
) -> FieldContract {
    FieldContract {
        field,
        since,
        value: Some(value),
        availability: Availability::Always,
    }
}

const fn conditional(
    field: &'static str,
    since: Option<&'static str>,
    reason: &'static str,
) -> FieldContract {
    FieldContract {
        field,
        since,
        value: None,
        availability: Availability::Conditional(reason),
    }
}

const fn never(
    field: &'static str,
    since: Option<&'static str>,
    reason: &'static str,
) -> FieldContract {
    FieldContract {
        field,
        since,
        value: None,
        availability: Availability::Never(reason),
    }
}

const WINDOWS_PROCESS: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-Kernel-Process/Analytic",
    ),
    always("ProcessId", SINCE_BASELINE),
    conditional(
        "Image",
        SINCE_BASELINE,
        "the provider may omit the image path",
    ),
    conditional(
        "CommandLine",
        SINCE_BASELINE,
        "queried from the live process and lost if it exits first",
    ),
    conditional(
        "ProcessStartTime",
        SINCE_BASELINE,
        "the event template may omit the native creation time",
    ),
    conditional(
        "ParentProcessId",
        SINCE_BASELINE,
        "the event template may omit parent identity",
    ),
    conditional(
        "ParentImage",
        SINCE_BASELINE,
        "present in the event or derived from the process cache",
    ),
    conditional(
        "ParentCommandLine",
        SINCE_BASELINE,
        "derived from the process cache when the parent is still known",
    ),
    conditional(
        "IntegrityLevel",
        SINCE_1_4_1,
        "available only on process-start templates with a MandatoryLabel SID",
    ),
    conditional(
        "OriginalFileName",
        SINCE_BASELINE,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "Product",
        SINCE_BASELINE,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "Description",
        SINCE_BASELINE,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "Company",
        SINCE_1_4_1,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "FileVersion",
        SINCE_1_4_1,
        "PE version-resource enrichment succeeds",
    ),
    never(
        "CgroupId",
        SINCE_BASELINE,
        "Windows process events do not have a Linux kernel cgroup identifier",
    ),
    conditional(
        "User",
        SINCE_PROCESS_USER,
        "the classic process record is correlated; the measured SID is retained or resolves to an account name",
    ),
    never(
        "CurrentDirectory",
        SINCE_BASELINE,
        "Microsoft-Windows-Kernel-Process does not expose the working directory",
    ),
    never(
        "TargetImage",
        SINCE_BASELINE,
        "a process-creation event has no target process",
    ),
    conditional(
        "Hashes",
        SINCE_ARTIFACT_HASHES,
        "computed from the image file after admission when a loaded rule selects on it, and seen only by those rules",
    ),
    conditional(
        "Imphash",
        SINCE_ARTIFACT_HASHES,
        "computed from the image file's import table after admission when a loaded rule selects on it, and seen only by those rules",
    ),
];

const WINDOWS_IMAGE_LOAD: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-Kernel-Process/Analytic",
    ),
    conditional(
        "ImageLoaded",
        SINCE_BASELINE,
        "the provider may omit the loaded image path",
    ),
    conditional(
        "ProcessId",
        SINCE_BASELINE,
        "the provider may omit process identity",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "the provider may omit the loading process image",
    ),
    conditional(
        "OriginalFileName",
        SINCE_BASELINE,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "Product",
        SINCE_BASELINE,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "Description",
        SINCE_BASELINE,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "Company",
        SINCE_1_4_1,
        "PE version-resource enrichment succeeds",
    ),
    conditional(
        "FileVersion",
        SINCE_1_4_1,
        "PE version-resource enrichment succeeds",
    ),
    never(
        "Signed",
        SINCE_BASELINE,
        "Kernel-Process image-load events contain no Authenticode result",
    ),
    never(
        "Signature",
        SINCE_BASELINE,
        "Kernel-Process image-load events contain no signer identity",
    ),
    never(
        "User",
        SINCE_BASELINE,
        "Kernel-Process image-load events contain no user identity",
    ),
    conditional(
        "Hashes",
        SINCE_ARTIFACT_HASHES,
        "computed from the loaded file after admission when a loaded rule selects on it, and seen only by those rules",
    ),
    conditional(
        "Imphash",
        SINCE_ARTIFACT_HASHES,
        "computed from the loaded file's import table after admission when a loaded rule selects on it, and seen only by those rules",
    ),
];

const WINDOWS_NETWORK: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-Kernel-Network/Analytic",
    ),
    conditional(
        "DestinationIp",
        SINCE_BASELINE,
        "the provider event template must carry the remote address",
    ),
    conditional(
        "SourceIp",
        SINCE_BASELINE,
        "the provider event template must carry the local address",
    ),
    conditional(
        "DestinationPort",
        SINCE_BASELINE,
        "the provider event template must carry the remote port",
    ),
    conditional(
        "SourcePort",
        SINCE_BASELINE,
        "the provider event template must carry the local port",
    ),
    always("ProcessId", SINCE_BASELINE),
    always("Protocol", SINCE_BASELINE),
    always("Initiated", SINCE_1_4_1),
    conditional(
        "Image",
        SINCE_BASELINE,
        "present in the event or derived from the process cache",
    ),
    conditional(
        "User",
        SINCE_BASELINE,
        "the provider event template carries user identity",
    ),
    conditional(
        "DestinationHostname",
        SINCE_BASELINE,
        "derived from a preceding observed DNS answer",
    ),
];

const WINDOWS_FILE: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-Kernel-File/Analytic",
    ),
    always("TargetFilename", SINCE_BASELINE),
    conditional(
        "ProcessId",
        SINCE_BASELINE,
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "present in the event or derived from the process cache",
    ),
    conditional(
        "User",
        SINCE_BASELINE,
        "the provider event template carries user identity",
    ),
    never(
        "SourceFilename",
        SINCE_BASELINE,
        "Kernel-File does not provide the old name on emitted rename events",
    ),
    never(
        "CreationUtcTime",
        SINCE_BASELINE,
        "Kernel-File reports the information class, not the new timestamp",
    ),
    never(
        "PreviousCreationUtcTime",
        SINCE_BASELINE,
        "Kernel-File reports the information class, not the old timestamp",
    ),
    never(
        "PathTruncated",
        SINCE_BASELINE,
        "ETW delivers a complete path or no attributable event",
    ),
];

const WINDOWS_REGISTRY: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-Kernel-Registry/Analytic",
    ),
    always("TargetObject", SINCE_BASELINE),
    conditional(
        "Details",
        SINCE_1_4_0,
        "captured registry value data is available and renderable",
    ),
    conditional(
        "ProcessId",
        SINCE_BASELINE,
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "present in the event or derived from the process cache",
    ),
    conditional(
        "EventType",
        SINCE_BASELINE,
        "the provider event template carries the event type",
    ),
    conditional(
        "User",
        SINCE_BASELINE,
        "the provider event template carries user identity",
    ),
    conditional(
        "NewName",
        SINCE_BASELINE,
        "the operation is a rename and the provider carries the new name",
    ),
];

const WINDOWS_DNS: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-DNS-Client/Operational",
    ),
    conditional(
        "QueryName",
        SINCE_BASELINE,
        "the DNS Client event template carries a query name",
    ),
    conditional(
        "QueryResults",
        SINCE_BASELINE,
        "the event is a response carrying decoded answers",
    ),
    conditional(
        "QueryStatus",
        SINCE_BASELINE,
        "the DNS Client event template carries a status",
    ),
    conditional(
        "ProcessId",
        SINCE_BASELINE,
        "the DNS Client event template carries process identity",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "present in the event or derived from the process cache",
    ),
    never(
        "RecordType",
        SINCE_BASELINE,
        "the subscribed DNS Client events do not expose the query record type",
    ),
];

const WINDOWS_POWERSHELL_SCRIPT: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-PowerShell/Operational",
    ),
    conditional(
        "ScriptBlockText",
        SINCE_BASELINE,
        "event 4104 contains a script block",
    ),
    conditional(
        "ScriptBlockId",
        SINCE_BASELINE,
        "event 4104 contains a script-block identifier",
    ),
    conditional(
        "Path",
        SINCE_BASELINE,
        "the script block is associated with a file",
    ),
    conditional(
        "ProcessId",
        SINCE_BASELINE,
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "present in the event or derived from the process cache",
    ),
    conditional(
        "User",
        SINCE_BASELINE,
        "the provider event template carries user identity",
    ),
];

const WINDOWS_POWERSHELL_MODULE: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-PowerShell/Operational",
    ),
    conditional(
        "ContextInfo",
        SINCE_1_4_1,
        "Module Logging is enabled and event 4103 carries context",
    ),
    conditional(
        "Payload",
        SINCE_1_4_1,
        "Module Logging is enabled and event 4103 carries a payload",
    ),
    conditional(
        "ProcessId",
        SINCE_1_4_1,
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        SINCE_1_4_1,
        "present in the event or derived from the process cache",
    ),
    conditional(
        "User",
        SINCE_1_4_1,
        "the provider event template carries user identity",
    ),
];

const WINDOWS_WMI: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-WMI-Activity/Trace",
    ),
    conditional(
        "Operation",
        SINCE_BASELINE,
        "the native WMI event family carries an operation",
    ),
    conditional(
        "User",
        SINCE_BASELINE,
        "the native WMI event family carries user identity",
    ),
    conditional(
        "Query",
        SINCE_BASELINE,
        "the native WMI event family carries a query or command line",
    ),
    conditional(
        "ProcessId",
        SINCE_BASELINE,
        "the native WMI event family carries client process identity",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "present in the event or derived from the process cache",
    ),
    conditional(
        "EventNamespace",
        SINCE_BASELINE,
        "the native WMI event family carries a namespace",
    ),
    conditional(
        "EventType",
        SINCE_BASELINE,
        "the native WMI event family carries an event type",
    ),
    conditional(
        "DestinationHostname",
        SINCE_BASELINE,
        "the native WMI event family carries a client machine",
    ),
];

const WINDOWS_TASK: &[FieldContract] = &[
    always_value(
        "Channel",
        SINCE_WINDOWS_CHANNEL,
        "Microsoft-Windows-TaskScheduler/Operational",
    ),
    conditional(
        "TaskName",
        SINCE_BASELINE,
        "TaskScheduler event 106 carries a task name",
    ),
    conditional(
        "UserName",
        SINCE_BASELINE,
        "TaskScheduler event 106 carries user context",
    ),
    never(
        "TaskContent",
        SINCE_BASELINE,
        "TaskScheduler event 106 does not carry the task XML definition",
    ),
    never(
        "User",
        SINCE_BASELINE,
        "TaskScheduler event 106 has UserContext, not a Sysmon User field",
    ),
    never(
        "ProcessId",
        SINCE_BASELINE,
        "TaskScheduler event 106 does not carry process identity",
    ),
    never(
        "Image",
        SINCE_BASELINE,
        "TaskScheduler event 106 does not carry a process image",
    ),
];

const WINDOWS_SERVICE: &[FieldContract] = &[
    always_value("Channel", SINCE_WINDOWS_CHANNEL, "System"),
    always("Provider_Name", SINCE_1_4_1),
    always("ServiceName", SINCE_1_4_0),
    always("ServiceFileName", SINCE_1_4_0),
    always("ImagePath", SINCE_1_4_1),
    conditional(
        "ServiceType",
        SINCE_1_4_0,
        "System event 7045 carries a service type",
    ),
    conditional(
        "StartType",
        SINCE_1_4_0,
        "System event 7045 carries a start type",
    ),
    conditional(
        "AccountName",
        SINCE_1_4_0,
        "System event 7045 carries an account name",
    ),
    conditional(
        "User",
        SINCE_1_4_0,
        "the Event Log system header carries a security user ID",
    ),
    never(
        "ProcessId",
        SINCE_1_4_0,
        "System event 7045 does not carry process identity",
    ),
    never(
        "Image",
        SINCE_1_4_0,
        "System event 7045 does not carry a creating process image",
    ),
];

const SECURITY_FIELD_REASON: &str =
    "the audited event template and host audit policy supply this field";

macro_rules! security_fields {
    ($($field:literal => $since:expr),+ $(,)?) => {
        &[
            always_value("Channel", SINCE_WINDOWS_CHANNEL, "Security"),
            conditional("SubjectUserSid", SINCE_1_4_1, SECURITY_FIELD_REASON),
            conditional("SubjectUserName", SINCE_1_4_1, SECURITY_FIELD_REASON),
            conditional("SubjectDomainName", SINCE_1_4_1, SECURITY_FIELD_REASON),
            conditional("SubjectLogonId", SINCE_1_4_1, SECURITY_FIELD_REASON),
            $(conditional($field, $since, SECURITY_FIELD_REASON)),+
        ]
    };
}

/// A Security event family added by #479. The field names are the event
/// template's own, read from the provider manifest on Windows 11 (all template
/// versions merged), not from documentation.
macro_rules! security_family {
    // The template opens with the `Subject*` identity block.
    (subject: $($field:literal),+ $(,)?) => {
        &[
            always_value("Channel", SINCE_WINDOWS_CHANNEL, "Security"),
            conditional("SubjectUserSid", SINCE_SECURITY_FAMILIES, SECURITY_FIELD_REASON),
            conditional("SubjectUserName", SINCE_SECURITY_FAMILIES, SECURITY_FIELD_REASON),
            conditional("SubjectDomainName", SINCE_SECURITY_FAMILIES, SECURITY_FIELD_REASON),
            conditional("SubjectLogonId", SINCE_SECURITY_FAMILIES, SECURITY_FIELD_REASON),
            $(conditional($field, SINCE_SECURITY_FAMILIES, SECURITY_FIELD_REASON)),+
        ]
    };
    // Credential validation and Windows Filtering Platform templates name no
    // subject.
    (no_subject: $($field:literal),+ $(,)?) => {
        &[
            always_value("Channel", SINCE_WINDOWS_CHANNEL, "Security"),
            $(conditional($field, SINCE_SECURITY_FAMILIES, SECURITY_FIELD_REASON)),+
        ]
    };
}

const WINDOWS_SECURITY_4624: &[FieldContract] = security_fields!(
    "TargetUserSid" => SINCE_1_4_1,
    "TargetUserName" => SINCE_1_4_1,
    "TargetDomainName" => SINCE_1_4_1,
    "TargetLogonId" => SINCE_1_4_1,
    "LogonType" => SINCE_1_4_1,
    "LogonProcessName" => SINCE_1_4_1,
    "AuthenticationPackageName" => SINCE_1_4_1,
    "WorkstationName" => SINCE_1_4_1,
    "LogonGuid" => SINCE_1_4_1,
    "LmPackageName" => SINCE_1_4_1,
    "KeyLength" => SINCE_1_4_1,
    "ProcessId" => SINCE_1_4_1,
    "ProcessName" => SINCE_1_4_1,
    "IpAddress" => SINCE_1_4_1,
    "IpPort" => SINCE_1_4_1,
    "ImpersonationLevel" => SINCE_1_4_1,
    "RestrictedAdminMode" => SINCE_1_4_1,
    "TargetOutboundUserName" => SINCE_1_4_1,
    "TargetOutboundDomainName" => SINCE_1_4_1,
    "VirtualAccount" => SINCE_1_4_1,
    "TargetLinkedLogonId" => SINCE_1_4_1,
    "ElevatedToken" => SINCE_1_4_1,
);
const WINDOWS_SECURITY_4656: &[FieldContract] = security_fields!(
    "ObjectServer" => SINCE_1_4_1,
    "ObjectType" => SINCE_1_4_1,
    "ObjectName" => SINCE_1_4_1,
    "HandleId" => SINCE_1_4_1,
    "AccessList" => SINCE_1_4_1,
    "AccessMask" => SINCE_1_4_1,
    "AccessReason" => SINCE_1_4_1,
    "PrivilegeList" => SINCE_1_4_1,
    "ProcessId" => SINCE_1_4_1,
    "ProcessName" => SINCE_1_4_1,
);
const WINDOWS_SECURITY_4663: &[FieldContract] = security_fields!(
    "ObjectServer" => SINCE_1_4_1,
    "ObjectType" => SINCE_1_4_1,
    "ObjectName" => SINCE_1_4_1,
    "HandleId" => SINCE_1_4_1,
    "AccessList" => SINCE_1_4_1,
    "AccessMask" => SINCE_1_4_1,
    "ProcessId" => SINCE_1_4_1,
    "ProcessName" => SINCE_1_4_1,
);
const WINDOWS_SECURITY_4697: &[FieldContract] = security_fields!(
    "ServiceName" => SINCE_1_4_1,
    "ServiceFileName" => SINCE_1_4_1,
    "ServiceType" => SINCE_1_4_1,
    "ServiceStartType" => SINCE_1_4_1,
    "ServiceAccount" => SINCE_1_4_1,
);
const WINDOWS_SECURITY_5136: &[FieldContract] = security_fields!(
    "DSName" => SINCE_1_4_1,
    "DSType" => SINCE_1_4_1,
    "ObjectDN" => SINCE_1_4_1,
    "ObjectGUID" => SINCE_1_4_1,
    "ObjectClass" => SINCE_1_4_1,
    "AttributeLDAPDisplayName" => SINCE_1_4_1,
    "AttributeSyntaxOID" => SINCE_1_4_1,
    "AttributeValue" => SINCE_1_4_1,
    "OperationType" => SINCE_1_4_1,
);
const WINDOWS_SECURITY_5145: &[FieldContract] = security_fields!(
    "ObjectType" => SINCE_1_4_1,
    "IpAddress" => SINCE_1_4_1,
    "IpPort" => SINCE_1_4_1,
    "ShareName" => SINCE_1_4_1,
    "ShareLocalPath" => SINCE_1_4_1,
    "RelativeTargetName" => SINCE_1_4_1,
    "AccessMask" => SINCE_1_4_1,
    "AccessList" => SINCE_1_4_1,
    "AccessReason" => SINCE_1_4_1,
);

// Logon failure and explicit credentials.
const WINDOWS_SECURITY_4625: &[FieldContract] = security_family!(subject:
    "TargetUserSid", "TargetUserName", "TargetDomainName", "Status", "FailureReason",
    "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
    "WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId",
    "ProcessName", "IpAddress", "IpPort",
);
const WINDOWS_SECURITY_4648: &[FieldContract] = security_family!(subject:
    "LogonGuid", "TargetUserName", "TargetDomainName", "TargetLogonGuid", "TargetServerName",
    "TargetInfo", "ProcessId", "ProcessName", "IpAddress", "IpPort",
);
const WINDOWS_SECURITY_4771: &[FieldContract] = security_family!(no_subject:
    "TargetUserName", "TargetSid", "ServiceName", "TicketOptions", "Status", "PreAuthType",
    "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint",
);
const WINDOWS_SECURITY_4776: &[FieldContract] = security_family!(no_subject:
    "PackageName", "TargetUserName", "Workstation", "Status",
);

// Registry value modification.
const WINDOWS_SECURITY_4657: &[FieldContract] = security_family!(subject:
    "ObjectName", "ObjectValueName", "HandleId", "OperationType", "OldValueType", "OldValue",
    "NewValueType", "NewValue", "ProcessId", "ProcessName",
);

// Scheduled tasks. 4702 carries the new definition as `TaskContentNew`.
const WINDOWS_SECURITY_TASK: &[FieldContract] = security_family!(subject:
    "TaskName", "TaskContent", "ClientProcessStartKey", "ClientProcessId", "ParentProcessId",
    "RpcCallClientLocality", "FQDN",
);
const WINDOWS_SECURITY_4702: &[FieldContract] = security_family!(subject:
    "TaskName", "TaskContentNew", "ClientProcessStartKey", "ClientProcessId", "ParentProcessId",
    "RpcCallClientLocality", "FQDN",
);

// Audit and log tampering. 1102 is written to the Security channel by the
// Event Log service itself, under its own provider.
const WINDOWS_SECURITY_1102: &[FieldContract] = &[
    always_value("Channel", SINCE_WINDOWS_CHANNEL, "Security"),
    always("Provider_Name", SINCE_SECURITY_FAMILIES),
    conditional(
        "SubjectUserSid",
        SINCE_SECURITY_FAMILIES,
        SECURITY_FIELD_REASON,
    ),
    conditional(
        "SubjectUserName",
        SINCE_SECURITY_FAMILIES,
        SECURITY_FIELD_REASON,
    ),
    conditional(
        "SubjectDomainName",
        SINCE_SECURITY_FAMILIES,
        SECURITY_FIELD_REASON,
    ),
    conditional(
        "SubjectLogonId",
        SINCE_SECURITY_FAMILIES,
        SECURITY_FIELD_REASON,
    ),
    conditional(
        "ClientProcessId",
        SINCE_SECURITY_FAMILIES,
        SECURITY_FIELD_REASON,
    ),
    conditional(
        "ClientProcessStartKey",
        SINCE_SECURITY_FAMILIES,
        SECURITY_FIELD_REASON,
    ),
];
const WINDOWS_SECURITY_4719: &[FieldContract] = security_family!(subject:
    "CategoryId", "SubcategoryId", "SubcategoryGuid", "AuditPolicyChanges", "ClientProcessId",
    "ClientProcessStartKey",
);
const WINDOWS_SECURITY_4817: &[FieldContract] = security_family!(subject:
    "ObjectServer", "ObjectType", "ObjectName", "OldSd", "NewSd",
);

// Account management.
const WINDOWS_SECURITY_USER_ACCOUNT: &[FieldContract] = security_family!(subject:
    "TargetUserName", "TargetDomainName", "TargetSid", "PrivilegeList", "SamAccountName",
    "DisplayName", "UserPrincipalName", "HomeDirectory", "HomePath", "ScriptPath",
    "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires", "PrimaryGroupId",
    "AllowedToDelegateTo", "OldUacValue", "NewUacValue", "UserAccountControl",
    "UserParameters", "SidHistory", "LogonHours",
);
const WINDOWS_SECURITY_4741: &[FieldContract] = security_family!(subject:
    "TargetUserName", "TargetDomainName", "TargetSid", "PrivilegeList", "SamAccountName",
    "DisplayName", "UserPrincipalName", "HomeDirectory", "HomePath", "ScriptPath",
    "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires", "PrimaryGroupId",
    "AllowedToDelegateTo", "OldUacValue", "NewUacValue", "UserAccountControl",
    "UserParameters", "SidHistory", "LogonHours", "DnsHostName", "ServicePrincipalNames",
);
const WINDOWS_SECURITY_ACCOUNT_TARGET: &[FieldContract] = security_family!(subject:
    "TargetUserName", "TargetDomainName", "TargetSid",
);
const WINDOWS_SECURITY_ACCOUNT_REMOVED: &[FieldContract] = security_family!(subject:
    "TargetUserName", "TargetDomainName", "TargetSid", "PrivilegeList",
);
const WINDOWS_SECURITY_GROUP_MEMBER_ADDED: &[FieldContract] = security_family!(subject:
    "MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid",
    "PrivilegeList", "MembershipExpirationTime",
);
const WINDOWS_SECURITY_4765: &[FieldContract] = security_family!(subject:
    "SourceUserName", "SourceSid", "TargetUserName", "TargetDomainName", "TargetSid",
    "PrivilegeList", "SidList",
);
const WINDOWS_SECURITY_4766: &[FieldContract] = security_family!(subject:
    "SourceUserName", "TargetUserName", "TargetDomainName", "TargetSid", "PrivilegeList",
);
const WINDOWS_SECURITY_4781: &[FieldContract] = security_family!(subject:
    "OldTargetUserName", "NewTargetUserName", "TargetDomainName", "TargetSid", "PrivilegeList",
);
const WINDOWS_SECURITY_4794: &[FieldContract] = security_family!(subject:
    "Workstation", "Status",
);

// Windows Filtering Platform and Plug and Play. The connection templates
// changed the process ID's spelling between versions (`ProcessID` in v0 and
// v2, `ProcessId` in v1), so both are allowed and rules see whichever the
// host writes.
const WINDOWS_SECURITY_WFP_CONNECTION: &[FieldContract] = security_family!(no_subject:
    "ProcessID", "ProcessId", "Application", "Direction", "SourceAddress", "SourcePort",
    "DestAddress", "DestPort", "Protocol", "InterfaceIndex", "FilterName", "FilterOrigin",
    "FilterRTID", "LayerName", "LayerRTID", "SublayerInformation", "RemoteUserID",
    "RemoteMachineID", "OriginalProfile", "CurrentProfile", "IsLoopback",
    "HasRemoteDynamicKeywordAddress", "FilterAction",
);
const WINDOWS_SECURITY_5152: &[FieldContract] = security_family!(no_subject:
    "ProcessId", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress",
    "DestPort", "Protocol", "FilterName", "FilterOrigin", "FilterRTID", "LayerName",
    "LayerRTID", "SublayerInformation", "FilterAction",
);
const WINDOWS_SECURITY_5447: &[FieldContract] = security_family!(no_subject:
    "ProcessId", "UserSid", "UserName", "ProviderKey", "ProviderName", "ChangeType",
    "FilterKey", "FilterName", "FilterType", "FilterId", "LayerKey", "LayerName", "LayerId",
    "Weight", "Conditions", "Action", "CalloutKey", "CalloutName",
);
const WINDOWS_SECURITY_6416: &[FieldContract] = security_family!(subject:
    "DeviceId", "DeviceDescription", "ClassId", "ClassName", "VendorIds", "CompatibleIds",
    "LocationInformation",
);

const LINUX_PROCESS: &[FieldContract] = &[
    always("Image", SINCE_BASELINE),
    always("ImageSource", SINCE_1_6_0),
    always("ProcessId", SINCE_BASELINE),
    always("RealUserId", SINCE_1_6_0),
    always("RealGroupId", SINCE_1_6_0),
    conditional(
        "EffectiveUserId",
        SINCE_1_6_0,
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "EffectiveGroupId",
        SINCE_1_6_0,
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "MountNamespace",
        SINCE_1_6_0,
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "PidNamespace",
        SINCE_1_6_0,
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "NetworkNamespace",
        SINCE_1_6_0,
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "SessionId",
        SINCE_1_6_0,
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "KernelStartBoottime",
        SINCE_1_6_0,
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "ControllingTty",
        SINCE_1_6_0,
        "runtime BTF resolves terminal fields and the process has a controlling terminal",
    ),
    conditional(
        "User",
        SINCE_1_6_0,
        "runtime BTF resolves effective credentials and the kernel read succeeds",
    ),
    conditional(
        "ImageTruncated",
        SINCE_1_6_0,
        "the raw exec filename exceeded the kernel capture buffer",
    ),
    conditional(
        "CommandLine",
        SINCE_BASELINE,
        "kernel argv capture or the live /proc entry is available",
    ),
    conditional(
        "ParentProcessId",
        SINCE_BASELINE,
        "the live /proc entry is available",
    ),
    conditional(
        "ParentImage",
        SINCE_BASELINE,
        "measured at fork or available from process state",
    ),
    conditional(
        "ParentCommandLine",
        SINCE_BASELINE,
        "measured at fork or available from process state",
    ),
    conditional(
        "CurrentDirectory",
        SINCE_PROCESS_PATH_ENRICHMENT,
        "the live /proc entry and BTF process identity remain available during downstream enrichment",
    ),
    conditional(
        "CgroupId",
        SINCE_BASELINE,
        "the kernel reports a non-zero cgroup identifier at exec time",
    ),
    conditional(
        "CgroupPath",
        SINCE_CONTAINER_CONTEXT,
        "the host mounts cgroup2 and the cgroup still exists when the event is enriched",
    ),
    conditional(
        "ContainerId",
        SINCE_CONTAINER_CONTEXT,
        "the cgroup path names a recognized container layout",
    ),
    conditional(
        "ContainerRuntime",
        SINCE_CONTAINER_CONTEXT,
        "ContainerId is present and its cgroup layout names the runtime",
    ),
    never(
        "OriginalFileName",
        SINCE_BASELINE,
        "PE version resources are Windows-only",
    ),
    never(
        "Product",
        SINCE_BASELINE,
        "PE version resources are Windows-only",
    ),
    never(
        "Description",
        SINCE_BASELINE,
        "PE version resources are Windows-only",
    ),
    never(
        "Company",
        SINCE_BASELINE,
        "PE version resources are Windows-only",
    ),
    never(
        "FileVersion",
        SINCE_BASELINE,
        "PE version resources are Windows-only",
    ),
    never(
        "IntegrityLevel",
        SINCE_BASELINE,
        "Windows integrity levels do not exist on Linux",
    ),
    never(
        "TargetImage",
        SINCE_BASELINE,
        "a process-creation event has no target process",
    ),
];

const LINUX_NETWORK: &[FieldContract] = &[
    always("DestinationIp", SINCE_BASELINE),
    always("DestinationPort", SINCE_BASELINE),
    always("ProcessId", SINCE_BASELINE),
    conditional(
        "User",
        SINCE_1_6_0,
        "runtime BTF resolves effective credentials and the kernel read succeeds",
    ),
    always("Initiated", SINCE_1_4_1),
    conditional(
        "Protocol",
        SINCE_BASELINE,
        "the socket fexit tier is active and sk_protocol names TCP or UDP",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "the process identity is still present in the process cache",
    ),
    conditional(
        "DestinationHostname",
        SINCE_BASELINE,
        "a preceding observed DNS answer resolves the destination",
    ),
    conditional(
        "SourceIp",
        SINCE_1_6_0,
        "the socket fexit tier measures the bound source address",
    ),
    conditional(
        "SourcePort",
        SINCE_1_6_0,
        "the socket fexit tier measures the bound source port",
    ),
];

const LINUX_FILE: &[FieldContract] = &[
    always("TargetFilename", SINCE_BASELINE),
    always("ProcessId", SINCE_BASELINE),
    conditional(
        "User",
        SINCE_1_6_0,
        "runtime BTF resolves effective credentials and the kernel read succeeds",
    ),
    conditional(
        "SourceFilename",
        SINCE_BASELINE,
        "the action is rename and the old path can be resolved",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "the process identity is still present in the process cache",
    ),
    conditional(
        "PathTruncated",
        SINCE_BASELINE,
        "the kernel path buffer truncated a source or target",
    ),
    never(
        "CreationUtcTime",
        SINCE_BASELINE,
        "the eBPF file probes do not read file timestamps",
    ),
    never(
        "PreviousCreationUtcTime",
        SINCE_BASELINE,
        "the eBPF file probes do not read file timestamps",
    ),
];

const LINUX_DNS: &[FieldContract] = &[
    always("RecordType", SINCE_BASELINE),
    always("ProcessId", SINCE_BASELINE),
    conditional(
        "QueryName",
        SINCE_BASELINE,
        "the DNS question can be parsed",
    ),
    conditional(
        "QueryResults",
        SINCE_DNS_RESPONSES,
        "the event is a response carrying A, AAAA, or CNAME answers",
    ),
    conditional(
        "Image",
        SINCE_BASELINE,
        "the process identity is still present in the process cache",
    ),
    conditional(
        "QueryStatus",
        SINCE_DNS_RESPONSES,
        "the event is a response; the value is the DNS RCODE",
    ),
];

const MACOS_PROCESS: &[FieldContract] = &[
    always("Image", SINCE_1_1_0),
    always("ProcessId", SINCE_1_1_0),
    always("ProcessStartTime", SINCE_1_1_0),
    always("User", SINCE_1_1_0),
    conditional(
        "CommandLine",
        SINCE_1_1_0,
        "ESF supplies at least one exec argument",
    ),
    conditional("ParentProcessId", SINCE_1_1_0, "the parent PID is non-zero"),
    conditional(
        "ParentImage",
        SINCE_1_1_0,
        "derived from the process cache by an observed stable parent identity",
    ),
    conditional(
        "ParentCommandLine",
        SINCE_1_6_0,
        "the stable parent identity resolves to a cached command line",
    ),
    always("RealUserId", SINCE_1_6_0),
    always("Signed", SINCE_1_6_0),
    always("SignatureStatus", SINCE_1_6_0),
    always("CodeSigningFlags", SINCE_1_6_0),
    always("IsPlatformBinary", SINCE_1_6_0),
    conditional(
        "PreExecImage",
        SINCE_1_6_0,
        "ESF supplies a non-empty acting process executable path",
    ),
    conditional(
        "Script",
        SINCE_1_6_0,
        "message version 2+ supplies a script for direct shebang execution",
    ),
    conditional(
        "SigningId",
        SINCE_1_6_0,
        "ESF supplies a non-empty signing identifier",
    ),
    conditional(
        "TeamId",
        SINCE_1_6_0,
        "ESF supplies a non-empty signing team identifier",
    ),
    conditional(
        "CdHash",
        SINCE_1_6_0,
        "the executable has the CS_SIGNED flag",
    ),
    conditional(
        "CurrentDirectory",
        SINCE_1_1_0,
        "ESF supplies an exec working directory",
    ),
    never(
        "CgroupId",
        SINCE_1_1_0,
        "macOS process events do not have a Linux kernel cgroup identifier",
    ),
    never(
        "ImageSource",
        SINCE_1_6_0,
        "ESF supplies the executable path directly",
    ),
    never(
        "ImageTruncated",
        SINCE_1_6_0,
        "ESF does not use the Linux raw-image buffer",
    ),
    never(
        "IntegrityLevel",
        SINCE_1_4_1,
        "Windows integrity levels do not exist on macOS",
    ),
    never(
        "TargetImage",
        SINCE_1_1_0,
        "a process-creation event has no target process",
    ),
    never(
        "OriginalFileName",
        SINCE_1_1_0,
        "PE version resources are Windows-only",
    ),
    never(
        "Product",
        SINCE_1_1_0,
        "PE version resources are Windows-only",
    ),
    never(
        "Description",
        SINCE_1_1_0,
        "PE version resources are Windows-only",
    ),
    never(
        "Company",
        SINCE_1_4_1,
        "PE version resources are Windows-only",
    ),
    never(
        "FileVersion",
        SINCE_1_4_1,
        "PE version resources are Windows-only",
    ),
];

const MACOS_FILE: &[FieldContract] = &[
    always("TargetFilename", SINCE_1_1_0),
    always("ProcessId", SINCE_1_1_0),
    always("User", SINCE_1_1_0),
    conditional("SourceFilename", SINCE_1_1_0, "the ESF action is a rename"),
    conditional(
        "Image",
        SINCE_1_1_0,
        "ESF supplies the acting process executable path",
    ),
    never(
        "CreationUtcTime",
        SINCE_1_1_0,
        "ESF file notifications do not carry file timestamps",
    ),
    never(
        "PreviousCreationUtcTime",
        SINCE_1_1_0,
        "ESF file notifications do not carry file timestamps",
    ),
    never(
        "PathTruncated",
        SINCE_1_1_0,
        "ESF paths are not copied through a fixed Rustinel buffer",
    ),
];

const MACOS_NETWORK: &[FieldContract] = &[
    always("DestinationIp", SINCE_1_1_0),
    always("SourceIp", SINCE_1_1_0),
    always("DestinationPort", SINCE_1_1_0),
    always("SourcePort", SINCE_1_1_0),
    always("Protocol", SINCE_1_1_0),
    conditional(
        "ProcessId",
        SINCE_1_1_0,
        "bounded socket-inventory attribution finds the owner",
    ),
    conditional(
        "Image",
        SINCE_1_1_0,
        "bounded socket-inventory attribution finds the owner",
    ),
    conditional(
        "DestinationHostname",
        SINCE_1_1_0,
        "a preceding observed DNS answer resolves the destination",
    ),
    never(
        "User",
        SINCE_1_1_0,
        "BPF packets do not carry process user identity",
    ),
    never(
        "Initiated",
        SINCE_1_4_1,
        "a wire capture cannot determine whether the local host initiated the flow",
    ),
];

const MACOS_DNS: &[FieldContract] = &[
    always("QueryName", SINCE_1_1_0),
    conditional(
        "RecordType",
        SINCE_1_1_0,
        "the DNS qtype has a known Sysmon-compatible name",
    ),
    never(
        "QueryResults",
        SINCE_1_1_0,
        "the BPF DNS path emits queries, not responses",
    ),
    never(
        "QueryStatus",
        SINCE_1_1_0,
        "the BPF DNS path emits queries, not responses",
    ),
    conditional(
        "ProcessId",
        SINCE_1_7_0,
        "bounded socket-inventory attribution finds the owner",
    ),
    conditional(
        "Image",
        SINCE_1_7_0,
        "bounded socket-inventory attribution finds the owner and executable path",
    ),
];

const PIPE_CREATED: &[FieldContract] = &[never(
    "*", SINCE_BASELINE,
    "named-pipe activity is not carried by Microsoft-Windows-Kernel-File and is not available from ETW",
)];

const CREATE_REMOTE_THREAD: &[FieldContract] = &[never(
    "*",
    SINCE_BASELINE,
    "no Rustinel sensor produces remote-thread creation telemetry",
)];

macro_rules! contract {
    ($platform:ident, $category:literal, $event:expr, $action:ident, $provider:literal, $source:literal, $fields:ident) => {
        EventFieldContract {
            platform: Platform::$platform,
            category: $category,
            event_id: $event,
            action: Some(SensorAction::$action),
            provider: $provider,
            source: $source,
            fields: $fields,
        }
    };
}

/// Complete event-field availability table.
pub const FIELD_AVAILABILITY: &[EventFieldContract] = &[
    contract!(
        Windows,
        "process_creation",
        Some(1),
        Start,
        "etw",
        "Microsoft-Windows-Kernel-Process",
        WINDOWS_PROCESS
    ),
    contract!(
        Windows,
        "network_connection",
        Some(3),
        Connect,
        "etw",
        "Microsoft-Windows-Kernel-Network",
        WINDOWS_NETWORK
    ),
    contract!(
        Windows,
        "network_connection",
        Some(3),
        Accept,
        "etw",
        "Microsoft-Windows-Kernel-Network",
        WINDOWS_NETWORK
    ),
    contract!(
        Windows,
        "file_event",
        None,
        Create,
        "etw",
        "Microsoft-Windows-Kernel-File",
        WINDOWS_FILE
    ),
    contract!(
        Windows,
        "file_event",
        None,
        Set,
        "etw",
        "Microsoft-Windows-Kernel-File",
        WINDOWS_FILE
    ),
    contract!(
        Windows,
        "file_event",
        None,
        Modify,
        "etw",
        "Microsoft-Windows-Kernel-File",
        WINDOWS_FILE
    ),
    contract!(
        Windows,
        "file_event",
        None,
        Delete,
        "etw",
        "Microsoft-Windows-Kernel-File",
        WINDOWS_FILE
    ),
    contract!(
        Windows,
        "file_event",
        None,
        Rename,
        "etw",
        "Microsoft-Windows-Kernel-File",
        WINDOWS_FILE
    ),
    contract!(
        Windows,
        "registry_event",
        None,
        Create,
        "etw",
        "Microsoft-Windows-Kernel-Registry",
        WINDOWS_REGISTRY
    ),
    contract!(
        Windows,
        "registry_event",
        None,
        Set,
        "etw",
        "Microsoft-Windows-Kernel-Registry",
        WINDOWS_REGISTRY
    ),
    contract!(
        Windows,
        "registry_event",
        None,
        Delete,
        "etw",
        "Microsoft-Windows-Kernel-Registry",
        WINDOWS_REGISTRY
    ),
    contract!(
        Windows,
        "dns_query",
        Some(3006),
        Query,
        "etw",
        "Microsoft-Windows-DNS-Client",
        WINDOWS_DNS
    ),
    contract!(
        Windows,
        "dns_query",
        Some(3008),
        Query,
        "etw",
        "Microsoft-Windows-DNS-Client",
        WINDOWS_DNS
    ),
    contract!(
        Windows,
        "image_load",
        Some(7),
        Load,
        "etw",
        "Microsoft-Windows-Kernel-Process",
        WINDOWS_IMAGE_LOAD
    ),
    contract!(
        Windows,
        "ps_script",
        Some(4104),
        Execute,
        "etw",
        "Microsoft-Windows-PowerShell",
        WINDOWS_POWERSHELL_SCRIPT
    ),
    contract!(
        Windows,
        "ps_module",
        Some(4103),
        Execute,
        "etw",
        "Microsoft-Windows-PowerShell",
        WINDOWS_POWERSHELL_MODULE
    ),
    contract!(
        Windows,
        "wmi_event",
        None,
        Execute,
        "etw",
        "Microsoft-Windows-WMI-Activity",
        WINDOWS_WMI
    ),
    contract!(
        Windows,
        "task_creation",
        Some(106),
        Register,
        "etw",
        "Microsoft-Windows-TaskScheduler",
        WINDOWS_TASK
    ),
    contract!(
        Windows,
        "service_creation",
        Some(7045),
        Register,
        "windows_event_log",
        "Service Control Manager",
        WINDOWS_SERVICE
    ),
    contract!(
        Windows,
        "security",
        Some(4624),
        Start,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4624
    ),
    contract!(
        Windows,
        "security",
        Some(4656),
        Access,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4656
    ),
    contract!(
        Windows,
        "security",
        Some(4663),
        Access,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4663
    ),
    contract!(
        Windows,
        "security",
        Some(4697),
        Register,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4697
    ),
    contract!(
        Windows,
        "security",
        Some(5136),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_5136
    ),
    contract!(
        Windows,
        "security",
        Some(5145),
        Access,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_5145
    ),
    contract!(
        Windows,
        "security",
        Some(1102),
        Delete,
        "windows_event_log",
        "Microsoft-Windows-Eventlog",
        WINDOWS_SECURITY_1102
    ),
    contract!(
        Windows,
        "security",
        Some(4625),
        Start,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4625
    ),
    contract!(
        Windows,
        "security",
        Some(4648),
        Start,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4648
    ),
    contract!(
        Windows,
        "security",
        Some(4657),
        Set,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4657
    ),
    contract!(
        Windows,
        "security",
        Some(4698),
        Register,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_TASK
    ),
    contract!(
        Windows,
        "security",
        Some(4699),
        Delete,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_TASK
    ),
    contract!(
        Windows,
        "security",
        Some(4700),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_TASK
    ),
    contract!(
        Windows,
        "security",
        Some(4701),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_TASK
    ),
    contract!(
        Windows,
        "security",
        Some(4702),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4702
    ),
    contract!(
        Windows,
        "security",
        Some(4719),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4719
    ),
    contract!(
        Windows,
        "security",
        Some(4720),
        Create,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_USER_ACCOUNT
    ),
    contract!(
        Windows,
        "security",
        Some(4722),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_ACCOUNT_TARGET
    ),
    contract!(
        Windows,
        "security",
        Some(4724),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_ACCOUNT_TARGET
    ),
    contract!(
        Windows,
        "security",
        Some(4726),
        Delete,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_ACCOUNT_REMOVED
    ),
    contract!(
        Windows,
        "security",
        Some(4728),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_GROUP_MEMBER_ADDED
    ),
    contract!(
        Windows,
        "security",
        Some(4732),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_GROUP_MEMBER_ADDED
    ),
    contract!(
        Windows,
        "security",
        Some(4738),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_USER_ACCOUNT
    ),
    contract!(
        Windows,
        "security",
        Some(4741),
        Create,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4741
    ),
    contract!(
        Windows,
        "security",
        Some(4743),
        Delete,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_ACCOUNT_REMOVED
    ),
    contract!(
        Windows,
        "security",
        Some(4756),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_GROUP_MEMBER_ADDED
    ),
    contract!(
        Windows,
        "security",
        Some(4765),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4765
    ),
    contract!(
        Windows,
        "security",
        Some(4766),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4766
    ),
    contract!(
        Windows,
        "security",
        Some(4771),
        Start,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4771
    ),
    contract!(
        Windows,
        "security",
        Some(4776),
        Start,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4776
    ),
    contract!(
        Windows,
        "security",
        Some(4781),
        Rename,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4781
    ),
    contract!(
        Windows,
        "security",
        Some(4794),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4794
    ),
    contract!(
        Windows,
        "security",
        Some(4817),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_4817
    ),
    contract!(
        Windows,
        "security",
        Some(5152),
        Connect,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_5152
    ),
    contract!(
        Windows,
        "security",
        Some(5156),
        Connect,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_WFP_CONNECTION
    ),
    contract!(
        Windows,
        "security",
        Some(5157),
        Connect,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_WFP_CONNECTION
    ),
    contract!(
        Windows,
        "security",
        Some(5447),
        Modify,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_5447
    ),
    contract!(
        Windows,
        "security",
        Some(6416),
        Register,
        "windows_event_log",
        "Microsoft-Windows-Security-Auditing",
        WINDOWS_SECURITY_6416
    ),
    EventFieldContract {
        platform: Platform::Windows,
        category: "pipe_created",
        event_id: Some(17),
        action: None,
        provider: "none",
        source: "Microsoft-Windows-Kernel-File",
        fields: PIPE_CREATED,
    },
    EventFieldContract {
        platform: Platform::Windows,
        category: "create_remote_thread",
        event_id: Some(8),
        action: None,
        provider: "none",
        source: "none",
        fields: CREATE_REMOTE_THREAD,
    },
    contract!(
        Linux,
        "process_creation",
        Some(1),
        Start,
        "ebpf",
        "execve tracepoints",
        LINUX_PROCESS
    ),
    contract!(
        Linux,
        "network_connection",
        Some(3),
        Connect,
        "ebpf",
        "socket fexit or connect tracepoints",
        LINUX_NETWORK
    ),
    contract!(
        Linux,
        "file_event",
        None,
        Create,
        "ebpf",
        "file syscall tracepoints",
        LINUX_FILE
    ),
    contract!(
        Linux,
        "file_event",
        None,
        Modify,
        "ebpf",
        "file syscall tracepoints",
        LINUX_FILE
    ),
    contract!(
        Linux,
        "file_event",
        None,
        Delete,
        "ebpf",
        "file syscall tracepoints",
        LINUX_FILE
    ),
    contract!(
        Linux,
        "file_event",
        None,
        Rename,
        "ebpf",
        "file syscall tracepoints",
        LINUX_FILE
    ),
    contract!(
        Linux,
        "dns_query",
        Some(22),
        Query,
        "ebpf",
        "DNS socket syscall hooks",
        LINUX_DNS
    ),
    contract!(
        MacOS,
        "process_creation",
        Some(1),
        Start,
        "esf",
        "Endpoint Security exec",
        MACOS_PROCESS
    ),
    contract!(
        MacOS,
        "network_connection",
        Some(3),
        Connect,
        "bpf",
        "/dev/bpf",
        MACOS_NETWORK
    ),
    contract!(
        MacOS,
        "file_event",
        None,
        Create,
        "esf",
        "Endpoint Security file notifications",
        MACOS_FILE
    ),
    contract!(
        MacOS,
        "file_event",
        None,
        Modify,
        "esf",
        "Endpoint Security file notifications",
        MACOS_FILE
    ),
    contract!(
        MacOS,
        "file_event",
        None,
        Delete,
        "esf",
        "Endpoint Security file notifications",
        MACOS_FILE
    ),
    contract!(
        MacOS,
        "file_event",
        None,
        Rename,
        "esf",
        "Endpoint Security file notifications",
        MACOS_FILE
    ),
    contract!(
        MacOS,
        "dns_query",
        Some(22),
        Query,
        "bpf",
        "/dev/bpf",
        MACOS_DNS
    ),
];

/// Canonical category name used by the compatibility table.
pub const fn category_name(category: EventCategory) -> &'static str {
    match category {
        EventCategory::Process => "process_creation",
        EventCategory::Network => "network_connection",
        EventCategory::File => "file_event",
        EventCategory::Registry => "registry_event",
        EventCategory::Dns => "dns_query",
        EventCategory::ImageLoad => "image_load",
        EventCategory::Scripting => "ps_script",
        EventCategory::PowerShellModule => "ps_module",
        EventCategory::Wmi => "wmi_event",
        EventCategory::Service => "service_creation",
        EventCategory::Task => "task_creation",
        EventCategory::Security => "security",
    }
}

const fn same_platform(left: Platform, right: Platform) -> bool {
    matches!(
        (left, right),
        (Platform::Windows, Platform::Windows)
            | (Platform::Linux, Platform::Linux)
            | (Platform::MacOS, Platform::MacOS)
    )
}

/// The half-open range of one platform's rows in [`FIELD_AVAILABILITY`].
///
/// The table is grouped by platform, so a lookup scans only its own platform's
/// rows. Without this, every field a Sigma rule reads from a Linux or macOS
/// event walks past every Windows contract first, and adding Windows event
/// families slows down the other platforms' detection hot path.
const fn platform_range(platform: Platform) -> (usize, usize) {
    let mut start = 0;
    while start < FIELD_AVAILABILITY.len()
        && !same_platform(FIELD_AVAILABILITY[start].platform, platform)
    {
        start += 1;
    }
    let mut end = start;
    while end < FIELD_AVAILABILITY.len()
        && same_platform(FIELD_AVAILABILITY[end].platform, platform)
    {
        end += 1;
    }
    (start, end)
}

const WINDOWS_RANGE: (usize, usize) = platform_range(Platform::Windows);
const LINUX_RANGE: (usize, usize) = platform_range(Platform::Linux);
const MACOS_RANGE: (usize, usize) = platform_range(Platform::MacOS);

/// Each platform's rows must be one contiguous run, or [`platform_range`] would
/// silently hide the rows after a second run and their contracts would stop
/// being found.
const _: () = assert!(
    (WINDOWS_RANGE.1 - WINDOWS_RANGE.0)
        + (LINUX_RANGE.1 - LINUX_RANGE.0)
        + (MACOS_RANGE.1 - MACOS_RANGE.0)
        == FIELD_AVAILABILITY.len(),
    "FIELD_AVAILABILITY must be grouped by platform: keep each platform's contracts contiguous"
);

/// The contracts for one platform, as a subslice of [`FIELD_AVAILABILITY`].
fn platform_contracts(platform: Platform) -> &'static [EventFieldContract] {
    let (start, end) = match platform {
        Platform::Windows => WINDOWS_RANGE,
        Platform::Linux => LINUX_RANGE,
        Platform::MacOS => MACOS_RANGE,
    };
    &FIELD_AVAILABILITY[start..end]
}

/// Find an event contract when the native decoder has not yet assigned an
/// action. Event ID must make the key unique; this is used by the Security
/// channel decoder as its field allowlist.
pub fn contract_for_event_id(
    platform: Platform,
    category: &str,
    event_id: u16,
    provider: &str,
) -> Option<&'static EventFieldContract> {
    platform_contracts(platform).iter().find(|contract| {
        contract.category == category
            && contract.event_id == Some(event_id)
            && contract.provider == provider
    })
}

fn event_contract(event: &NormalizedEvent) -> Option<&'static EventFieldContract> {
    platform_contracts(event.platform).iter().find(|contract| {
        contract.category == category_name(event.category)
            && contract.provider == event.provider
            && contract.event_id.is_none_or(|id| id == event.event_id)
            // Event Log records identify their schema by event ID and do not
            // carry the synthetic action opcode used by native sensors.
            && (event.provider == "windows_event_log"
                || contract
                    .action
                    .is_none_or(|action| action_code_matches(action, event.opcode)))
    })
}

/// Native Windows channel recorded for this exact emitted event shape.
pub(crate) fn channel_for_event(event: &NormalizedEvent) -> Option<&'static str> {
    event_contract(event).and_then(|contract| {
        contract
            .fields
            .iter()
            .find(|field| field.field == "Channel")
            .and_then(|field| field.value)
    })
}

const fn action_code_matches(action: SensorAction, opcode: u8) -> bool {
    match action {
        SensorAction::Start => opcode == 1,
        SensorAction::Stop => opcode == 2,
        SensorAction::Connect => opcode == 0 || opcode == 12,
        SensorAction::Accept => opcode == 15,
        SensorAction::Create => opcode == 36 || opcode == 64,
        SensorAction::Modify => opcode == 65,
        SensorAction::Delete => opcode == 38 || opcode == 70,
        SensorAction::Rename => opcode == 71,
        SensorAction::Set => opcode == 2 || opcode == 39,
        SensorAction::Query
        | SensorAction::Load
        | SensorAction::Execute
        | SensorAction::Register => opcode == 0 || opcode == 10,
        SensorAction::Disconnect | SensorAction::Access | SensorAction::Fork => true,
    }
}

/// Look up a field exactly as Sigma will see the event.
pub fn availability_for_event(event: &NormalizedEvent, field: &str) -> Option<Availability> {
    event_contract(event).and_then(|contract| {
        contract
            .fields
            .iter()
            .find(|entry| entry.field == field || entry.field == "*")
            .map(|entry| entry.availability)
    })
}

/// Always fields missing from an emitted normalized event.
pub fn missing_always_fields(event: &NormalizedEvent) -> Vec<&'static str> {
    event_contract(event)
        .into_iter()
        .flat_map(|contract| contract.fields)
        .filter(|entry| entry.availability == Availability::Always)
        .filter_map(|entry| (!field_is_populated(event, entry.field)).then_some(entry.field))
        .collect()
}

/// Populated fields which the matching event contract declares unavailable.
///
/// The detector accessor still filters these fields at read time. This check
/// makes the contradictory producer/contract state observable instead of
/// silently relying on that safety net forever.
pub fn populated_never_fields(event: &NormalizedEvent) -> Vec<&'static str> {
    event_contract(event)
        .into_iter()
        .flat_map(|contract| contract.fields)
        .filter(|entry| matches!(entry.availability, Availability::Never(_)))
        .filter_map(|entry| field_is_populated(event, entry.field).then_some(entry.field))
        .collect()
}

fn field_is_populated(event: &NormalizedEvent, field: &str) -> bool {
    if event.get_field_unchecked(field).is_some() {
        return true;
    }

    // The zero-allocation string accessor cannot borrow a formatted numeric
    // value. Keep the presence check typed for the one numeric model field.
    matches!(
        (&event.fields, field),
        (EventFields::ProcessCreation(fields), "ProcessStartTime")
            if fields.process_start_time.is_some()
    )
}

/// Flattened compatibility artifact generated from [`FIELD_AVAILABILITY`].
#[derive(Serialize)]
struct Baseline<'a> {
    schema_version: u16,
    entries: Vec<BaselineEntry<'a>>,
}

#[derive(Serialize)]
struct BaselineEntry<'a> {
    platform: Platform,
    category: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<SensorAction>,
    provider: &'a str,
    source: &'a str,
    field: &'a str,
    since: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
    #[serde(flatten)]
    availability: Availability,
}

pub fn compatibility_json() -> String {
    validate_since_versions();
    let entries = FIELD_AVAILABILITY
        .iter()
        .flat_map(|contract| {
            contract.fields.iter().map(|field| BaselineEntry {
                platform: contract.platform,
                category: contract.category,
                event_id: contract.event_id,
                action: contract.action,
                provider: contract.provider,
                source: contract.source,
                field: field.field,
                since: field.since,
                value: field.value,
                availability: field.availability,
            })
        })
        .collect();
    let mut json = serde_json::to_string_pretty(&Baseline {
        schema_version: SCHEMA_VERSION,
        entries,
    })
    .expect("static field availability serializes");
    json.push('\n');
    json
}

fn validate_since_versions() {
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .expect("the Rustinel package version must be valid semver");
    for field in FIELD_AVAILABILITY
        .iter()
        .flat_map(|contract| contract.fields)
    {
        let Some(since) = field.since else {
            continue;
        };
        let version = Version::parse(since)
            .unwrap_or_else(|error| panic!("{} has invalid since {since:?}: {error}", field.field));
        assert!(
            version.pre.is_empty(),
            "{} since {since:?} is not a released version",
            field.field
        );
        assert!(
            version <= current,
            "{} since {since:?} is newer than Rustinel {current}",
            field.field
        );
    }
}

fn key_label(contract: &EventFieldContract) -> String {
    let selector = match (contract.event_id, contract.action) {
        (Some(id), Some(action)) => format!("{id} / {action:?}"),
        (Some(id), None) => id.to_string(),
        (None, Some(action)) => format!("{action:?}"),
        (None, None) => "all".to_string(),
    };
    selector.to_ascii_lowercase()
}

/// Generated permanent-gap table embedded in `docs/field-availability.md`.
pub fn unavailable_fields_markdown() -> String {
    use std::collections::BTreeMap;

    let mut output = String::from(
        "<!-- BEGIN GENERATED FIELD AVAILABILITY -->\n\
This table is generated from `FIELD_AVAILABILITY` in `src/field_availability.rs`.\n\
Edit that table and run `cargo run --bin generate-docs`.\n\n\
| Platform | Category | Event / action | Source | Unavailable field | Reason |\n\
| --- | --- | --- | --- | --- | --- |\n",
    );
    let mut rows: BTreeMap<(&str, &str, &str, &str, &str), Vec<String>> = BTreeMap::new();
    for contract in FIELD_AVAILABILITY {
        for field in contract.fields {
            let Availability::Never(reason) = field.availability else {
                continue;
            };
            rows.entry((
                contract.platform.as_str(),
                contract.category,
                contract.source,
                field.field,
                reason,
            ))
            .or_default()
            .push(key_label(contract));
        }
    }
    for ((platform, category, source, field, reason), mut selectors) in rows {
        selectors.sort();
        selectors.dedup();
        output.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | `{}` | {} |\n",
            platform,
            category,
            selectors.join(", "),
            source,
            field,
            reason
        ));
    }
    output.push_str("<!-- END GENERATED FIELD AVAILABILITY -->\n");
    output
}

/// Generated availability summary embedded in `docs/coverage.md`.
pub fn coverage_markdown() -> String {
    let mut output = String::from(
        "<!-- BEGIN GENERATED FIELD AVAILABILITY -->\n\
Generated from `FIELD_AVAILABILITY`.\n\
These count fields, not rules: a rule that references a `Never` field inside an `or` branch can still fire.\n\n\
| Platform | Always | Conditional | Never |\n\
| --- | ---: | ---: | ---: |\n",
    );
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOS] {
        let mut counts = [0usize; 3];
        for availability in FIELD_AVAILABILITY
            .iter()
            .filter(|contract| contract.platform == platform)
            .flat_map(|contract| contract.fields.iter().map(|field| field.availability))
        {
            match availability {
                Availability::Always => counts[0] += 1,
                Availability::Conditional(_) => counts[1] += 1,
                Availability::Never(_) => counts[2] += 1,
            }
        }
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            platform.as_str(),
            counts[0],
            counts[1],
            counts[2]
        ));
    }
    output.push_str(
        "\nThe complete machine-readable baseline is \
[`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).\n\
<!-- END GENERATED FIELD AVAILABILITY -->\n",
    );
    output
}
