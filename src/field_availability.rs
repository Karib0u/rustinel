//! Machine-readable field availability for every sensor event shape.
//!
//! This is the source of truth for field-level compatibility. Keep limitations
//! here rather than in a decoder comment or a hand-maintained documentation
//! list: `doctor`, the generated compatibility baseline, and the generated
//! documentation all consume [`FIELD_AVAILABILITY`].

use serde::Serialize;

use crate::models::{EventCategory, EventFields, NormalizedEvent};
use crate::sensor::{Platform, SensorAction};

pub const SCHEMA_VERSION: u16 = 1;

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

const fn always(field: &'static str) -> FieldContract {
    FieldContract {
        field,
        availability: Availability::Always,
    }
}

const fn conditional(field: &'static str, reason: &'static str) -> FieldContract {
    FieldContract {
        field,
        availability: Availability::Conditional(reason),
    }
}

const fn never(field: &'static str, reason: &'static str) -> FieldContract {
    FieldContract {
        field,
        availability: Availability::Never(reason),
    }
}

const WINDOWS_PROCESS: &[FieldContract] = &[
    always("ProcessId"),
    conditional("Image", "the provider may omit the image path"),
    conditional(
        "CommandLine",
        "queried from the live process and lost if it exits first",
    ),
    conditional(
        "ProcessStartTime",
        "the event template may omit the native creation time",
    ),
    conditional(
        "ParentProcessId",
        "the event template may omit parent identity",
    ),
    conditional(
        "ParentImage",
        "present in the event or derived from the process cache",
    ),
    conditional(
        "ParentCommandLine",
        "derived from the process cache when the parent is still known",
    ),
    conditional(
        "IntegrityLevel",
        "available only on process-start templates with a MandatoryLabel SID",
    ),
    conditional(
        "OriginalFileName",
        "PE version-resource enrichment succeeds",
    ),
    conditional("Product", "PE version-resource enrichment succeeds"),
    conditional("Description", "PE version-resource enrichment succeeds"),
    conditional("Company", "PE version-resource enrichment succeeds"),
    conditional("FileVersion", "PE version-resource enrichment succeeds"),
    never(
        "CgroupId",
        "Windows process events do not have a Linux kernel cgroup identifier",
    ),
    never(
        "User",
        "Microsoft-Windows-Kernel-Process does not expose process user identity",
    ),
    never(
        "CurrentDirectory",
        "Microsoft-Windows-Kernel-Process does not expose the working directory",
    ),
    never(
        "TargetImage",
        "a process-creation event has no target process",
    ),
    never("Hashes", "process images are not hashed by this collector"),
    never("Imphash", "process images are not hashed by this collector"),
];

const WINDOWS_IMAGE_LOAD: &[FieldContract] = &[
    conditional("ImageLoaded", "the provider may omit the loaded image path"),
    conditional("ProcessId", "the provider may omit process identity"),
    conditional("Image", "the provider may omit the loading process image"),
    conditional(
        "OriginalFileName",
        "PE version-resource enrichment succeeds",
    ),
    conditional("Product", "PE version-resource enrichment succeeds"),
    conditional("Description", "PE version-resource enrichment succeeds"),
    conditional("Company", "PE version-resource enrichment succeeds"),
    conditional("FileVersion", "PE version-resource enrichment succeeds"),
    never(
        "Signed",
        "Kernel-Process image-load events contain no Authenticode result",
    ),
    never(
        "Signature",
        "Kernel-Process image-load events contain no signer identity",
    ),
    never(
        "User",
        "Kernel-Process image-load events contain no user identity",
    ),
    never("Hashes", "loaded images are not hashed by this collector"),
    never("Imphash", "loaded images are not hashed by this collector"),
];

const WINDOWS_NETWORK: &[FieldContract] = &[
    conditional(
        "DestinationIp",
        "the provider event template must carry the remote address",
    ),
    conditional(
        "SourceIp",
        "the provider event template must carry the local address",
    ),
    conditional(
        "DestinationPort",
        "the provider event template must carry the remote port",
    ),
    conditional(
        "SourcePort",
        "the provider event template must carry the local port",
    ),
    always("ProcessId"),
    always("Protocol"),
    always("Initiated"),
    conditional(
        "Image",
        "present in the event or derived from the process cache",
    ),
    conditional("User", "the provider event template carries user identity"),
    conditional(
        "DestinationHostname",
        "derived from a preceding observed DNS answer",
    ),
];

const WINDOWS_FILE: &[FieldContract] = &[
    always("TargetFilename"),
    conditional(
        "ProcessId",
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        "present in the event or derived from the process cache",
    ),
    conditional("User", "the provider event template carries user identity"),
    never(
        "SourceFilename",
        "Kernel-File does not provide the old name on emitted rename events",
    ),
    never(
        "CreationUtcTime",
        "Kernel-File reports the information class, not the new timestamp",
    ),
    never(
        "PreviousCreationUtcTime",
        "Kernel-File reports the information class, not the old timestamp",
    ),
    never(
        "PathTruncated",
        "ETW delivers a complete path or no attributable event",
    ),
];

const WINDOWS_REGISTRY: &[FieldContract] = &[
    always("TargetObject"),
    conditional(
        "Details",
        "captured registry value data is available and renderable",
    ),
    conditional(
        "ProcessId",
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        "present in the event or derived from the process cache",
    ),
    conditional(
        "EventType",
        "the provider event template carries the event type",
    ),
    conditional("User", "the provider event template carries user identity"),
    conditional(
        "NewName",
        "the operation is a rename and the provider carries the new name",
    ),
];

const WINDOWS_DNS: &[FieldContract] = &[
    conditional(
        "QueryName",
        "the DNS Client event template carries a query name",
    ),
    conditional(
        "QueryResults",
        "the event is a response carrying decoded answers",
    ),
    conditional(
        "QueryStatus",
        "the DNS Client event template carries a status",
    ),
    conditional(
        "ProcessId",
        "the DNS Client event template carries process identity",
    ),
    conditional(
        "Image",
        "present in the event or derived from the process cache",
    ),
    never(
        "RecordType",
        "the subscribed DNS Client events do not expose the query record type",
    ),
];

const WINDOWS_POWERSHELL_SCRIPT: &[FieldContract] = &[
    conditional("ScriptBlockText", "event 4104 contains a script block"),
    conditional(
        "ScriptBlockId",
        "event 4104 contains a script-block identifier",
    ),
    conditional("Path", "the script block is associated with a file"),
    conditional(
        "ProcessId",
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        "present in the event or derived from the process cache",
    ),
    conditional("User", "the provider event template carries user identity"),
];

const WINDOWS_POWERSHELL_MODULE: &[FieldContract] = &[
    conditional(
        "ContextInfo",
        "Module Logging is enabled and event 4103 carries context",
    ),
    conditional(
        "Payload",
        "Module Logging is enabled and event 4103 carries a payload",
    ),
    conditional(
        "ProcessId",
        "the provider event template carries process identity",
    ),
    conditional(
        "Image",
        "present in the event or derived from the process cache",
    ),
    conditional("User", "the provider event template carries user identity"),
];

const WINDOWS_WMI: &[FieldContract] = &[
    conditional(
        "Operation",
        "the native WMI event family carries an operation",
    ),
    conditional("User", "the native WMI event family carries user identity"),
    conditional(
        "Query",
        "the native WMI event family carries a query or command line",
    ),
    conditional(
        "ProcessId",
        "the native WMI event family carries client process identity",
    ),
    conditional(
        "Image",
        "present in the event or derived from the process cache",
    ),
    conditional(
        "EventNamespace",
        "the native WMI event family carries a namespace",
    ),
    conditional(
        "EventType",
        "the native WMI event family carries an event type",
    ),
    conditional(
        "DestinationHostname",
        "the native WMI event family carries a client machine",
    ),
];

const WINDOWS_TASK: &[FieldContract] = &[
    conditional("TaskName", "TaskScheduler event 106 carries a task name"),
    conditional("UserName", "TaskScheduler event 106 carries user context"),
    never(
        "TaskContent",
        "TaskScheduler event 106 does not carry the task XML definition",
    ),
    never(
        "User",
        "TaskScheduler event 106 has UserContext, not a Sysmon User field",
    ),
    never(
        "ProcessId",
        "TaskScheduler event 106 does not carry process identity",
    ),
    never(
        "Image",
        "TaskScheduler event 106 does not carry a process image",
    ),
];

const WINDOWS_SERVICE: &[FieldContract] = &[
    always("Provider_Name"),
    always("ServiceName"),
    always("ServiceFileName"),
    always("ImagePath"),
    conditional("ServiceType", "System event 7045 carries a service type"),
    conditional("StartType", "System event 7045 carries a start type"),
    conditional("AccountName", "System event 7045 carries an account name"),
    conditional(
        "User",
        "the Event Log system header carries a security user ID",
    ),
    never(
        "ProcessId",
        "System event 7045 does not carry process identity",
    ),
    never(
        "Image",
        "System event 7045 does not carry a creating process image",
    ),
];

const SECURITY_FIELD_REASON: &str =
    "the audited event template and host audit policy supply this field";

macro_rules! security_fields {
    ($($field:literal),+ $(,)?) => {
        &[
            conditional("SubjectUserSid", SECURITY_FIELD_REASON),
            conditional("SubjectUserName", SECURITY_FIELD_REASON),
            conditional("SubjectDomainName", SECURITY_FIELD_REASON),
            conditional("SubjectLogonId", SECURITY_FIELD_REASON),
            $(conditional($field, SECURITY_FIELD_REASON)),+
        ]
    };
}

const WINDOWS_SECURITY_4624: &[FieldContract] = security_fields!(
    "TargetUserSid",
    "TargetUserName",
    "TargetDomainName",
    "TargetLogonId",
    "LogonType",
    "LogonProcessName",
    "AuthenticationPackageName",
    "WorkstationName",
    "LogonGuid",
    "LmPackageName",
    "KeyLength",
    "ProcessId",
    "ProcessName",
    "IpAddress",
    "IpPort",
    "ImpersonationLevel",
    "RestrictedAdminMode",
    "TargetOutboundUserName",
    "TargetOutboundDomainName",
    "VirtualAccount",
    "TargetLinkedLogonId",
    "ElevatedToken",
);
const WINDOWS_SECURITY_4656: &[FieldContract] = security_fields!(
    "ObjectServer",
    "ObjectType",
    "ObjectName",
    "HandleId",
    "AccessList",
    "AccessMask",
    "AccessReason",
    "PrivilegeList",
    "ProcessId",
    "ProcessName",
);
const WINDOWS_SECURITY_4663: &[FieldContract] = security_fields!(
    "ObjectServer",
    "ObjectType",
    "ObjectName",
    "HandleId",
    "AccessList",
    "AccessMask",
    "ProcessId",
    "ProcessName",
);
const WINDOWS_SECURITY_4697: &[FieldContract] = security_fields!(
    "ServiceName",
    "ServiceFileName",
    "ServiceType",
    "ServiceStartType",
    "ServiceAccount",
);
const WINDOWS_SECURITY_5136: &[FieldContract] = security_fields!(
    "DSName",
    "DSType",
    "ObjectDN",
    "ObjectGUID",
    "ObjectClass",
    "AttributeLDAPDisplayName",
    "AttributeSyntaxOID",
    "AttributeValue",
    "OperationType",
);
const WINDOWS_SECURITY_5145: &[FieldContract] = security_fields!(
    "ObjectType",
    "IpAddress",
    "IpPort",
    "ShareName",
    "ShareLocalPath",
    "RelativeTargetName",
    "AccessMask",
    "AccessList",
    "AccessReason",
);

const LINUX_PROCESS: &[FieldContract] = &[
    always("Image"),
    always("ImageSource"),
    always("ProcessId"),
    always("RealUserId"),
    always("RealGroupId"),
    conditional(
        "EffectiveUserId",
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "EffectiveGroupId",
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "MountNamespace",
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "PidNamespace",
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "NetworkNamespace",
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "SessionId",
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "KernelStartBoottime",
        "runtime BTF resolves this field and the kernel read succeeds",
    ),
    conditional(
        "ControllingTty",
        "runtime BTF resolves terminal fields and the process has a controlling terminal",
    ),
    conditional(
        "User",
        "runtime BTF resolves effective credentials and the kernel read succeeds",
    ),
    conditional(
        "ImageTruncated",
        "the raw exec filename exceeded the kernel capture buffer",
    ),
    conditional(
        "CommandLine",
        "kernel argv capture or the live /proc entry is available",
    ),
    conditional("ParentProcessId", "the live /proc entry is available"),
    conditional(
        "ParentImage",
        "measured at fork or available from process state",
    ),
    conditional(
        "ParentCommandLine",
        "measured at fork or available from process state",
    ),
    conditional("CurrentDirectory", "the live /proc entry is available"),
    conditional(
        "CgroupId",
        "the kernel reports a non-zero cgroup identifier at exec time",
    ),
    never("OriginalFileName", "PE version resources are Windows-only"),
    never("Product", "PE version resources are Windows-only"),
    never("Description", "PE version resources are Windows-only"),
    never("Company", "PE version resources are Windows-only"),
    never("FileVersion", "PE version resources are Windows-only"),
    never(
        "IntegrityLevel",
        "Windows integrity levels do not exist on Linux",
    ),
    never(
        "TargetImage",
        "a process-creation event has no target process",
    ),
];

const LINUX_NETWORK: &[FieldContract] = &[
    always("DestinationIp"),
    always("DestinationPort"),
    always("ProcessId"),
    conditional(
        "User",
        "runtime BTF resolves effective credentials and the kernel read succeeds",
    ),
    always("Initiated"),
    conditional(
        "Protocol",
        "the socket fexit tier is active and sk_protocol names TCP or UDP",
    ),
    conditional(
        "Image",
        "the process identity is still present in the process cache",
    ),
    conditional(
        "DestinationHostname",
        "a preceding observed DNS answer resolves the destination",
    ),
    conditional(
        "SourceIp",
        "the socket fexit tier measures the bound source address",
    ),
    conditional(
        "SourcePort",
        "the socket fexit tier measures the bound source port",
    ),
];

const LINUX_FILE: &[FieldContract] = &[
    always("TargetFilename"),
    always("ProcessId"),
    conditional(
        "User",
        "runtime BTF resolves effective credentials and the kernel read succeeds",
    ),
    conditional(
        "SourceFilename",
        "the action is rename and the old path can be resolved",
    ),
    conditional(
        "Image",
        "the process identity is still present in the process cache",
    ),
    conditional(
        "PathTruncated",
        "the kernel path buffer truncated a source or target",
    ),
    never(
        "CreationUtcTime",
        "the eBPF file probes do not read file timestamps",
    ),
    never(
        "PreviousCreationUtcTime",
        "the eBPF file probes do not read file timestamps",
    ),
];

const LINUX_DNS: &[FieldContract] = &[
    always("RecordType"),
    always("ProcessId"),
    conditional(
        "QueryName",
        "the DNS question can be parsed or the kernel fallback is non-empty",
    ),
    never(
        "QueryResults",
        "the eBPF DNS probe emits outbound queries and does not parse responses",
    ),
    conditional(
        "Image",
        "the process identity is still present in the process cache",
    ),
    never(
        "QueryStatus",
        "the eBPF DNS probe does not parse response status",
    ),
];

const MACOS_PROCESS: &[FieldContract] = &[
    always("Image"),
    always("ProcessId"),
    always("ProcessStartTime"),
    always("User"),
    conditional("CommandLine", "ESF supplies at least one exec argument"),
    conditional("ParentProcessId", "the parent PID is non-zero"),
    conditional(
        "ParentImage",
        "derived from the process cache by an observed stable parent identity",
    ),
    conditional(
        "ParentCommandLine",
        "the stable parent identity resolves to a cached command line",
    ),
    always("RealUserId"),
    always("Signed"),
    always("SignatureStatus"),
    always("CodeSigningFlags"),
    always("IsPlatformBinary"),
    conditional(
        "PreExecImage",
        "ESF supplies a non-empty acting process executable path",
    ),
    conditional(
        "Script",
        "message version 2+ supplies a script for direct shebang execution",
    ),
    conditional("SigningId", "ESF supplies a non-empty signing identifier"),
    conditional("TeamId", "ESF supplies a non-empty signing team identifier"),
    conditional("CdHash", "the executable has the CS_SIGNED flag"),
    conditional("CurrentDirectory", "ESF supplies an exec working directory"),
    never(
        "CgroupId",
        "macOS process events do not have a Linux kernel cgroup identifier",
    ),
    never("ImageSource", "ESF supplies the executable path directly"),
    never(
        "ImageTruncated",
        "ESF does not use the Linux raw-image buffer",
    ),
    never(
        "IntegrityLevel",
        "Windows integrity levels do not exist on macOS",
    ),
    never(
        "TargetImage",
        "a process-creation event has no target process",
    ),
    never("OriginalFileName", "PE version resources are Windows-only"),
    never("Product", "PE version resources are Windows-only"),
    never("Description", "PE version resources are Windows-only"),
    never("Company", "PE version resources are Windows-only"),
    never("FileVersion", "PE version resources are Windows-only"),
];

const MACOS_FILE: &[FieldContract] = &[
    always("TargetFilename"),
    always("ProcessId"),
    always("User"),
    conditional("SourceFilename", "the ESF action is a rename"),
    conditional("Image", "ESF supplies the acting process executable path"),
    never(
        "CreationUtcTime",
        "ESF file notifications do not carry file timestamps",
    ),
    never(
        "PreviousCreationUtcTime",
        "ESF file notifications do not carry file timestamps",
    ),
    never(
        "PathTruncated",
        "ESF paths are not copied through a fixed Rustinel buffer",
    ),
];

const MACOS_NETWORK: &[FieldContract] = &[
    always("DestinationIp"),
    always("SourceIp"),
    always("DestinationPort"),
    always("SourcePort"),
    always("Protocol"),
    conditional(
        "ProcessId",
        "bounded socket-inventory attribution finds the owner",
    ),
    conditional(
        "Image",
        "bounded socket-inventory attribution finds the owner",
    ),
    conditional(
        "DestinationHostname",
        "a preceding observed DNS answer resolves the destination",
    ),
    never("User", "BPF packets do not carry process user identity"),
    never(
        "Initiated",
        "a wire capture cannot determine whether the local host initiated the flow",
    ),
];

const MACOS_DNS: &[FieldContract] = &[
    always("QueryName"),
    conditional(
        "RecordType",
        "the DNS qtype has a known Sysmon-compatible name",
    ),
    never(
        "QueryResults",
        "the BPF DNS path emits queries, not responses",
    ),
    never(
        "QueryStatus",
        "the BPF DNS path emits queries, not responses",
    ),
    never(
        "ProcessId",
        "BPF DNS packets are not attributed to processes",
    ),
    never("Image", "BPF DNS packets are not attributed to processes"),
];

const PIPE_CREATED: &[FieldContract] = &[never(
    "*",
    "named-pipe activity is not carried by Microsoft-Windows-Kernel-File and is not available from ETW",
)];

const CREATE_REMOTE_THREAD: &[FieldContract] = &[never(
    "*",
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
        Some(22),
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
        "socket send tracepoints",
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

/// Find an event contract when the native decoder has not yet assigned an
/// action. Event ID must make the key unique; this is used by the Security
/// channel decoder as its field allowlist.
pub fn contract_for_event_id(
    platform: Platform,
    category: &str,
    event_id: u16,
    provider: &str,
) -> Option<&'static EventFieldContract> {
    FIELD_AVAILABILITY.iter().find(|contract| {
        contract.platform == platform
            && contract.category == category
            && contract.event_id == Some(event_id)
            && contract.provider == provider
    })
}

fn event_contract(event: &NormalizedEvent) -> Option<&'static EventFieldContract> {
    FIELD_AVAILABILITY.iter().find(|contract| {
        contract.platform == event.platform
            && contract.category == category_name(event.category)
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
        SensorAction::Disconnect | SensorAction::Access => true,
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
    #[serde(flatten)]
    availability: Availability,
}

pub fn compatibility_json() -> String {
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

fn key_label(contract: &EventFieldContract) -> String {
    let selector = match (contract.event_id, contract.action) {
        (Some(id), Some(action)) => format!("{id} / {action:?}"),
        (Some(id), None) => id.to_string(),
        (None, Some(action)) => format!("{action:?}"),
        (None, None) => "all".to_string(),
    };
    selector.to_ascii_lowercase()
}

/// Generated permanent-gap table embedded in `docs/limitations.md`.
pub fn limitations_markdown() -> String {
    use std::collections::BTreeMap;

    let mut output = String::from(
        "<!-- BEGIN GENERATED FIELD AVAILABILITY -->\n\
The per-field list below is generated from `FIELD_AVAILABILITY`; edit the Rust\n\
table and run `cargo run --bin generate-field-availability`, not this section.\n\n\
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
This summary is generated from `FIELD_AVAILABILITY`. Counts describe field\n\
contracts, not Sigma rule inertness; alternatives and negation in a rule's\n\
condition must be analysed before deciding whether that rule can fire.\n\n\
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
        "\nThe complete machine-readable baseline is\n\
[`compatibility/field-availability.json`](../compatibility/field-availability.json).\n\
<!-- END GENERATED FIELD AVAILABILITY -->\n",
    );
    output
}
