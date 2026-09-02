use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, TraceBuilder, TraceProperties, TraceTrait, UserTrace};
use ferrisetw::{EventRecord, GUID};
use tokio::sync::mpsc::{error::TrySendError, Sender};
use tracing::{debug, info, trace, warn};

use crate::models::{
    DnsQueryFields, EventCategory, FileEventFields, ImageLoadFields, NetworkConnectionFields,
    PowerShellModuleFields, PowerShellScriptFields, ProcessCreationFields, RegistryEventFields,
    TaskCreationFields, WmiEventFields,
};
use crate::sensor::integrity_level::integrity_level_from_sid;
use crate::sensor::network_events::{
    classify_kernel_network_event, decode_etw_ipv4, decode_etw_port, NetworkAddressFamily,
};
use crate::sensor::{Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorPayload};
use crate::utils::pe;
use crate::utils::{convert_nt_to_dos, parse_metadata, query_process_command_line};

use super::event_log::EventLogSubscriptions;
use super::file_paths::FilePathCache;
use super::registry_paths::RegistryPathCache;
use super::{field_maps, mapper, registry_value_data};

/// Fixed trace session name for stopping the trace on shutdown.
pub(super) const TRACE_SESSION_NAME: &str = "rustinel-etw-trace";

/// Session name for the dedicated `Microsoft-Windows-Kernel-Process` trace.
///
/// Process events are collected in their own session because they are the only
/// ones with a *latency* requirement: `CommandLine` is not carried by any
/// Kernel-Process event version, so it is read back out of the PEB in
/// [`decode_process`], and that read only succeeds while the process is still
/// alive. `cmd /c echo` lives 10-30 ms. Every other provider needs the
/// opposite - the wide buffer pool of [`session_properties`], which is what
/// makes a buffer take a long time to fill and be handed over. One session
/// cannot satisfy both; two can. See [`process_session_properties`] and
/// [`super::flush`], which flushes this session four times as often.
pub(super) const PROCESS_TRACE_SESSION_NAME: &str = "rustinel-etw-process";
const WINDOWS_EPOCH_DELTA_100NS: i64 = 116444736000000000;

/// Size of one ETW session buffer, in KB.
///
/// `ferrisetw` defaults to 32 KB with the buffer counts left at 0, which lets
/// the kernel pick them — in practice 2 to 24 buffers, a 768 KB ceiling. That
/// ceiling cannot absorb a burst. On a Windows 11 lab VM (6 vCPU, 8 GB), a
/// 4,000-process fork tree lost 12-60% of process starts on the defaults across
/// four runs, and none at all on the values here; the workload and the full
/// table are in `docs/operations.md`.
///
/// The loss is kernel-side, so no per-field fix reaches it — it degrades
/// `CommandLine`, `ParentImage` and every other process field at once, and a
/// lost *parent* start costs `ParentImage` on all of that process's children.
/// Larger buffers are what helps: the cost of a burst is buffer *turnover*, and
/// 256 KB holds eight times the events per flush. See [`SESSION_MIN_BUFFERS`]
/// for the memory this commits.
const SESSION_BUFFER_SIZE_KB: u32 = 256;

/// Buffers committed when the session starts.
///
/// ETW session buffers are non-paged pool, allocated up front for the minimum
/// and grown on demand to [`SESSION_MAX_BUFFERS`]. 64 x 256 KB is 16 MB
/// resident — deliberately paid at startup rather than during the burst,
/// because growing the pool is exactly the work that is too slow when a fork
/// tree is already filling buffers.
const SESSION_MIN_BUFFERS: u32 = 64;

/// Upper bound on the buffer pool: 128 x 256 KB = 32 MB.
///
/// 42x the default ceiling. This is a fixed configuration on purpose — adaptive
/// sizing is not warranted until a single configuration is shown not to cover
/// realistic hosts.
const SESSION_MAX_BUFFERS: u32 = 128;

/// How often partially filled buffers are flushed to the consumer.
///
/// One second is the ETW minimum. It bounds the delay on a *quiet* host, where
/// buffers would otherwise sit unfilled; under load buffers flush as soon as
/// they fill, so this does not affect burst behaviour either way.
const SESSION_FLUSH_TIMER: Duration = Duration::from_secs(1);

/// Buffer configuration for the real-time session.
///
/// Everything else is inherited from `ferrisetw`'s defaults, in particular the
/// logging mode: `EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING` is kept on purpose.
/// Per-processor buffering would raise raw throughput, but it delivers events
/// per CPU rather than in timestamp order, and both [`FilePathCache`] and
/// [`RegistryPathCache`] resolve a path by pairing a naming event with a later
/// event on the same object — reordering those silently mis-attributes paths.
/// A wider buffer pool buys the same headroom without touching ordering.
fn session_properties() -> TraceProperties {
    TraceProperties {
        buffer_size: SESSION_BUFFER_SIZE_KB,
        min_buffer: SESSION_MIN_BUFFERS,
        max_buffer: SESSION_MAX_BUFFERS,
        flush_timer: SESSION_FLUSH_TIMER,
        ..TraceProperties::default()
    }
}

/// Size of one buffer on the Kernel-Process session, in KB.
///
/// The small buffer is the point of the second session. A buffer is handed to
/// the consumer when it fills, and a 256 KB buffer carrying only process and
/// image-load events takes far longer to fill than a 32 KB one - on a quiet
/// host it never does, and delivery falls back on the flush timer. That is the
/// regression #349 describes: the back-fill race window went from ~8-16 ms to
/// ~100 ms-1 s when #312 widened the shared session, and a `cmd /c echo` exits
/// inside it. 32 KB is the value that measured 15/15 short-lived command lines
/// in 1.3.0.
const PROCESS_SESSION_BUFFER_SIZE_KB: u32 = 32;

/// Buffers committed when the Kernel-Process session starts: 2 MB.
const PROCESS_SESSION_MIN_BUFFERS: u32 = 64;

/// Upper bound on the Kernel-Process buffer pool: 512 x 32 KB = 16 MB.
///
/// The buffer counts are set explicitly for the same reason [`session_properties`]
/// sets them: left at `0` the kernel picks at most 24 buffers, a 768 KB ceiling
/// that lost 12-60% of process starts under a fork tree (#312). Small buffers
/// and a deep pool are not in tension - the first bounds latency, the second
/// bounds burst loss - so this session keeps 1.3.0's latency without giving up
/// #312's headroom for the events that matter most to it.
const PROCESS_SESSION_MAX_BUFFERS: u32 = 512;

/// Buffer configuration for the dedicated Kernel-Process session.
///
/// Deliberately close to `ferrisetw`'s defaults, which is what Rustinel ran on
/// before #312: the same 32 KB buffer and the same one-second flush timer, with
/// only the pool depth raised. The logging mode is inherited for the same
/// reason as the main session - event order within a session is load-bearing -
/// though nothing on this session pairs events the way the path caches do.
fn process_session_properties() -> TraceProperties {
    TraceProperties {
        buffer_size: PROCESS_SESSION_BUFFER_SIZE_KB,
        min_buffer: PROCESS_SESSION_MIN_BUFFERS,
        max_buffer: PROCESS_SESSION_MAX_BUFFERS,
        flush_timer: SESSION_FLUSH_TIMER,
        ..TraceProperties::default()
    }
}

/// ETW provider metadata.
#[derive(Debug, Clone)]
struct EtwProvider {
    guid: GUID,
    name: &'static str,
    level: u8,
    keywords: u64,
    event_ids: &'static [u16],
}

struct EtwProviders;

impl EtwProviders {
    const KERNEL_PROCESS_GUID: &'static str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
    const KERNEL_NETWORK_GUID: &'static str = "7dd42a49-5329-4832-8dfd-43d979153a88";
    const KERNEL_FILE_GUID: &'static str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
    const KERNEL_REGISTRY_GUID: &'static str = "70eb4f03-c1de-4f73-a051-33d13d5413bd";
    const DNS_CLIENT_GUID: &'static str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
    const POWERSHELL_GUID: &'static str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
    const WMI_ACTIVITY_GUID: &'static str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";
    const TASK_SCHEDULER_GUID: &'static str = "de7b24ea-73c8-4a09-985d-5bdadcfa9017";

    // Keyword names follow the Microsoft-Windows-Kernel-File manifest.
    const KERNEL_FILE_KEYWORD_FILENAME: u64 = 0x0010;
    /// Enables Cleanup (13), Close (14), Read (15), SetInformation (17), and
    /// the query paths. Needed for two things that are otherwise impossible:
    /// `Close`, which is when a `FileObject` may be released from the path
    /// index, and `SetInformation`, which is the only report of truncation or
    /// of a creation-time change. It also turns on high-volume read and query
    /// events, so [`kernel_file_route`] drops those before the schema lookup.
    const KERNEL_FILE_KEYWORD_FILEIO: u64 = 0x0020;
    const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x0080;
    const KERNEL_FILE_KEYWORD_WRITE: u64 = 0x0200;
    const KERNEL_FILE_KEYWORD_DELETE_PATH: u64 = 0x0400;
    const KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH: u64 = 0x0800;
    const FILE_KEYWORDS: u64 = Self::KERNEL_FILE_KEYWORD_FILENAME
        | Self::KERNEL_FILE_KEYWORD_FILEIO
        | Self::KERNEL_FILE_KEYWORD_CREATE
        | Self::KERNEL_FILE_KEYWORD_WRITE
        | Self::KERNEL_FILE_KEYWORD_DELETE_PATH
        | Self::KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH;

    // Keyword names and values follow the Microsoft-Windows-Kernel-Registry
    // manifest. The values used before #279 were off by a whole nibble:
    // `SetValueKey` is 0x100 and `DeleteValueKey` 0x200, not 0x2000 and
    // 0x8000, which are `OpenKey` and `QueryKey`. The session subscribed to
    // two read paths and to neither value write, so `registry_set` could not
    // have fired even with correct classification.
    const REG_KEYWORD_CLOSE_KEY: u64 = 0x0001;
    const REG_KEYWORD_SET_VALUE_KEY: u64 = 0x0100;
    const REG_KEYWORD_DELETE_VALUE_KEY: u64 = 0x0200;
    const REG_KEYWORD_CREATE_KEY: u64 = 0x1000;
    /// `OpenKey` produces no telemetry of its own. It is subscribed because it
    /// is a *naming* event: `SetValueKey` and friends deliver an empty
    /// `KeyName`, and most writes land on keys that were opened rather than
    /// created, so without this their path is unrecoverable. `CloseKey` is the
    /// matching eviction point. See [`super::registry_paths`].
    const REG_KEYWORD_OPEN_KEY: u64 = 0x2000;
    const REG_KEYWORD_DELETE_KEY: u64 = 0x4000;
    const REGISTRY_KEYWORDS: u64 = Self::REG_KEYWORD_CLOSE_KEY
        | Self::REG_KEYWORD_SET_VALUE_KEY
        | Self::REG_KEYWORD_DELETE_VALUE_KEY
        | Self::REG_KEYWORD_CREATE_KEY
        | Self::REG_KEYWORD_OPEN_KEY
        | Self::REG_KEYWORD_DELETE_KEY;

    const WINEVENT_KEYWORD_PROCESS: u64 = 0x0010;
    const WINEVENT_KEYWORD_IMAGE: u64 = 0x0040;
    const PROCESS_KEYWORDS: u64 = Self::WINEVENT_KEYWORD_PROCESS | Self::WINEVENT_KEYWORD_IMAGE;

    const NETWORK_KEYWORD_TCPIP: u64 = 0x10;
    const NETWORK_KEYWORD_UDP: u64 = 0x20;
    const NETWORK_KEYWORDS: u64 = Self::NETWORK_KEYWORD_TCPIP | Self::NETWORK_KEYWORD_UDP;

    // Manifest-derived provider scopes. The channel keyword is required for
    // providers whose useful events live in an Operational channel. Event ID
    // filters then keep lifecycle and diagnostic records out of the session.
    const OPERATIONAL_KEYWORD: u64 = 0x8000_0000_0000_0000;
    const POWERSHELL_RUNSPACE_KEYWORD: u64 = 0x0000_0000_0000_0001;
    /// Module logging (4103) is published under `Cmdlets`, not `Runspace`:
    /// the manifest gives 4103 a keyword mask of `0x8000_0000_0000_0020` and
    /// 4104 one of `0x8000_0000_0000_0001`, and a session that asks for
    /// `Runspace` alone is never sent the module events at all. The event ID
    /// filter below is what keeps the rest of the `Cmdlets` traffic — the
    /// analytic command-lifecycle events, tens per interpreter run — out of
    /// the session buffers.
    const POWERSHELL_CMDLETS_KEYWORD: u64 = 0x0000_0000_0000_0020;
    const POWERSHELL_KEYWORDS: u64 =
        Self::POWERSHELL_RUNSPACE_KEYWORD | Self::POWERSHELL_CMDLETS_KEYWORD;
    const DNS_EVENT_IDS: &'static [u16] = &[3006, 3008];
    const POWERSHELL_EVENT_IDS: &'static [u16] = &[
        POWERSHELL_EVENT_MODULE_LOGGING,
        POWERSHELL_EVENT_SCRIPT_BLOCK,
    ];
    // Native WMI-Activity numbering is unrelated to Sysmon's, but both reach
    // the engine under `(windows, wmi, wmi_event)`, so any collected ID that
    // happens to equal a Sysmon `wmi_event` ID (19 = filter, 20 = consumer,
    // 21 = filter-to-consumer binding) makes stock SigmaHQ rules fire on the
    // wrong event. 19 and 20 are excluded for that reason (#291); mapping them
    // is not an option, because the native events do not carry the WMI
    // persistence fields those rules read.
    const WMI_EVENT_IDS: &'static [u16] = &[1, 2, 11, 12, 14, 15, 16, 17, 22, 23, 24];
    const TASK_EVENT_IDS: &'static [u16] = &[106];

    fn kernel_process() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_PROCESS_GUID),
            name: "Microsoft-Windows-Kernel-Process",
            level: 4,
            keywords: Self::PROCESS_KEYWORDS,
            event_ids: &[],
        }
    }

    fn kernel_network() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_NETWORK_GUID),
            name: "Microsoft-Windows-Kernel-Network",
            level: 4,
            keywords: Self::NETWORK_KEYWORDS,
            event_ids: &[],
        }
    }

    fn kernel_file() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_FILE_GUID),
            name: "Microsoft-Windows-Kernel-File",
            level: 4,
            keywords: Self::FILE_KEYWORDS,
            event_ids: &KERNEL_FILE_ROUTED_EVENT_IDS,
        }
    }

    fn kernel_registry() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_REGISTRY_GUID),
            name: "Microsoft-Windows-Kernel-Registry",
            level: 4,
            keywords: Self::REGISTRY_KEYWORDS,
            event_ids: &KERNEL_REGISTRY_ROUTED_EVENT_IDS,
        }
    }

    fn dns_client() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::DNS_CLIENT_GUID),
            name: "Microsoft-Windows-DNS-Client",
            level: 4,
            keywords: Self::OPERATIONAL_KEYWORD,
            event_ids: Self::DNS_EVENT_IDS,
        }
    }

    fn powershell() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::POWERSHELL_GUID),
            name: "Microsoft-Windows-PowerShell",
            // Script-block event 4104 is Verbose in the provider manifest;
            // module-logging event 4103 is Informational. An ETW level is a
            // ceiling, so Verbose collects both.
            level: 5,
            keywords: Self::POWERSHELL_KEYWORDS,
            event_ids: Self::POWERSHELL_EVENT_IDS,
        }
    }

    fn wmi_activity() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::WMI_ACTIVITY_GUID),
            name: "Microsoft-Windows-WMI-Activity",
            level: 4,
            keywords: Self::OPERATIONAL_KEYWORD,
            event_ids: Self::WMI_EVENT_IDS,
        }
    }

    fn task_scheduler() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::TASK_SCHEDULER_GUID),
            name: "Microsoft-Windows-TaskScheduler",
            level: 4,
            keywords: Self::OPERATIONAL_KEYWORD,
            event_ids: Self::TASK_EVENT_IDS,
        }
    }

    /// Providers on the dedicated low-latency session.
    ///
    /// Kernel-Process only, and deliberately so. Registry in particular must
    /// stay with the others: [`RegistryPathCache`] resolves a write's key by
    /// pairing it with the earlier `OpenKey` that named it, and that pairing
    /// only holds within one session's ordering. Process events are the one
    /// stream nothing else is paired against - arriving *earlier* than the rest
    /// is strictly better for `ProcessCache` enrichment, never worse.
    fn process_session() -> Vec<EtwProvider> {
        vec![Self::kernel_process()]
    }

    /// Providers on the main, burst-tolerant session.
    fn main_session() -> Vec<EtwProvider> {
        vec![
            Self::kernel_network(),
            Self::kernel_file(),
            Self::kernel_registry(),
            Self::dns_client(),
            Self::powershell(),
            Self::wmi_activity(),
            Self::task_scheduler(),
        ]
    }

    #[cfg(test)]
    fn all() -> Vec<EtwProvider> {
        vec![
            Self::kernel_process(),
            Self::kernel_network(),
            Self::kernel_file(),
            Self::kernel_registry(),
            Self::dns_client(),
            Self::powershell(),
            Self::wmi_activity(),
            Self::task_scheduler(),
        ]
    }
}

/// The event IDs [`kernel_file_route`] accepts, pushed down to the provider as a
/// scope filter so the rest are never written into the session at all.
///
/// This does not measurably reduce sensor CPU — the unrouted events were already
/// rejected on an integer match before the schema lookup — but it roughly halves
/// the ETW buffer volume the kernel moves on our behalf, which is worth having
/// for free. Kept in sync with `kernel_file_route` by
/// `filter_matches_routing_allowlist`; a drift would silently delete detections.
const KERNEL_FILE_ROUTED_EVENT_IDS: [u16; 9] = [10, 11, 12, 14, 16, 17, 26, 27, 28];

/// Microsoft-Windows-PowerShell manifest event IDs.
///
/// The two carry different Sigma logsources — 4104 is `ps_script`, 4103 is
/// `ps_module` — and different templates, so they are routed apart before
/// decoding rather than sharing one PowerShell payload.
const POWERSHELL_EVENT_MODULE_LOGGING: u16 = 4103;
const POWERSHELL_EVENT_SCRIPT_BLOCK: u16 = 4104;

/// One provider, two Sigma logsources: the event ID is the only thing that
/// separates script block logging from module logging, so the PowerShell
/// provider cannot be routed on its GUID like the others. Kept in sync with
/// [`EtwProviders::POWERSHELL_EVENT_IDS`] by
/// `powershell_filter_matches_routing_allowlist`.
fn powershell_route(event_id: u16) -> Option<(EventCategory, SensorAction)> {
    match event_id {
        POWERSHELL_EVENT_SCRIPT_BLOCK => Some((EventCategory::Scripting, SensorAction::Execute)),
        POWERSHELL_EVENT_MODULE_LOGGING => {
            Some((EventCategory::PowerShellModule, SensorAction::Execute))
        }
        _ => None,
    }
}

/// Microsoft-Windows-Kernel-File manifest event IDs.
const KERNEL_FILE_EVENT_NAME_CREATE: u16 = 10;
const KERNEL_FILE_EVENT_NAME_DELETE: u16 = 11;
const KERNEL_FILE_EVENT_CREATE: u16 = 12;
const KERNEL_FILE_EVENT_CLOSE: u16 = 14;
const KERNEL_FILE_EVENT_WRITE: u16 = 16;
const KERNEL_FILE_EVENT_SET_INFORMATION: u16 = 17;
const KERNEL_FILE_EVENT_DELETE_PATH: u16 = 26;
const KERNEL_FILE_EVENT_RENAME_PATH: u16 = 27;
const KERNEL_FILE_EVENT_SET_LINK_PATH: u16 = 28;

/// Microsoft-Windows-Kernel-Registry manifest event IDs.
///
/// The manifest declares opcodes 32-46 for event IDs 1-15, but the records the
/// session actually receives carry opcode 0, exactly as Kernel-File does. The
/// old classifier read `record.opcode()` and compared it against 36/38/39/41,
/// which is doubly wrong: opcode is always 0 at runtime, and even the manifest
/// values do not line up — 36 is `SetValueKey`, 38 `QueryValueKey`, 39
/// `EnumerateKey` and 41 `QueryMultipleValueKey`. Route on the event ID (#279).
const KERNEL_REGISTRY_EVENT_CREATE_KEY: u16 = 1;
const KERNEL_REGISTRY_EVENT_OPEN_KEY: u16 = 2;
const KERNEL_REGISTRY_EVENT_DELETE_KEY: u16 = 3;
const KERNEL_REGISTRY_EVENT_SET_VALUE_KEY: u16 = 5;
const KERNEL_REGISTRY_EVENT_DELETE_VALUE_KEY: u16 = 6;
const KERNEL_REGISTRY_EVENT_CLOSE_KEY: u16 = 13;

/// The event IDs [`kernel_registry_route`] accepts, pushed down to the provider
/// as a scope filter. Kept in sync with the router by
/// `registry_filter_matches_routing_allowlist`.
const KERNEL_REGISTRY_ROUTED_EVENT_IDS: [u16; 6] = [
    KERNEL_REGISTRY_EVENT_CREATE_KEY,
    KERNEL_REGISTRY_EVENT_OPEN_KEY,
    KERNEL_REGISTRY_EVENT_DELETE_KEY,
    KERNEL_REGISTRY_EVENT_SET_VALUE_KEY,
    KERNEL_REGISTRY_EVENT_DELETE_VALUE_KEY,
    KERNEL_REGISTRY_EVENT_CLOSE_KEY,
];

/// What a Microsoft-Windows-Kernel-Registry event is good for.
///
/// An allowlist, like [`kernel_file_route`]: an unrecognised event is dropped
/// rather than labelled a modification. The `_ => SensorAction::Modify`
/// catch-all this replaces collapsed the whole action taxonomy onto a single
/// value that maps to no Sysmon event ID, so `registry_add`, `registry_set` and
/// `registry_delete` rules were evaluated against every registry event and
/// could never match one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelRegistryRoute {
    /// Carries `BaseName`/`RelativeName`; record the key's path.
    ///
    /// `creates` distinguishes `CreateKey`, which also reports a creation when
    /// its `Disposition` says a new key was made, from `OpenKey`, which is
    /// index maintenance only.
    Name { creates: bool },
    /// Emit telemetry under this action, resolving the path from the index.
    Emit(SensorAction),
    /// A closed key: drop its `KeyObject` from the index.
    Evict,
}

fn kernel_registry_route(event_id: u16) -> Option<KernelRegistryRoute> {
    match event_id {
        KERNEL_REGISTRY_EVENT_CREATE_KEY => Some(KernelRegistryRoute::Name { creates: true }),
        KERNEL_REGISTRY_EVENT_OPEN_KEY => Some(KernelRegistryRoute::Name { creates: false }),
        // A deleted key and a deleted value are both Sysmon 12 and both
        // `registry_delete`; the value name survives in `Details`.
        KERNEL_REGISTRY_EVENT_DELETE_KEY | KERNEL_REGISTRY_EVENT_DELETE_VALUE_KEY => {
            Some(KernelRegistryRoute::Emit(SensorAction::Delete))
        }
        KERNEL_REGISTRY_EVENT_SET_VALUE_KEY => Some(KernelRegistryRoute::Emit(SensorAction::Set)),
        KERNEL_REGISTRY_EVENT_CLOSE_KEY => Some(KernelRegistryRoute::Evict),
        // 4 QueryKey, 7 QueryValueKey, 8 EnumerateKey, 9 EnumerateValueKey,
        // 10 QueryMultipleValueKey, 12 FlushKey, 14 QuerySecurityKey — reads
        // and bookkeeping, no state change. 11 SetInformationKey and
        // 15 SetSecurityKey do change state but have no Sysmon or Sigma
        // counterpart to carry them.
        _ => None,
    }
}

/// `FILE_INFORMATION_CLASS` values seen on `SetInformation` (event ID 17).
///
/// The event reports only which class was set, never the values written, so
/// these tell us *that* a timestamp or a file size changed but not to what.
const FILE_BASIC_INFORMATION: u64 = 4;
const FILE_ALLOCATION_INFORMATION: u64 = 19;
const FILE_END_OF_FILE_INFORMATION: u64 = 20;

/// What a Microsoft-Windows-Kernel-File event is good for.
///
/// Previously every unrecognised event ID fell into a `_ => Modify` catch-all,
/// which quietly turned the provider's name-cache bookkeeping into telemetry:
/// one `CreateNew` produced a create *and* a spurious change event. Routing is
/// now an allowlist, so an event nobody has looked at is dropped rather than
/// labelled a modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelFileRoute {
    /// Emit telemetry under this action.
    Emit(SensorAction),
    /// Carries a name; record it and emit nothing. These are the index the
    /// provider publishes so consumers can resolve the pathless events.
    Index,
    /// A closed handle: drop its `FileObject` from the index.
    EvictObject,
    /// A name leaving the kernel's name cache: drop its `FileKey`.
    EvictKey,
    /// Action depends on the `InfoClass`, which needs the parsed event.
    SetInformation,
}

/// The manifest provider emits file events with opcode 0, so routing must use
/// manifest event IDs rather than MOF FileIo opcodes.
///
/// `None` means "not interesting" — checked before the schema lookup, so the
/// high-volume `Read` (15), `QueryInformation` (22), and `FSCTL` (23) events
/// that the `FILEIO` keyword also enables cost only a match on an integer.
fn kernel_file_route(event_id: u16) -> Option<KernelFileRoute> {
    match event_id {
        KERNEL_FILE_EVENT_CREATE => Some(KernelFileRoute::Emit(SensorAction::Create)),
        KERNEL_FILE_EVENT_WRITE => Some(KernelFileRoute::Emit(SensorAction::Modify)),
        KERNEL_FILE_EVENT_DELETE_PATH => Some(KernelFileRoute::Emit(SensorAction::Delete)),
        KERNEL_FILE_EVENT_RENAME_PATH | KERNEL_FILE_EVENT_SET_LINK_PATH => {
            Some(KernelFileRoute::Emit(SensorAction::Rename))
        }
        KERNEL_FILE_EVENT_SET_INFORMATION => Some(KernelFileRoute::SetInformation),
        KERNEL_FILE_EVENT_NAME_CREATE => Some(KernelFileRoute::Index),
        KERNEL_FILE_EVENT_NAME_DELETE => Some(KernelFileRoute::EvictKey),
        KERNEL_FILE_EVENT_CLOSE => Some(KernelFileRoute::EvictObject),
        // Deliberately unrouted, with the reason recorded so a future reader
        // does not have to re-derive it:
        //   13 Cleanup     — precedes Close; Close is the eviction point
        //   15 Read        — not a modification
        //   18 SetDelete   — duplicate of 26 DeletePath, which carries the path
        //   19 Rename      — duplicate of 27 RenamePath, which carries the path
        //   22/23/32/34    — query and control paths, no state change
        _ => None,
    }
}

/// Resolve `SetInformation` (event ID 17) to an action via its `InfoClass`.
///
/// This is the event that makes truncation and timestamp manipulation visible
/// at all; both were previously uncollected because the keyword was not
/// enabled. Returns `None` for the many other information classes, which are
/// ordinary metadata updates.
fn set_information_action(parser: &Parser) -> Option<SensorAction> {
    match try_get_uint_as_u64(parser, "InfoClass")? {
        // Timestamps and attributes. This is the closest analogue to Sysmon
        // Event ID 2 (file creation time changed), i.e. timestomping, which is
        // what Sigma's `file_change` category actually denotes.
        FILE_BASIC_INFORMATION => Some(SensorAction::Set),
        // Setting the allocation size or end-of-file position: truncation.
        // Truncate-to-zero of an existing file is a common wiper and
        // ransomware pattern and produced no event at all before this.
        FILE_ALLOCATION_INFORMATION | FILE_END_OF_FILE_INFORMATION => Some(SensorAction::Modify),
        _ => None,
    }
}

/// IRP_MJ_CREATE disposition values (top byte of CreateOptions).
///
/// The disposition controls whether the I/O manager creates a new file,
/// opens an existing one, or some combination of both.
const FILE_DISPOSITION_SUPERSEDE: u32 = 0;
const FILE_DISPOSITION_OPEN: u32 = 1;
const FILE_DISPOSITION_CREATE: u32 = 2;
const FILE_DISPOSITION_OPEN_IF: u32 = 3;
const FILE_DISPOSITION_OVERWRITE: u32 = 4;
const FILE_DISPOSITION_OVERWRITE_IF: u32 = 5;

/// Refine a [`SensorAction::Create`] for Kernel-File Event ID 12 based on
/// the `CreateOptions` disposition.
///
/// Event ID 12 corresponds to `IRP_MJ_CREATE`, which fires for **every** file
/// handle request — including plain opens and attribute queries.  Without
/// inspecting the disposition we would misclassify reads as file creations.
///
/// Returns:
/// * `Some(action)` — the (possibly adjusted) action for this event.
/// * `None` — the event should be dropped (pure open / read).
fn refine_file_create_action(parser: &Parser, action: SensorAction) -> Option<SensorAction> {
    if action != SensorAction::Create {
        return Some(action);
    }

    let create_options = parser.try_parse::<u32>("CreateOptions").ok()?;
    let disposition = (create_options >> 24) & 0xFF;

    match disposition {
        // Pure open of an existing file — never creates.  Drop the event
        // to match Sysmon behaviour (Sysmon does not emit FileCreate for
        // plain opens).
        FILE_DISPOSITION_OPEN => None,

        // Overwrite of an existing file — the file already exists so this
        // is a modification, not a creation.
        FILE_DISPOSITION_OVERWRITE => Some(SensorAction::Modify),

        // SUPERSEDE, CREATE, OPEN_IF, OVERWRITE_IF can all result in a
        // new file being created.
        FILE_DISPOSITION_SUPERSEDE
        | FILE_DISPOSITION_CREATE
        | FILE_DISPOSITION_OPEN_IF
        | FILE_DISPOSITION_OVERWRITE_IF => Some(SensorAction::Create),

        // Unknown disposition — keep as Create to be safe.
        _ => Some(SensorAction::Create),
    }
}

/// `REG_DISPOSITION` values reported by Kernel-Registry event ID 1.
const REG_CREATED_NEW_KEY: u32 = 1;
const REG_OPENED_EXISTING_KEY: u32 = 2;

/// Whether a Kernel-Registry `CreateKey` (event ID 1) actually created a key.
///
/// `CreateKey` is `NtCreateKey`, which opens an existing key just as readily as
/// it makes a new one — the same trap as `IRP_MJ_CREATE` on the file side (see
/// [`refine_file_create_action`]). Without this check every key open on the
/// machine would surface as a `registry_add`, trading a category that never
/// fires for one that fires constantly.
///
/// Returns `None` when the event should be dropped.
fn refine_registry_create_action(parser: &Parser) -> Option<()> {
    match parser.try_parse::<u32>("Disposition") {
        Ok(REG_CREATED_NEW_KEY) => Some(()),
        Ok(REG_OPENED_EXISTING_KEY) => None,
        // An unreadable or unknown disposition keeps the event: a missed
        // detection is worse than an extra one.
        Ok(_) | Err(_) => Some(()),
    }
}

/// Shared state the ETW callback carries across events.
///
/// The path index has to outlive a single event: the naming event and the
/// write it explains are different records, often seconds apart.
struct EtwState {
    routing: EtwRouting,
    file_paths: Mutex<FilePathCache>,
    registry_paths: Mutex<RegistryPathCache>,
    /// File events dropped because neither identifier resolved to a path.
    ///
    /// Handles opened before the sensor started were never indexed, so writes
    /// through them cannot be attributed until the handle is reopened. Dropping
    /// them is the right policy — a pathless event matches no rule — but without
    /// a count there is no way to tell a quiet endpoint from a blind one.
    unresolved_file_events: AtomicU64,
    /// Registry events dropped because the `KeyObject` resolved to no path.
    ///
    /// Same blind spot as `unresolved_file_events`: a key opened before the
    /// sensor started was never named, so writes through it cannot be
    /// attributed until it is reopened.
    unresolved_registry_events: AtomicU64,
}

impl EtwState {
    fn new() -> Self {
        Self {
            routing: EtwRouting::new(),
            file_paths: Mutex::new(FilePathCache::new()),
            registry_paths: Mutex::new(RegistryPathCache::new()),
            unresolved_file_events: AtomicU64::new(0),
            unresolved_registry_events: AtomicU64::new(0),
        }
    }

    /// The path index is derived state, so a poisoned lock is recoverable and
    /// recovering is the only safe option: this runs inside an ETW callback
    /// invoked by the OS, and unwinding across that boundary would take the
    /// sensor down. Losing path resolution for the life of the process because
    /// one callback panicked is a worse failure than a stale cache entry.
    fn paths(&self) -> MutexGuard<'_, FilePathCache> {
        self.file_paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Recovered for the same reason as [`Self::paths`]: unwinding out of an
    /// OS-invoked ETW callback would take the sensor down.
    fn registry_paths(&self) -> MutexGuard<'_, RegistryPathCache> {
        self.registry_paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct EtwRouting {
    kernel_process_guid: GUID,
    kernel_file_guid: GUID,
    kernel_registry_guid: GUID,
    powershell_guid: GUID,
    guid_to_category: HashMap<GUID, EventCategory>,
}

impl EtwRouting {
    fn new() -> Self {
        let mut guid_to_category = HashMap::new();
        guid_to_category.insert(EtwProviders::kernel_network().guid, EventCategory::Network);
        guid_to_category.insert(EtwProviders::kernel_file().guid, EventCategory::File);
        guid_to_category.insert(
            EtwProviders::kernel_registry().guid,
            EventCategory::Registry,
        );
        guid_to_category.insert(EtwProviders::dns_client().guid, EventCategory::Dns);
        guid_to_category.insert(EtwProviders::wmi_activity().guid, EventCategory::Wmi);
        guid_to_category.insert(EtwProviders::task_scheduler().guid, EventCategory::Task);

        Self {
            kernel_process_guid: EtwProviders::kernel_process().guid,
            kernel_file_guid: EtwProviders::kernel_file().guid,
            kernel_registry_guid: EtwProviders::kernel_registry().guid,
            powershell_guid: EtwProviders::powershell().guid,
            guid_to_category,
        }
    }

    fn route(&self, record: &EventRecord) -> Option<(EventCategory, SensorAction)> {
        let provider_guid = record.provider_id();

        if provider_guid == self.kernel_process_guid {
            return match record.opcode() {
                1 => Some((EventCategory::Process, SensorAction::Start)),
                2 => Some((EventCategory::Process, SensorAction::Stop)),
                10 => Some((EventCategory::ImageLoad, SensorAction::Load)),
                _ => None,
            };
        }

        if provider_guid == self.powershell_guid {
            return powershell_route(record.event_id());
        }

        let category = *self.guid_to_category.get(&provider_guid)?;
        let action = match category {
            EventCategory::Network => {
                classify_kernel_network_event(record.event_id())?.connection_action()?
            }
            // Kernel-File needs the path index and so has its own pipeline;
            // `decode_record` diverts it before reaching here.
            EventCategory::File => return None,
            // Kernel-Registry needs the key-path index and so has its own
            // pipeline; `decode_record` diverts it before reaching here.
            EventCategory::Registry => return None,
            EventCategory::Dns => SensorAction::Query,
            EventCategory::Wmi => SensorAction::Execute,
            EventCategory::Task => SensorAction::Register,
            EventCategory::Service | EventCategory::Security => {
                unreachable!("event log categories use the event log sources")
            }
            EventCategory::Process
            | EventCategory::ImageLoad
            | EventCategory::Scripting
            | EventCategory::PowerShellModule => unreachable!(),
        };

        Some((category, action))
    }
}

#[derive(Debug)]
struct DecodedEtwEvent {
    pid: Option<u32>,
    process_start_key: Option<ProcessStartKey>,
    payload: SensorPayload,
}

/// Windows ETW sensor implementation.
pub struct EtwSensor {
    shutdown: Arc<AtomicBool>,
    flush_interval_ms: u64,
    process_flush_interval_ms: u64,
}

impl EtwSensor {
    pub fn new() -> Self {
        Self::with_flush_intervals(
            super::flush::DEFAULT_INTERVAL_MS,
            super::flush::DEFAULT_PROCESS_INTERVAL_MS,
        )
    }

    /// The two sessions are configured separately on purpose; see
    /// [`super::flush::process_interval`].
    pub fn with_flush_intervals(flush_interval_ms: u64, process_flush_interval_ms: u64) -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            flush_interval_ms,
            process_flush_interval_ms,
        }
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

/// Ask the registry provider to include value data, once the session exists.
///
/// This cannot be part of building the provider: `ferrisetw` has no way to
/// express the filter payload it needs, so the provider is re-enabled by hand
/// on the running session. A failure is logged and tolerated — `Details` then
/// falls back to the value name, exactly as before #292 — because the
/// mechanism is undocumented and may not hold on every Windows build.
fn request_registry_value_data() {
    let provider = EtwProviders::kernel_registry();
    match registry_value_data::request_value_data(
        TRACE_SESSION_NAME,
        to_windows_guid(provider.guid),
        provider.level,
        provider.keywords,
        provider.event_ids,
    ) {
        Ok(()) => info!("Registry value data capture enabled"),
        Err(err) => warn!(
            "Could not enable registry value data capture ({err:#}); \
             registry Details will carry the value name"
        ),
    }
}

/// `ferrisetw` is built against a different `windows` version than this crate,
/// so the two `GUID` types are distinct despite being the same four fields.
fn to_windows_guid(guid: GUID) -> windows::core::GUID {
    windows::core::GUID {
        data1: guid.data1,
        data2: guid.data2,
        data3: guid.data3,
        data4: guid.data4,
    }
}

impl Default for EtwSensor {
    fn default() -> Self {
        Self::new()
    }
}

/// Attach `providers` to a named session and return the builder.
///
/// Every provider gets the same callback: routing is by provider GUID inside
/// [`decode_record`], not by which session delivered the record, so the split
/// is invisible below this point.
fn build_session(
    session_name: &str,
    properties: TraceProperties,
    providers: Vec<EtwProvider>,
    state: &Arc<EtwState>,
    tx: &Sender<SensorEvent>,
) -> TraceBuilder<UserTrace> {
    info!(
        "ETW session '{}' buffers: {} KB x {}-{} ({} MB ceiling), flush {}s",
        session_name,
        properties.buffer_size,
        properties.min_buffer,
        properties.max_buffer,
        (properties.buffer_size as u64 * properties.max_buffer as u64) / 1024,
        properties.flush_timer.as_secs(),
    );

    let mut trace_builder = UserTrace::new()
        .named(session_name.to_string())
        .set_trace_properties(properties);

    for provider_def in providers {
        info!(
            "Enabling ETW provider: {} ({:?}) with level {} and keywords: 0x{:X} on session '{}'",
            provider_def.name,
            provider_def.guid,
            provider_def.level,
            provider_def.keywords,
            session_name
        );

        let state = Arc::clone(state);
        let tx = tx.clone();
        let mut provider_builder = Provider::by_guid(provider_def.guid)
            .level(provider_def.level)
            .any(provider_def.keywords)
            .add_callback(move |record, schema_locator| {
                let Some(event) = decode_record(record, schema_locator, &state) else {
                    return;
                };

                // Blocking inside an ETW callback stalls the trace
                // session and loses events in the kernel buffer instead,
                // so overflow is shed. The telemetry counters record both
                // outcomes and emit the rate-limited cumulative warning.
                if let Err(TrySendError::Closed(_)) = crate::telemetry::try_send(
                    crate::telemetry::ChannelId::SensorEvents,
                    &tx,
                    event,
                ) {
                    trace!("Sensor event channel closed; dropping ETW event");
                }
            });

        if !provider_def.event_ids.is_empty() {
            provider_builder = provider_builder
                .add_filter(EventFilter::ByEventIds(provider_def.event_ids.to_vec()));
        }

        trace_builder = trace_builder.enable(provider_builder.build());
    }

    trace_builder
}

/// Interpret the return of a blocking `process()` call.
///
/// Stopping a trace from `shutdown()` makes `process()` return an error by
/// design; only a failure while the sensor is supposed to keep running is a
/// real one, and it must reach the caller - logging alone buries the ETW error
/// code in the operational log (#256).
fn interpret_process_result(
    session_name: &str,
    result: std::result::Result<(), ferrisetw::trace::TraceError>,
    shutting_down: bool,
) -> Result<()> {
    match result {
        Ok(()) => {
            info!("ETW trace session '{session_name}' stopped");
            Ok(())
        }
        Err(err) if shutting_down => {
            info!("ETW trace session '{session_name}' stopped with result: {err:?}");
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!(
            "ETW trace processing failed for session '{session_name}': {err:?}"
        )),
    }
}

impl EtwSensor {
    /// Start both sessions and block on the main one until shutdown.
    ///
    /// The two sessions are started before either is processed, so a failure to
    /// create the second one is reported as a startup error rather than as a
    /// sensor that silently runs without process events.
    fn run_sessions(&self, tx: &Sender<SensorEvent>) -> Result<()> {
        let state = Arc::new(EtwState::new());

        let main_builder = build_session(
            TRACE_SESSION_NAME,
            session_properties(),
            EtwProviders::main_session(),
            &state,
            tx,
        );
        let process_builder = build_session(
            PROCESS_TRACE_SESSION_NAME,
            process_session_properties(),
            EtwProviders::process_session(),
            &state,
            tx,
        );

        let (mut main_trace, _main_handle) = main_builder
            .start()
            .map_err(|err| anyhow::anyhow!("Failed to start ETW trace: {err:?}"))?;
        info!("ETW trace session '{TRACE_SESSION_NAME}' started successfully");

        request_registry_value_data();

        // Dropping `main_trace` on this path stops the session it created, so
        // a half-started pair cannot be left behind for the next run to trip
        // over.
        let (process_trace, process_handle) = process_builder
            .start()
            .map_err(|err| anyhow::anyhow!("Failed to start ETW process trace: {err:?}"))?;
        info!("ETW trace session '{PROCESS_TRACE_SESSION_NAME}' started successfully");

        // Check the worker before blocking on the main session. Otherwise a
        // thread-creation failure would leave the sensor running forever with
        // no consumer for process events.
        let process_worker = self.spawn_process_trace_worker(process_handle)?;

        // The process flusher is required whenever its interval is enabled:
        // without it, short-lived command-line capture falls back to 16.6%.
        let process_flusher = match super::flush::spawn(
            PROCESS_TRACE_SESSION_NAME,
            super::flush::process_interval(self.process_flush_interval_ms),
            Arc::clone(&self.shutdown),
            tx.clone(),
        ) {
            Ok(flusher) => flusher,
            Err(err) => {
                self.shutdown.store(true, Ordering::Relaxed);
                drop(process_trace);
                let _ = process_worker.join();
                return Err(err);
            }
        };

        // Failure of the main session's optional latency optimization keeps
        // the existing behavior: ETW's native timer still delivers events.
        let main_flusher = super::flush::spawn(
            TRACE_SESSION_NAME,
            super::flush::main_interval(self.flush_interval_ms),
            Arc::clone(&self.shutdown),
            tx.clone(),
        )
        .unwrap_or_else(|err| {
            warn!("Forced ETW flush disabled for main session: {err:#}");
            None
        });
        let flushers = [main_flusher, process_flusher];

        let main_result = interpret_process_result(
            TRACE_SESSION_NAME,
            main_trace.process(),
            self.shutdown.load(Ordering::Relaxed),
        );

        // Whatever ended the main session ends the sensor. The process session
        // is stopped by name so its blocking `process_from_handle` returns and
        // the worker can be joined; `process_trace` would do the same on drop,
        // but only after the join has already deadlocked.
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = stop_trace_by_name(PROCESS_TRACE_SESSION_NAME);

        let process_result = process_worker
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("ETW process trace thread panicked")));

        for flusher in flushers.into_iter().flatten() {
            let _ = flusher.join();
        }

        drop(process_trace);
        main_result.and(process_result)
    }

    /// Run the Kernel-Process session on its own thread.
    ///
    /// A second `process()` cannot share the main thread - the call blocks
    /// until its session stops. The handle is processed rather than the trace
    /// itself so the `UserTrace` stays with the caller, which is what stops the
    /// session when this function's caller returns.
    fn spawn_process_trace_worker(
        &self,
        handle: ferrisetw::native::TraceHandle,
    ) -> Result<std::thread::JoinHandle<Result<()>>> {
        let shutdown = Arc::clone(&self.shutdown);
        std::thread::Builder::new()
            .name("etw-process-trace".into())
            .spawn(move || {
                let result = interpret_process_result(
                    PROCESS_TRACE_SESSION_NAME,
                    UserTrace::process_from_handle(handle),
                    shutdown.load(Ordering::Relaxed),
                );

                // The main session's `process()` is blocking, so a failure here
                // would otherwise sit unnoticed until the agent is stopped by
                // hand, with every process event missing in the meantime. Stop
                // the main session to make the failure reach the caller - the
                // same contract `run_subscription` uses for the event logs.
                if result.is_err() && !shutdown.swap(true, Ordering::Relaxed) {
                    let _ = stop_trace_by_name(TRACE_SESSION_NAME);
                }

                result
            })
            .map_err(|err| anyhow::anyhow!("Failed to spawn ETW process trace thread: {err}"))
    }
}

impl Sensor for EtwSensor {
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        info!("Starting ETW sensor...");

        self.shutdown.store(false, Ordering::Relaxed);
        let event_logs = EventLogSubscriptions::start(tx.clone(), Arc::clone(&self.shutdown))?;

        // A session left running by a previous process keeps its old buffer
        // sizing and its old providers, and `start` would then bind to it.
        let _ = stop_trace_by_name(TRACE_SESSION_NAME);
        let _ = stop_trace_by_name(PROCESS_TRACE_SESSION_NAME);

        let trace_result = self.run_sessions(&tx);

        self.shutdown.store(true, Ordering::Relaxed);
        event_logs.join().and(trace_result)
    }

    fn shutdown(&self) {
        info!("Initiating graceful shutdown of ETW sensor...");
        self.shutdown.store(true, Ordering::Relaxed);

        for session in [TRACE_SESSION_NAME, PROCESS_TRACE_SESSION_NAME] {
            info!("Stopping ETW trace session '{session}'...");
            if let Err(err) = stop_trace_by_name(session) {
                warn!("Failed to stop trace session '{session}': {err:?}");
            }
        }
    }
}

fn decode_record(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    state: &EtwState,
) -> Option<SensorEvent> {
    if record.provider_id() == state.routing.kernel_file_guid {
        return decode_kernel_file_record(record, schema_locator, state);
    }
    if record.provider_id() == state.routing.kernel_registry_guid {
        return decode_kernel_registry_record(record, schema_locator, state);
    }

    let (category, action) = state.routing.route(record)?;
    let schema = match schema_locator.event_schema(record) {
        Ok(schema) => schema,
        Err(err) => {
            trace!(
                "Failed to get ETW schema for provider {:?} event {}: {:?}",
                record.provider_id(),
                record.event_id(),
                err
            );
            return None;
        }
    };
    let parser = Parser::create(record, &schema);

    let decoded = match category {
        EventCategory::Process => decode_process(&parser, record, action),
        EventCategory::Network => decode_network(&parser, record),
        EventCategory::File => unreachable!("kernel-file records are diverted above"),
        EventCategory::Registry => unreachable!("kernel-registry records are diverted above"),
        EventCategory::Dns => decode_dns(&parser, record),
        EventCategory::ImageLoad => decode_image_load(&parser, record),
        EventCategory::Scripting => decode_powershell(&parser, record),
        EventCategory::PowerShellModule => decode_powershell_module(&parser, record),
        EventCategory::Wmi => decode_wmi(&parser, record),
        EventCategory::Service | EventCategory::Security => {
            unreachable!("event log categories use the event log sources")
        }
        EventCategory::Task => decode_task(&parser, record),
    }?;

    // A payload without fields cannot satisfy a Sigma selection. Provider
    // allowlists should prevent these records, but keep this loss-free guard at
    // the decode boundary so manifest drift cannot reintroduce fieldless noise.
    if !has_matchable_fields(&decoded.payload) {
        return None;
    }

    let normalization = mapper::normalization_for_record(category, action, record);

    Some(SensorEvent {
        platform: Platform::Windows,
        provider: "etw",
        action,
        normalization,
        pid: decoded.pid,
        timestamp: filetime_to_system_time(record.raw_timestamp()),
        process_start_key: decoded.process_start_key,
        payload: decoded.payload,
    })
}

fn has_matchable_fields(payload: &SensorPayload) -> bool {
    match payload {
        SensorPayload::Dns(fields) => {
            fields.query_name.is_some()
                || fields.query_results.is_some()
                || fields.record_type.is_some()
                || fields.query_status.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
        }
        SensorPayload::Scripting(fields) => {
            fields.script_block_text.is_some()
                || fields.script_block_id.is_some()
                || fields.path.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
                || fields.user.is_some()
        }
        SensorPayload::PowerShellModule(fields) => {
            fields.context_info.is_some()
                || fields.payload.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
                || fields.user.is_some()
        }
        SensorPayload::Wmi(fields) => {
            fields.operation.is_some()
                || fields.user.is_some()
                || fields.query.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
                || fields.event_namespace.is_some()
                || fields.event_type.is_some()
                || fields.destination_hostname.is_some()
        }
        SensorPayload::Service(fields) => {
            fields.service_name.is_some()
                || fields.service_file_name.is_some()
                || fields.service_type.is_some()
                || fields.start_type.is_some()
                || fields.account_name.is_some()
                || fields.user.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
        }
        SensorPayload::Task(fields) => {
            fields.task_name.is_some()
                || fields.task_content.is_some()
                || fields.user_name.is_some()
                || fields.user.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
        }
        _ => true,
    }
}

fn decode_process(
    parser: &Parser,
    record: &EventRecord,
    action: SensorAction,
) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::process_creation_mappings();

    // The PID and the command line come first, and nothing is allowed between
    // them and the back-fill below. Everything else this function does is
    // reading a property out of a buffer that is already in memory; the
    // back-fill is the one step racing a live process, and `parse_metadata`
    // in particular opens and maps the image off disk. Decoding in field order
    // put that read, and every path conversion, ahead of the race for no
    // reason. See `PROCESS_TRACE_SESSION_NAME`.
    let process_id = try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
        .or_else(|| Some(record.process_id().to_string()));
    let pid = process_id
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_else(|| record.process_id());

    // No Kernel-Process event version carries `CommandLine`, so this is a read
    // of the live process's PEB and only succeeds while it still exists.
    let mut command_line = try_get_string(parser, mappings.get_etw_field("CommandLine")?);
    if action == SensorAction::Start && command_line.is_none() {
        command_line = query_process_command_line(pid);
    }

    let creation_time_opt = try_get_uint_as_u64(parser, "CreateTime")
        .or_else(|| try_get_uint_as_u64(parser, "ProcessStartTime"));
    let creation_time_with_fallback =
        creation_time_opt.or_else(|| try_get_uint_as_u64(parser, "TimeStamp"));

    let raw_image = try_get_string_any(
        parser,
        &[
            mappings.get_etw_field("Image")?,
            "ImageFileName",
            "ProcessName",
        ],
    );
    let raw_parent_image = try_get_string_any(
        parser,
        &[mappings.get_etw_field("ParentImage")?, "ParentProcessName"],
    );
    let raw_current_directory = try_get_string(parser, mappings.get_etw_field("CurrentDirectory")?);

    let image = raw_image.map(|path| convert_nt_to_dos(&path));
    let parent_image = raw_parent_image.map(|path| convert_nt_to_dos(&path));
    let current_directory = raw_current_directory.map(|path| convert_nt_to_dos(&path));

    // Version resources are only worth reading on a start: on a stop the image
    // is often already gone, and the fields describe the binary, not the exit.
    let pe_metadata = match image.as_deref() {
        Some(path) if action == SensorAction::Start => parse_metadata(path),
        _ => None,
    };
    let (original_file_name, product, description, company, file_version) =
        pe::version_fields(pe_metadata);

    let fields = ProcessCreationFields {
        image: image.clone(),
        original_file_name,
        product,
        description,
        company,
        file_version,
        // Process creation describes one image and has no target process.
        target_image: None,
        command_line,
        process_id,
        process_start_time: creation_time_with_fallback,
        parent_process_id: try_get_uint(parser, mappings.get_etw_field("ParentProcessId")?),
        parent_image,
        parent_command_line: try_get_string(parser, mappings.get_etw_field("ParentCommandLine")?),
        current_directory,
        // `MandatoryLabel` is a SID; Sigma matches on Sysmon's level name.
        // It is only on the start template, so a stop event has none.
        integrity_level: try_get_string(parser, mappings.get_etw_field("IntegrityLevel")?)
            .and_then(|sid| integrity_level_from_sid(&sid)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    let process_start_key = match action {
        SensorAction::Start => {
            creation_time_opt.map(|start_time| ProcessStartKey { pid, start_time })
        }
        SensorAction::Stop => {
            creation_time_opt.map(|start_time| ProcessStartKey { pid, start_time })
        }
        _ => None,
    };

    Some(DecodedEtwEvent {
        pid: Some(pid),
        process_start_key,
        payload: SensorPayload::Process(fields),
    })
}

/// Decode a Microsoft-Windows-Kernel-File record, resolving its path.
///
/// Kernel-File is handled apart from the other providers because it is the
/// only one whose events cannot be understood in isolation: the write events
/// name their target by kernel pointer and rely on an index the consumer
/// builds from earlier naming events.
fn decode_kernel_file_record(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    state: &EtwState,
) -> Option<SensorEvent> {
    // Checked before the schema lookup: the FILEIO keyword needed for Close
    // and SetInformation also delivers every read and query on the machine,
    // and decoding those would be pure overhead.
    let route = kernel_file_route(record.event_id())?;

    let schema = match schema_locator.event_schema(record) {
        Ok(schema) => schema,
        Err(err) => {
            trace!(
                "Failed to get Kernel-File schema for event {}: {:?}",
                record.event_id(),
                err
            );
            return None;
        }
    };
    let parser = Parser::create(record, &schema);

    let file_object = try_get_uint_as_u64(&parser, "FileObject");
    let file_key = try_get_uint_as_u64(&parser, "FileKey");
    // DeletePath, RenamePath, and SetLinkPath carry `FilePath`; Create and the
    // name-cache events carry `FileName`.
    let named_path = try_get_string_any(&parser, &["FilePath", "FileName"]);

    // Any event carrying a name feeds the index, including the ones that also
    // produce telemetry — a Create both reports a creation and teaches us the
    // path for the writes that follow on that handle.
    if let Some(path) = named_path.as_deref() {
        state.paths().learn(file_object, file_key, path);
    }

    let action = match route {
        KernelFileRoute::Index => return None,
        KernelFileRoute::EvictObject => {
            if let Some(object) = file_object {
                state.paths().forget_object(object);
            }
            return None;
        }
        KernelFileRoute::EvictKey => {
            if let Some(key) = file_key {
                state.paths().forget_key(key);
            }
            return None;
        }
        // Event ID 12 fires for every handle request, including plain opens;
        // the disposition says whether anything was actually created.
        KernelFileRoute::Emit(SensorAction::Create) => {
            refine_file_create_action(&parser, SensorAction::Create)?
        }
        KernelFileRoute::Emit(action) => action,
        KernelFileRoute::SetInformation => set_information_action(&parser)?,
    };

    // A file event with no path cannot match a rule — essentially every file
    // rule keys on TargetFilename — so an unresolvable event is dropped rather
    // than sent on to occupy space in a bounded channel.
    let raw_path = match named_path {
        Some(path) => path,
        None => match state.paths().resolve(file_object, file_key) {
            Some(path) => path.to_string(),
            None => {
                // Counted rather than silently discarded: this is the sensor's
                // blind spot, and its size is the only way to know whether an
                // endpoint is quiet or unobserved.
                let unresolved = state.unresolved_file_events.fetch_add(1, Ordering::Relaxed) + 1;
                if unresolved == 1 || unresolved.is_multiple_of(1000) {
                    debug!(
                        unresolved_file_events = unresolved,
                        "Dropping file event whose path could not be resolved"
                    );
                }
                return None;
            }
        },
    };

    let mappings = field_maps::file_event_mappings();
    let fields = FileEventFields {
        source_filename: None,
        target_filename: Some(convert_nt_to_dos(&raw_path)),
        process_id: try_get_uint(&parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(&parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        // Kernel-File reports which information class was set, never the
        // values, so unlike Sysmon Event ID 2 these stay empty on Windows.
        creation_utc_time: try_get_string(&parser, mappings.get_etw_field("CreationUtcTime")?),
        previous_creation_utc_time: try_get_string(
            &parser,
            mappings.get_etw_field("PreviousCreationUtcTime")?,
        ),
        user: try_get_string(&parser, mappings.get_etw_field("User")?),
        // ETW delivers whole paths or none at all; there is no capture buffer
        // to overflow on Windows.
        path_truncated: None,
    };

    let pid = parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id()));
    let normalization = mapper::normalization_for_record(EventCategory::File, action, record);

    Some(SensorEvent {
        platform: Platform::Windows,
        provider: "etw",
        action,
        normalization,
        pid,
        timestamp: filetime_to_system_time(record.raw_timestamp()),
        process_start_key: None,
        payload: SensorPayload::File(fields),
    })
}

/// Decode a Microsoft-Windows-Kernel-Registry record, maintaining the key-path
/// index the pathless write events depend on.
///
/// Mirrors [`decode_kernel_file_record`]. `SetValueKey`, `DeleteValueKey` and
/// `DeleteKey` deliver an empty `KeyName` and identify their target only by
/// `KeyObject`, so the naming events (`CreateKey`, `OpenKey`) have to be joined
/// to them. Before #279 none of this existed: the action came from an opcode
/// that is always 0, and every registry event reached the detectors as an
/// unclassified `registry_event` with `event.code = 0`.
fn decode_kernel_registry_record(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    state: &EtwState,
) -> Option<SensorEvent> {
    // Checked before the schema lookup so unrouted events cost only an
    // integer match.
    let route = kernel_registry_route(record.event_id())?;

    let schema = match schema_locator.event_schema(record) {
        Ok(schema) => schema,
        Err(err) => {
            trace!(
                "Failed to get Kernel-Registry schema for event {}: {:?}",
                record.event_id(),
                err
            );
            return None;
        }
    };
    let parser = Parser::create(record, &schema);

    let key_object = try_get_uint_as_u64(&parser, "KeyObject");

    let (action, target_object, value_name) = match route {
        KernelRegistryRoute::Name { creates } => {
            let base_object = try_get_uint_as_u64(&parser, "BaseObject");
            let base_name = try_get_string(&parser, "BaseName").unwrap_or_default();
            let relative_name = try_get_string(&parser, "RelativeName").unwrap_or_default();

            // Indexing happens for both CreateKey and OpenKey, including the
            // creates that also emit: a key that is created is then written
            // through, and those writes carry only its `KeyObject`.
            let path =
                state
                    .registry_paths()
                    .learn(base_object, key_object, &base_name, &relative_name);

            if !creates {
                return None;
            }
            // `NtCreateKey` opens existing keys just as readily as it makes new
            // ones — the same trap as `IRP_MJ_CREATE` on the file side. Without
            // the disposition check every key open would surface as a
            // `registry_add`.
            refine_registry_create_action(&parser)?;
            (SensorAction::Create, path?, None)
        }
        KernelRegistryRoute::Evict => {
            if let Some(object) = key_object {
                state.registry_paths().forget(object);
            }
            return None;
        }
        KernelRegistryRoute::Emit(action) => {
            let value_name = try_get_string(&parser, "ValueName");
            // `KeyName` is declared on these events but measured empty on
            // Windows 11, so the index is the real source of the path.
            let path = try_get_string(&parser, "KeyName")
                .filter(|name| !name.is_empty())
                .or_else(|| {
                    state
                        .registry_paths()
                        .resolve(key_object)
                        .map(str::to_string)
                });

            // Sysmon reports a value write as `<key>\<value>` on Event ID 13,
            // and `registry_set` rules are written against that shape — an
            // `endswith: '\Run\Foo'` rule needs the value name in the path,
            // not only in `Details`.
            let path = path.map(|path| match value_name.as_deref() {
                Some(value) if !value.is_empty() => format!("{path}\\{value}"),
                _ => path,
            });

            match path {
                Some(path) => (action, path, value_name),
                None => {
                    // Counted rather than silently discarded, for the same
                    // reason as the file index: this is the sensor's blind
                    // spot and its size is the only measure of it.
                    let unresolved = state
                        .unresolved_registry_events
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    if unresolved == 1 || unresolved.is_multiple_of(10_000) {
                        debug!(
                            unresolved_registry_events = unresolved,
                            "Dropping registry event whose key path could not be resolved"
                        );
                    }
                    return None;
                }
            }
        }
    };

    let mappings = field_maps::registry_event_mappings();
    let fields = RegistryEventFields {
        target_object: Some(target_object),
        details: registry_details(&parser, value_name.as_deref()),
        process_id: try_get_uint(&parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(&parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        event_type: try_get_string(&parser, "EventType"),
        user: try_get_string(&parser, mappings.get_etw_field("User")?),
        new_name: try_get_string(&parser, "NewName"),
    };

    let pid = parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id()));
    let normalization = mapper::normalization_for_record(EventCategory::Registry, action, record);

    Some(SensorEvent {
        platform: Platform::Windows,
        provider: "etw",
        action,
        normalization,
        pid,
        timestamp: filetime_to_system_time(record.raw_timestamp()),
        process_start_key: None,
        payload: SensorPayload::Registry(fields),
    })
}

/// `Details` for a registry event: the value *data*, as Sysmon Event ID 13
/// defines it, falling back to the value name.
///
/// The fallback is not dead code. `CapturedData` is only populated because
/// [`registry_value_data::request_value_data`] asked for it through an
/// undocumented filter payload, and that request can fail — on a Windows build
/// that does not honour it, or if the re-enable itself failed and was logged as
/// a warning. Emitting nothing there would be a regression on the pre-#292
/// behaviour, so the name is still better than an absent field.
fn registry_details(parser: &Parser, value_name: Option<&str>) -> Option<String> {
    let captured = parser
        .try_parse::<Vec<u8>>(field_maps::registry_event_mappings().get_etw_field("Details")?)
        .unwrap_or_default();
    let value_type =
        try_get_uint_as_u64(parser, registry_value_data::VALUE_TYPE_PROPERTY).unwrap_or(0);

    registry_value_data::format_value_data(value_type as u32, &captured)
        .or_else(|| value_name.map(str::to_string))
}

fn decode_network(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::network_connection_mappings();
    let route = classify_kernel_network_event(record.event_id())?;

    let fields = NetworkConnectionFields {
        destination_ip: try_get_ip(parser, "daddr", route.address_family)
            .or_else(|| try_get_ip(parser, "DestinationAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "RemoteAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "dstaddr", route.address_family)),
        source_ip: try_get_ip(parser, "saddr", route.address_family)
            .or_else(|| try_get_ip(parser, "SourceAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "LocalAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "srcaddr", route.address_family)),
        destination_port: try_get_port(parser, "dport")
            .or_else(|| try_get_port(parser, "DestinationPort"))
            .or_else(|| try_get_port(parser, "RemotePort"))
            .or_else(|| try_get_port(parser, "dstport")),
        source_port: try_get_port(parser, "sport")
            .or_else(|| try_get_port(parser, "SourcePort"))
            .or_else(|| try_get_port(parser, "LocalPort"))
            .or_else(|| try_get_port(parser, "srcport")),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
            .or_else(|| Some(record.process_id().to_string())),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        destination_hostname: try_get_string(
            parser,
            mappings.get_etw_field("DestinationHostname")?,
        ),
        protocol: Some(route.protocol.as_str().to_string()),
        // Direction comes from the operation the event ID encodes, not from a
        // payload property: Kernel-Network has no equivalent of Sysmon's
        // `Initiated`. Only Connect and Accept reach here, so this is `Some`
        // in practice, but the classifier stays the single source of truth.
        initiated: route.initiated(),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Network(fields),
    })
}

fn decode_dns(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::dns_query_mappings();
    let fields = DnsQueryFields {
        query_name: try_get_string(parser, mappings.get_etw_field("QueryName")?),
        query_results: try_get_string(parser, mappings.get_etw_field("QueryResults")?),
        record_type: None,
        query_status: try_get_uint(parser, mappings.get_etw_field("QueryStatus")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Dns(fields),
    })
}

fn decode_image_load(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::image_load_mappings();
    let image_loaded = try_get_string(parser, mappings.get_etw_field("ImageLoaded")?)
        .map(|path| convert_nt_to_dos(&path));

    let pe_metadata = image_loaded.as_deref().and_then(parse_metadata);
    let (original_file_name, product, description, company, file_version) =
        pe::version_fields(pe_metadata);

    let fields = ImageLoadFields {
        image_loaded,
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        original_file_name,
        product,
        description,
        company,
        file_version,
        signed: try_get_string(parser, mappings.get_etw_field("Signed")?),
        signature: try_get_string(parser, mappings.get_etw_field("Signature")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::ImageLoad(fields),
    })
}

fn decode_powershell(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::powershell_script_mappings();
    let fields = PowerShellScriptFields {
        script_block_text: try_get_string(parser, mappings.get_etw_field("ScriptBlockText")?),
        script_block_id: try_get_string(parser, mappings.get_etw_field("ScriptBlockId")?),
        path: try_get_string(parser, mappings.get_etw_field("Path")?)
            .map(|path| convert_nt_to_dos(&path)),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Scripting(fields),
    })
}

fn decode_powershell_module(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::powershell_module_mappings();
    let fields = PowerShellModuleFields {
        context_info: try_get_string(parser, mappings.get_etw_field("ContextInfo")?),
        payload: try_get_string(parser, mappings.get_etw_field("Payload")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::PowerShellModule(fields),
    })
}

fn decode_wmi(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::wmi_event_mappings();
    let fields = WmiEventFields {
        operation: try_get_string(parser, mappings.get_etw_field("Operation")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        query: try_get_string(parser, mappings.get_etw_field("Query")?)
            .or_else(|| try_get_string(parser, "Commandline")),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
            .or_else(|| try_get_uint(parser, "ClientProcessId")),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        event_namespace: try_get_string(parser, mappings.get_etw_field("EventNamespace")?)
            .or_else(|| try_get_string(parser, "NamespaceName")),
        event_type: try_get_string(parser, mappings.get_etw_field("EventType")?),
        destination_hostname: try_get_string(
            parser,
            mappings.get_etw_field("DestinationHostname")?,
        )
        .or_else(|| try_get_string(parser, "ClientMachine")),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Wmi(fields),
    })
}

fn decode_task(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::task_creation_mappings();
    let fields = TaskCreationFields {
        task_name: try_get_string(parser, mappings.get_etw_field("TaskName")?),
        task_content: try_get_string(parser, mappings.get_etw_field("TaskContent")?),
        user_name: try_get_string(parser, mappings.get_etw_field("UserName")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Task(fields),
    })
}

fn filetime_to_system_time(filetime: i64) -> SystemTime {
    let unix_100ns = filetime.saturating_sub(WINDOWS_EPOCH_DELTA_100NS).max(0) as u64;
    let secs = unix_100ns / 10_000_000;
    let nanos = (unix_100ns % 10_000_000) * 100;
    UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(nanos)
}

fn try_get_string(parser: &Parser, property_name: &str) -> Option<String> {
    match parser.try_parse::<String>(property_name) {
        Ok(value) => {
            let trimmed = value.trim_end_matches('\0').to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(_) => None,
    }
}

fn try_get_string_any(parser: &Parser, property_names: &[&str]) -> Option<String> {
    for property_name in property_names {
        if let Some(value) = try_get_string(parser, property_name) {
            return Some(value);
        }
    }
    None
}

fn try_get_uint(parser: &Parser, property_name: &str) -> Option<String> {
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(value.to_string());
    }
    if let Ok(value) = parser.try_parse::<u64>(property_name) {
        return Some(value.to_string());
    }
    if let Ok(value) = parser.try_parse::<u16>(property_name) {
        return Some(value.to_string());
    }
    if let Ok(value) = parser.try_parse::<u8>(property_name) {
        return Some(value.to_string());
    }
    None
}

fn try_get_uint_as_u64(parser: &Parser, property_name: &str) -> Option<u64> {
    if let Ok(value) = parser.try_parse::<u64>(property_name) {
        return Some(value);
    }
    if let Ok(value) = parser.try_parse::<i64>(property_name) {
        return Some(value as u64);
    }
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(value as u64);
    }
    None
}

fn try_get_port(parser: &Parser, property_name: &str) -> Option<String> {
    if let Ok(value) = parser.try_parse::<u16>(property_name) {
        return Some(decode_etw_port(value).to_string());
    }
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(decode_etw_port(value as u16).to_string());
    }
    None
}

fn try_get_ip(
    parser: &Parser,
    property_name: &str,
    address_family: NetworkAddressFamily,
) -> Option<String> {
    match address_family {
        NetworkAddressFamily::Ipv4 => {
            if let Ok(addr) = parser.try_parse::<u32>(property_name) {
                return Some(decode_etw_ipv4(addr).to_string());
            }
        }
        NetworkAddressFamily::Ipv6 => {
            if let Ok(IpAddr::V6(addr)) = parser.try_parse::<IpAddr>(property_name) {
                return Some(addr.to_string());
            }
        }
        NetworkAddressFamily::Unspecified => {
            if let Ok(ip) = parser.try_parse::<IpAddr>(property_name) {
                return Some(ip.to_string());
            }
        }
    }
    try_get_string(parser, property_name)
}

fn parse_optional_u32(value: Option<&str>) -> Option<u32> {
    value.and_then(|value| value.parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_properties_are_set_explicitly() {
        // The bug this guards is silent: leaving the properties at their
        // defaults cost 12-60% of process starts under a fork tree, with no
        // error and no counter (#306). Assert the session is not running on
        // `ferrisetw`'s defaults, and that the pool it asks for is large
        // enough to matter.
        let props = session_properties();
        let defaults = TraceProperties::default();

        assert!(
            props.buffer_size > defaults.buffer_size,
            "buffer size must be raised above the {} KB default",
            defaults.buffer_size
        );
        assert!(
            props.min_buffer > 0 && props.max_buffer >= props.min_buffer,
            "buffer counts must be explicit and ordered, got {}-{}",
            props.min_buffer,
            props.max_buffer
        );

        // The default ceiling is 24 x 32 KB; anything close to it is not a fix.
        let ceiling_kb = props.buffer_size as u64 * props.max_buffer as u64;
        assert!(
            ceiling_kb >= 16 * 1024,
            "buffer pool ceiling is only {ceiling_kb} KB"
        );

        // Below one second ETW clamps silently, so the value would not be the
        // configured one.
        assert!(props.flush_timer >= Duration::from_secs(1));

        // Ordering is load-bearing for the path caches; inheriting the default
        // logging mode is what keeps it. See `session_properties`.
        assert_eq!(props.log_file_mode, defaults.log_file_mode);
    }

    #[test]
    fn process_session_trades_buffer_size_for_pool_depth() {
        // The two properties this session exists for, and they pull in
        // opposite directions if only one number is available to tune: a
        // *small* buffer so it fills and is handed over before a short-lived
        // process exits (#349), and a *deep* pool so a fork tree does not
        // overrun it the way `ferrisetw`'s defaults did (#312).
        let props = process_session_properties();
        let main = session_properties();
        let defaults = TraceProperties::default();

        assert!(
            props.buffer_size <= defaults.buffer_size,
            "process buffers must not be larger than the {} KB default that measured 15/15",
            defaults.buffer_size
        );
        assert!(
            props.buffer_size < main.buffer_size,
            "a process session sized like the main session is not a fix"
        );

        assert!(
            props.min_buffer > 0 && props.max_buffer >= props.min_buffer,
            "buffer counts must be explicit and ordered, got {}-{}",
            props.min_buffer,
            props.max_buffer
        );
        let ceiling_kb = props.buffer_size as u64 * props.max_buffer as u64;
        assert!(
            ceiling_kb >= 16 * 1024,
            "process buffer pool ceiling is only {ceiling_kb} KB"
        );

        assert!(props.flush_timer >= Duration::from_secs(1));
        assert_eq!(props.log_file_mode, defaults.log_file_mode);
    }

    #[test]
    fn sessions_partition_the_providers() {
        // A provider dropped from both lists is silent telemetry loss, and one
        // enabled on both is a duplicate of every event it carries.
        let mut split: Vec<&str> = EtwProviders::process_session()
            .iter()
            .chain(EtwProviders::main_session().iter())
            .map(|provider| provider.name)
            .collect();
        let mut all: Vec<&str> = EtwProviders::all()
            .iter()
            .map(|provider| provider.name)
            .collect();
        split.sort_unstable();
        all.sort_unstable();

        assert_eq!(split, all, "provider split does not cover every provider");
        let unique = {
            let mut names = split.clone();
            names.dedup();
            names
        };
        assert_eq!(unique, split, "a provider is enabled on both sessions");
    }

    #[test]
    fn only_kernel_process_is_split_off() {
        // Registry must stay on the main session: `RegistryPathCache` pairs a
        // write with the `OpenKey` that named its key, and that pairing only
        // holds within one session's ordering. Kernel-File has the same
        // constraint through `FilePathCache`.
        let names: Vec<&str> = EtwProviders::process_session()
            .iter()
            .map(|provider| provider.name)
            .collect();
        assert_eq!(names, vec!["Microsoft-Windows-Kernel-Process"]);
    }

    #[test]
    fn sessions_have_distinct_names() {
        assert_ne!(TRACE_SESSION_NAME, PROCESS_TRACE_SESSION_NAME);
    }

    #[test]
    fn shutdown_is_not_treated_as_a_processing_failure() {
        // `stop_trace_by_name` makes the blocking `process()` return an error;
        // reporting that as a sensor failure would make every clean stop look
        // like a crash, and swallowing it unconditionally would hide a real one
        // (#256).
        let err = || Err(ferrisetw::trace::TraceError::InvalidTraceName);

        assert!(interpret_process_result(TRACE_SESSION_NAME, err(), true).is_ok());
        assert!(interpret_process_result(TRACE_SESSION_NAME, err(), false).is_err());
        assert!(interpret_process_result(TRACE_SESSION_NAME, Ok(()), false).is_ok());
    }

    #[test]
    fn filter_matches_routing_allowlist() {
        // The provider-side filter is an allowlist: an ID that routes but is
        // missing here never reaches the callback at all, which would delete a
        // detection with no error, no dropped-event counter, and nothing in the
        // log. Derive the expected set from the router so the two cannot drift.
        let routed: Vec<u16> = (0u16..=64)
            .filter(|id| kernel_file_route(*id).is_some())
            .collect();
        assert_eq!(
            routed,
            KERNEL_FILE_ROUTED_EVENT_IDS.to_vec(),
            "provider filter and kernel_file_route disagree"
        );
    }

    #[test]
    fn kernel_file_event_ids_route_to_actions() {
        use KernelFileRoute::Emit;
        assert_eq!(kernel_file_route(12), Some(Emit(SensorAction::Create)));
        assert_eq!(kernel_file_route(16), Some(Emit(SensorAction::Modify)));
        assert_eq!(kernel_file_route(26), Some(Emit(SensorAction::Delete)));
        assert_eq!(kernel_file_route(27), Some(Emit(SensorAction::Rename)));
        assert_eq!(kernel_file_route(28), Some(Emit(SensorAction::Rename)));
    }

    #[test]
    fn name_cache_events_are_index_maintenance_not_telemetry() {
        // Measured on Windows 11: one CreateNew emits both a Create (12) and a
        // NameCreate (10). Treating 10 as telemetry produced a spurious change
        // event per file creation, and a rename produced three events.
        assert_eq!(kernel_file_route(10), Some(KernelFileRoute::Index));
        assert_eq!(kernel_file_route(11), Some(KernelFileRoute::EvictKey));
        assert_eq!(kernel_file_route(14), Some(KernelFileRoute::EvictObject));
    }

    #[test]
    fn unexamined_kernel_file_events_are_dropped_not_called_modifications() {
        // The old `_ => Modify` catch-all labelled every one of these a file
        // modification. 18 and 19 are the pathless duplicates of DeletePath
        // (26) and RenamePath (27); the rest are reads and queries.
        for event_id in [13, 15, 18, 19, 20, 21, 22, 23, 30, 32, 34, 99] {
            assert_eq!(
                kernel_file_route(event_id),
                None,
                "event {event_id} must not be routed"
            );
        }
    }

    #[test]
    fn set_information_needs_its_info_class() {
        assert_eq!(
            kernel_file_route(17),
            Some(KernelFileRoute::SetInformation),
            "the action depends on InfoClass, which needs the parsed event"
        );
    }

    #[test]
    fn file_keywords_enable_close_and_set_information() {
        // FILEIO is what delivers Close (14) and SetInformation (17); without
        // it the path index can never release a handle and truncation and
        // creation-time changes are never collected at all.
        assert_ne!(
            EtwProviders::FILE_KEYWORDS & EtwProviders::KERNEL_FILE_KEYWORD_FILEIO,
            0
        );
    }

    #[test]
    fn registry_details_reads_the_value_data_property() {
        // `Details` meant `ValueName` until #292, which made 180 SigmaHQ rules
        // match the name of the value instead of what was written into it.
        assert_eq!(
            field_maps::registry_event_mappings().get_etw_field("Details"),
            Some("CapturedData"),
            "Details must map to the value data, with ValueName only as fallback"
        );
    }

    #[test]
    fn registry_filter_matches_routing_allowlist() {
        // Same allowlist-drift guard as the Kernel-File filter: an ID that
        // routes but is missing from the filter never reaches the callback.
        let routed: Vec<u16> = (0u16..=64)
            .filter(|id| kernel_registry_route(*id).is_some())
            .collect();
        let mut expected = KERNEL_REGISTRY_ROUTED_EVENT_IDS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            routed, expected,
            "provider filter and kernel_registry_route disagree"
        );
    }

    #[test]
    fn registry_event_ids_route_to_write_actions() {
        use KernelRegistryRoute::Emit;
        assert_eq!(kernel_registry_route(3), Some(Emit(SensorAction::Delete)));
        assert_eq!(kernel_registry_route(5), Some(Emit(SensorAction::Set)));
        assert_eq!(kernel_registry_route(6), Some(Emit(SensorAction::Delete)));
    }

    #[test]
    fn naming_events_maintain_the_index_and_only_create_emits() {
        // SetValueKey delivers an empty KeyName, so CreateKey and OpenKey are
        // the only source of a key's path. OpenKey must never produce
        // telemetry of its own; CreateKey does, subject to its Disposition.
        assert_eq!(
            kernel_registry_route(1),
            Some(KernelRegistryRoute::Name { creates: true })
        );
        assert_eq!(
            kernel_registry_route(2),
            Some(KernelRegistryRoute::Name { creates: false })
        );
        assert_eq!(kernel_registry_route(13), Some(KernelRegistryRoute::Evict));
    }

    #[test]
    fn registry_reads_are_dropped_not_called_modifications() {
        // The `_ => Modify` catch-all this replaces put every one of these
        // through the full Sigma evaluation under an action code of 0.
        for event_id in [4, 7, 8, 9, 10, 11, 12, 14, 15, 16, 40, 99] {
            assert_eq!(
                kernel_registry_route(event_id),
                None,
                "registry event {event_id} must not be routed"
            );
        }
    }

    #[test]
    fn registry_keywords_cover_writes_naming_and_eviction() {
        // Manifest values: CloseKey 0x1, SetValueKey 0x100,
        // DeleteValueKey 0x200, CreateKey 0x1000, OpenKey 0x2000,
        // DeleteKey 0x4000. The mask previously used 0x2000 and 0x8000 for the
        // two *value* keywords, which are OpenKey and QueryKey — it subscribed
        // to reads and missed every value write.
        assert_eq!(EtwProviders::REGISTRY_KEYWORDS, 0x7301);

        // QueryKey is the one high-volume read path with no role here: it
        // neither names a key nor changes one.
        const QUERY_KEY: u64 = 0x8000;
        assert_eq!(EtwProviders::REGISTRY_KEYWORDS & QUERY_KEY, 0);
    }

    #[test]
    fn every_routed_registry_event_has_its_keyword() {
        // A routed event whose keyword is not in the mask is never delivered:
        // the exact failure that made `registry_set` structurally dead (#279).
        for (event_id, keyword) in [
            (1u16, EtwProviders::REG_KEYWORD_CREATE_KEY),
            (2, EtwProviders::REG_KEYWORD_OPEN_KEY),
            (3, EtwProviders::REG_KEYWORD_DELETE_KEY),
            (5, EtwProviders::REG_KEYWORD_SET_VALUE_KEY),
            (6, EtwProviders::REG_KEYWORD_DELETE_VALUE_KEY),
            (13, EtwProviders::REG_KEYWORD_CLOSE_KEY),
        ] {
            assert!(
                kernel_registry_route(event_id).is_some(),
                "event {event_id} must be routed"
            );
            assert_ne!(
                EtwProviders::REGISTRY_KEYWORDS & keyword,
                0,
                "event {event_id} is routed but its keyword is not subscribed"
            );
        }
    }

    #[test]
    fn provider_guids_are_unique() {
        let providers = EtwProviders::all();
        let mut guids = std::collections::HashSet::new();

        for provider in providers {
            assert!(
                guids.insert(format!("{:?}", provider.guid)),
                "duplicate GUID found for provider: {}",
                provider.name
            );
        }
    }

    #[test]
    fn user_providers_are_scoped_to_matchable_events() {
        let dns = EtwProviders::dns_client();
        assert_eq!(dns.keywords, EtwProviders::OPERATIONAL_KEYWORD);
        assert_eq!(dns.event_ids, &[3006, 3008]);

        let powershell = EtwProviders::powershell();
        // Both keywords are required: 4104 is published under `Runspace` and
        // 4103 under `Cmdlets`, so dropping either silently removes a whole
        // Sigma logsource from the sensor.
        assert_ne!(
            powershell.keywords & EtwProviders::POWERSHELL_RUNSPACE_KEYWORD,
            0
        );
        assert_ne!(
            powershell.keywords & EtwProviders::POWERSHELL_CMDLETS_KEYWORD,
            0
        );
        assert_eq!(powershell.level, 5);
        assert_eq!(powershell.event_ids, &[4103, 4104]);

        assert_eq!(EtwProviders::task_scheduler().event_ids, &[106]);
        assert!(!EtwProviders::WMI_EVENT_IDS.contains(&3));
        assert!(!EtwProviders::WMI_EVENT_IDS.contains(&13));
        assert!(!EtwProviders::WMI_EVENT_IDS.contains(&18));
    }

    #[test]
    fn powershell_filter_matches_routing_allowlist() {
        // A provider filter and a router that disagree fail silently: an ID in
        // the filter but not the router is decoded work thrown away, and an ID
        // in the router but not the filter never reaches the session at all.
        for &event_id in EtwProviders::POWERSHELL_EVENT_IDS {
            assert!(
                powershell_route(event_id).is_some(),
                "event {event_id} is subscribed but not routed"
            );
        }

        assert_eq!(
            powershell_route(POWERSHELL_EVENT_SCRIPT_BLOCK),
            Some((EventCategory::Scripting, SensorAction::Execute)),
            "script block logging must stay on ps_script"
        );
        assert_eq!(
            powershell_route(POWERSHELL_EVENT_MODULE_LOGGING),
            Some((EventCategory::PowerShellModule, SensorAction::Execute)),
            "module logging must reach ps_module, not ps_script"
        );
        // 4105/4106 (script block start/stop) share the Runspace keyword and
        // carry no matchable text.
        assert_eq!(powershell_route(4105), None);
        assert_eq!(powershell_route(4106), None);
    }

    #[test]
    fn wmi_activity_event_ids_do_not_alias_sysmon_wmi_event_ids() {
        // Sysmon `wmi_event`: 19 = filter, 20 = consumer, 21 = binding.
        const SYSMON_WMI_EVENT_IDS: &[u16] = &[19, 20, 21];

        for &event_id in EtwProviders::WMI_EVENT_IDS {
            let sysmon_id = mapper::map_to_sysmon_id(EventCategory::Wmi, 0, event_id);
            assert!(
                !SYSMON_WMI_EVENT_IDS.contains(&sysmon_id),
                "native WMI-Activity event {event_id} reaches the engine as \
                 Sysmon wmi_event ID {sysmon_id}, so a stock rule selecting \
                 that ID would match an unrelated event"
            );
        }
    }

    #[test]
    fn fieldless_provider_payload_is_not_matchable() {
        let empty = SensorPayload::Scripting(PowerShellScriptFields {
            script_block_text: None,
            script_block_id: None,
            path: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(!has_matchable_fields(&empty));

        let populated = SensorPayload::Scripting(PowerShellScriptFields {
            script_block_text: Some("Get-Process".to_string()),
            script_block_id: None,
            path: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(has_matchable_fields(&populated));

        let empty_module = SensorPayload::PowerShellModule(PowerShellModuleFields {
            context_info: None,
            payload: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(!has_matchable_fields(&empty_module));

        let populated_module = SensorPayload::PowerShellModule(PowerShellModuleFields {
            context_info: Some("Host Application = powershell.exe".to_string()),
            payload: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(has_matchable_fields(&populated_module));
    }
}
