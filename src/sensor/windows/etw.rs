use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, TraceTrait, UserTrace};
use ferrisetw::{EventRecord, GUID};
use tokio::sync::mpsc::{error::TrySendError, Sender};
use tracing::{info, trace, warn};

use crate::models::{
    DnsQueryFields, EventCategory, FileEventFields, ImageLoadFields, NetworkConnectionFields,
    PowerShellScriptFields, ProcessCreationFields, RegistryEventFields, ServiceCreationFields,
    TaskCreationFields, WmiEventFields,
};
use crate::sensor::network_events::{
    classify_kernel_network_event, decode_etw_ipv4, decode_etw_port, NetworkAddressFamily,
};
use crate::sensor::{Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorPayload};
use crate::utils::{convert_nt_to_dos, parse_metadata, query_process_command_line};

use super::file_paths::FilePathCache;
use super::{field_maps, mapper};

/// Fixed trace session name for stopping the trace on shutdown.
const TRACE_SESSION_NAME: &str = "rustinel-etw-trace";
const WINDOWS_EPOCH_DELTA_100NS: i64 = 116444736000000000;

/// ETW provider metadata.
#[derive(Debug, Clone)]
struct EtwProvider {
    guid: GUID,
    name: &'static str,
    keywords: u64,
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
    const SERVICE_CONTROL_MANAGER_GUID: &'static str = "555908d1-a6d7-4695-8e1e-26931d2012f4";
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

    const REG_KEYWORD_CREATE_KEY: u64 = 0x1000;
    const REG_KEYWORD_SET_VALUE_KEY: u64 = 0x2000;
    const REG_KEYWORD_DELETE_KEY: u64 = 0x4000;
    const REG_KEYWORD_DELETE_VALUE_KEY: u64 = 0x8000;
    const REGISTRY_KEYWORDS: u64 = Self::REG_KEYWORD_CREATE_KEY
        | Self::REG_KEYWORD_SET_VALUE_KEY
        | Self::REG_KEYWORD_DELETE_KEY
        | Self::REG_KEYWORD_DELETE_VALUE_KEY;

    const WINEVENT_KEYWORD_PROCESS: u64 = 0x0010;
    const WINEVENT_KEYWORD_IMAGE: u64 = 0x0040;
    const PROCESS_KEYWORDS: u64 = Self::WINEVENT_KEYWORD_PROCESS | Self::WINEVENT_KEYWORD_IMAGE;

    const NETWORK_KEYWORD_TCPIP: u64 = 0x10;
    const NETWORK_KEYWORD_UDP: u64 = 0x20;
    const NETWORK_KEYWORDS: u64 = Self::NETWORK_KEYWORD_TCPIP | Self::NETWORK_KEYWORD_UDP;

    const DEFAULT_KEYWORDS: u64 = u64::MAX;

    fn kernel_process() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_PROCESS_GUID),
            name: "Microsoft-Windows-Kernel-Process",
            keywords: Self::PROCESS_KEYWORDS,
        }
    }

    fn kernel_network() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_NETWORK_GUID),
            name: "Microsoft-Windows-Kernel-Network",
            keywords: Self::NETWORK_KEYWORDS,
        }
    }

    fn kernel_file() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_FILE_GUID),
            name: "Microsoft-Windows-Kernel-File",
            keywords: Self::FILE_KEYWORDS,
        }
    }

    fn kernel_registry() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_REGISTRY_GUID),
            name: "Microsoft-Windows-Kernel-Registry",
            keywords: Self::REGISTRY_KEYWORDS,
        }
    }

    fn dns_client() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::DNS_CLIENT_GUID),
            name: "Microsoft-Windows-DNS-Client",
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    fn powershell() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::POWERSHELL_GUID),
            name: "Microsoft-Windows-PowerShell",
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    fn wmi_activity() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::WMI_ACTIVITY_GUID),
            name: "Microsoft-Windows-WMI-Activity",
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    fn service_control_manager() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::SERVICE_CONTROL_MANAGER_GUID),
            name: "Microsoft-Windows-Service-Control-Manager",
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    fn task_scheduler() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::TASK_SCHEDULER_GUID),
            name: "Microsoft-Windows-TaskScheduler",
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    fn all() -> Vec<EtwProvider> {
        vec![
            Self::kernel_process(),
            Self::kernel_network(),
            Self::kernel_file(),
            Self::kernel_registry(),
            Self::dns_client(),
            Self::powershell(),
            Self::wmi_activity(),
            Self::service_control_manager(),
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

/// Shared state the ETW callback carries across events.
///
/// The path index has to outlive a single event: the naming event and the
/// write it explains are different records, often seconds apart.
struct EtwState {
    routing: EtwRouting,
    file_paths: Mutex<FilePathCache>,
    /// File events dropped because neither identifier resolved to a path.
    ///
    /// Handles opened before the sensor started were never indexed, so writes
    /// through them cannot be attributed until the handle is reopened. Dropping
    /// them is the right policy — a pathless event matches no rule — but without
    /// a count there is no way to tell a quiet endpoint from a blind one.
    unresolved_file_events: AtomicU64,
}

impl EtwState {
    fn new() -> Self {
        Self {
            routing: EtwRouting::new(),
            file_paths: Mutex::new(FilePathCache::new()),
            unresolved_file_events: AtomicU64::new(0),
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
}

struct EtwRouting {
    kernel_process_guid: GUID,
    kernel_file_guid: GUID,
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
        guid_to_category.insert(EtwProviders::powershell().guid, EventCategory::Scripting);
        guid_to_category.insert(EtwProviders::wmi_activity().guid, EventCategory::Wmi);
        guid_to_category.insert(
            EtwProviders::service_control_manager().guid,
            EventCategory::Service,
        );
        guid_to_category.insert(EtwProviders::task_scheduler().guid, EventCategory::Task);

        Self {
            kernel_process_guid: EtwProviders::kernel_process().guid,
            kernel_file_guid: EtwProviders::kernel_file().guid,
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

        let category = *self.guid_to_category.get(&provider_guid)?;
        let action = match category {
            EventCategory::Network => {
                classify_kernel_network_event(record.event_id())?.connection_action()?
            }
            // Kernel-File needs the path index and so has its own pipeline;
            // `decode_record` diverts it before reaching here.
            EventCategory::File => return None,
            EventCategory::Registry => match record.opcode() {
                36 => SensorAction::Create,
                38 | 41 => SensorAction::Delete,
                39 => SensorAction::Set,
                _ => SensorAction::Modify,
            },
            EventCategory::Dns => SensorAction::Query,
            EventCategory::Scripting => SensorAction::Execute,
            EventCategory::Wmi => SensorAction::Execute,
            EventCategory::Service | EventCategory::Task => SensorAction::Register,
            EventCategory::Process | EventCategory::ImageLoad => unreachable!(),
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
}

impl EtwSensor {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl Default for EtwSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for EtwSensor {
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        info!("Starting ETW sensor...");

        let _ = stop_trace_by_name(TRACE_SESSION_NAME);

        let mut trace_builder = UserTrace::new().named(TRACE_SESSION_NAME.to_string());
        let state = Arc::new(EtwState::new());

        for provider_def in EtwProviders::all() {
            info!(
                "Enabling ETW provider: {} ({:?}) with keywords: 0x{:X}",
                provider_def.name, provider_def.guid, provider_def.keywords
            );

            let state = Arc::clone(&state);
            let tx = tx.clone();
            let mut provider_builder = Provider::by_guid(provider_def.guid)
                .level(4)
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

            // Only Kernel-File is filtered: the FILEIO keyword it needs for
            // Close and SetInformation also turns on every read and query on
            // the machine, and none of those are routed.
            if provider_def.guid == EtwProviders::kernel_file().guid {
                provider_builder = provider_builder.add_filter(EventFilter::ByEventIds(
                    KERNEL_FILE_ROUTED_EVENT_IDS.to_vec(),
                ));
            }

            let provider = provider_builder.build();

            trace_builder = trace_builder.enable(provider);
        }

        let result = trace_builder.start();
        match result {
            Ok((mut trace, _handle)) => {
                info!(
                    "ETW trace session '{}' started successfully",
                    TRACE_SESSION_NAME
                );

                match trace.process() {
                    Ok(()) => {
                        info!("ETW sensor stopped");
                        Ok(())
                    }
                    Err(err) => {
                        // Stopping the trace from `shutdown()` makes `process()`
                        // return an error by design; only a failure while the
                        // sensor is supposed to keep running is a real one, and
                        // it must reach the caller — logging alone buries the
                        // ETW error code in the operational log (#256).
                        if self.shutdown.load(Ordering::Relaxed) {
                            info!("ETW sensor stopped with result: {:?}", err);
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!("ETW trace processing failed: {:?}", err))
                        }
                    }
                }
            }
            Err(err) => Err(anyhow::anyhow!("Failed to start ETW trace: {:?}", err)),
        }
    }

    fn shutdown(&self) {
        info!("Initiating graceful shutdown of ETW sensor...");
        self.shutdown.store(true, Ordering::Relaxed);

        info!("Stopping ETW trace session '{}'...", TRACE_SESSION_NAME);
        if let Err(err) = stop_trace_by_name(TRACE_SESSION_NAME) {
            warn!(
                "Failed to stop trace session '{}': {:?}",
                TRACE_SESSION_NAME, err
            );
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
        EventCategory::Registry => decode_registry(&parser, record),
        EventCategory::Dns => decode_dns(&parser, record),
        EventCategory::ImageLoad => decode_image_load(&parser, record),
        EventCategory::Scripting => decode_powershell(&parser, record),
        EventCategory::Wmi => decode_wmi(&parser, record),
        EventCategory::Service => decode_service(&parser, record),
        EventCategory::Task => decode_task(&parser, record),
    }?;

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

fn decode_process(
    parser: &Parser,
    record: &EventRecord,
    action: SensorAction,
) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::process_creation_mappings();
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

    let (original_file_name, product, description) = if action == SensorAction::Start {
        if let Some(path) = image.as_deref() {
            if let Some(metadata) = parse_metadata(path) {
                (
                    metadata.original_filename,
                    metadata.product,
                    metadata.description,
                )
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    let mut fields = ProcessCreationFields {
        image: image.clone(),
        original_file_name,
        product,
        description,
        target_image: try_get_string(parser, mappings.get_etw_field("TargetImage")?)
            .map(|path| convert_nt_to_dos(&path)),
        command_line: try_get_string(parser, mappings.get_etw_field("CommandLine")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
            .or_else(|| Some(record.process_id().to_string())),
        process_start_time: creation_time_with_fallback,
        parent_process_id: try_get_uint(parser, mappings.get_etw_field("ParentProcessId")?),
        parent_image,
        parent_command_line: try_get_string(parser, mappings.get_etw_field("ParentCommandLine")?),
        current_directory,
        integrity_level: try_get_string(parser, mappings.get_etw_field("IntegrityLevel")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        logon_id: try_get_string(parser, mappings.get_etw_field("LogonId")?),
        logon_guid: try_get_string(parser, mappings.get_etw_field("LogonGuid")?),
    };

    let pid = fields
        .process_id
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_else(|| record.process_id());

    if action == SensorAction::Start && fields.command_line.is_none() {
        if let Some(command_line) = query_process_command_line(pid) {
            fields.command_line = Some(command_line);
        }
    }

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
                    warn!(
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

fn decode_registry(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let event_mappings = field_maps::registry_event_mappings();
    let modify_mappings = field_maps::registry_modify_mappings();

    let fields = RegistryEventFields {
        target_object: try_get_string(parser, event_mappings.get_etw_field("TargetObject")?)
            .or_else(|| try_get_string(parser, modify_mappings.get_etw_field("TargetObject")?)),
        details: try_get_string(parser, event_mappings.get_etw_field("Details")?)
            .or_else(|| try_get_string(parser, modify_mappings.get_etw_field("Details")?)),
        process_id: try_get_uint(parser, event_mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, event_mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        event_type: try_get_string(parser, "EventType"),
        user: try_get_string(parser, event_mappings.get_etw_field("User")?),
        new_name: try_get_string(parser, "NewName"),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Registry(fields),
    })
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

    let (original_file_name, product, description) = if let Some(path) = image_loaded.as_deref() {
        if let Some(metadata) = parse_metadata(path) {
            (
                metadata.original_filename,
                metadata.product,
                metadata.description,
            )
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    let fields = ImageLoadFields {
        image_loaded,
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        original_file_name,
        product,
        description,
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

fn decode_wmi(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::wmi_event_mappings();
    let fields = WmiEventFields {
        operation: try_get_string(parser, mappings.get_etw_field("Operation")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        query: try_get_string(parser, mappings.get_etw_field("Query")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        event_namespace: try_get_string(parser, mappings.get_etw_field("EventNamespace")?),
        event_type: try_get_string(parser, mappings.get_etw_field("EventType")?),
        destination_hostname: try_get_string(
            parser,
            mappings.get_etw_field("DestinationHostname")?,
        ),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Wmi(fields),
    })
}

fn decode_service(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::service_creation_mappings();
    let fields = ServiceCreationFields {
        service_name: try_get_string(parser, mappings.get_etw_field("ServiceName")?),
        service_file_name: try_get_string(parser, mappings.get_etw_field("ServiceFileName")?)
            .map(|path| convert_nt_to_dos(&path)),
        service_type: try_get_uint(parser, mappings.get_etw_field("ServiceType")?),
        start_type: try_get_uint(parser, mappings.get_etw_field("StartType")?),
        account_name: try_get_string(parser, mappings.get_etw_field("AccountName")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Service(fields),
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
}
