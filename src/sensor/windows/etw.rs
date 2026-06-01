use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
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
use crate::sensor::{Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorPayload};
use crate::utils::{convert_nt_to_dos, parse_metadata, query_process_command_line};

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
    const KERNEL_FILE_GUID: &'static str = "edd08927-9cc4-4e65-b970-63462d3f77bd";
    const KERNEL_REGISTRY_GUID: &'static str = "70eb4f03-c1de-4f73-a051-33d13d5413bd";
    const DNS_CLIENT_GUID: &'static str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
    const POWERSHELL_GUID: &'static str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
    const WMI_ACTIVITY_GUID: &'static str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";
    const SERVICE_CONTROL_MANAGER_GUID: &'static str = "555908d1-a6d7-4695-8e1e-26931d2012f4";
    const TASK_SCHEDULER_GUID: &'static str = "de7b24ea-73c8-4a09-985d-5bdadcfa9017";

    const KERNEL_FILE_KEYWORD_FILENAME: u64 = 0x0010;
    const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x0080;
    const KERNEL_FILE_KEYWORD_DELETE: u64 = 0x0200;
    const KERNEL_FILE_KEYWORD_RENAME: u64 = 0x0400;
    const KERNEL_FILE_KEYWORD_SETINFO: u64 = 0x0800;
    const FILE_KEYWORDS: u64 = Self::KERNEL_FILE_KEYWORD_FILENAME
        | Self::KERNEL_FILE_KEYWORD_CREATE
        | Self::KERNEL_FILE_KEYWORD_DELETE
        | Self::KERNEL_FILE_KEYWORD_RENAME
        | Self::KERNEL_FILE_KEYWORD_SETINFO;

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

struct EtwRouting {
    kernel_process_guid: GUID,
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
            EventCategory::Network => match record.event_id() {
                10 | 11 => return None,
                12 => SensorAction::Connect,
                13 => SensorAction::Disconnect,
                14 => SensorAction::Accept,
                id if id >= 15 => SensorAction::Connect,
                _ => return None,
            },
            EventCategory::File => match record.opcode() {
                64 | 65 => SensorAction::Create,
                70 | 72 => SensorAction::Delete,
                71 => SensorAction::Rename,
                _ => SensorAction::Modify,
            },
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
    dropped_events: Arc<AtomicU64>,
}

impl EtwSensor {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            dropped_events: Arc::new(AtomicU64::new(0)),
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
        let routing = Arc::new(EtwRouting::new());
        let dropped_events = Arc::clone(&self.dropped_events);

        for provider_def in EtwProviders::all() {
            info!(
                "Enabling ETW provider: {} ({:?}) with keywords: 0x{:X}",
                provider_def.name, provider_def.guid, provider_def.keywords
            );

            let routing = Arc::clone(&routing);
            let tx = tx.clone();
            let dropped_events = Arc::clone(&dropped_events);
            let provider = Provider::by_guid(provider_def.guid)
                .level(4)
                .any(provider_def.keywords)
                .add_callback(move |record, schema_locator| {
                    let Some(event) = decode_record(record, schema_locator, &routing) else {
                        return;
                    };

                    match tx.try_send(event) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            let dropped = dropped_events.fetch_add(1, Ordering::Relaxed) + 1;
                            if dropped == 1 || dropped.is_multiple_of(100) {
                                warn!(
                                    dropped_events = dropped,
                                    "Sensor event channel full; dropping ETW event"
                                );
                            }
                        }
                        Err(TrySendError::Closed(_)) => {
                            trace!("Sensor event channel closed; dropping ETW event");
                        }
                    }
                })
                .build();

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
                        if self.shutdown.load(Ordering::Relaxed) {
                            info!("ETW sensor stopped with result: {:?}", err);
                            Ok(())
                        } else {
                            warn!("ETW trace processing error: {:?}", err);
                            Ok(())
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
    routing: &EtwRouting,
) -> Option<SensorEvent> {
    let (category, action) = routing.route(record)?;
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
        EventCategory::File => decode_file(&parser, record),
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
            creation_time_with_fallback.map(|start_time| ProcessStartKey { pid, start_time })
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

fn decode_file(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::file_event_mappings();
    let fields = FileEventFields {
        source_filename: None,
        target_filename: try_get_string(parser, mappings.get_etw_field("TargetFilename")?)
            .map(|path| convert_nt_to_dos(&path)),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        creation_utc_time: try_get_string(parser, mappings.get_etw_field("CreationUtcTime")?),
        previous_creation_utc_time: try_get_string(parser, "PreviousCreationTime"),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
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
    let transport = match record.event_id() {
        12..=14 => Some("tcp".to_string()),
        id if id >= 15 => Some("udp".to_string()),
        _ => None,
    };

    let fields = NetworkConnectionFields {
        destination_ip: try_get_ip(parser, "daddr")
            .or_else(|| try_get_ip(parser, "DestinationAddress"))
            .or_else(|| try_get_ip(parser, "RemoteAddress"))
            .or_else(|| try_get_ip(parser, "dstaddr")),
        source_ip: try_get_ip(parser, "saddr")
            .or_else(|| try_get_ip(parser, "SourceAddress"))
            .or_else(|| try_get_ip(parser, "LocalAddress"))
            .or_else(|| try_get_ip(parser, "srcaddr")),
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
        protocol: transport,
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
        return Some(u16::from_be(value).to_string());
    }
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(u16::from_be(value as u16).to_string());
    }
    None
}

fn try_get_ip(parser: &Parser, property_name: &str) -> Option<String> {
    if let Ok(ip) = parser.try_parse::<IpAddr>(property_name) {
        return Some(ip.to_string());
    }
    if let Ok(addr) = parser.try_parse::<u32>(property_name) {
        let ipv4 = Ipv4Addr::from(addr.to_be_bytes());
        return Some(ipv4.to_string());
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
