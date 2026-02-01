//! Event normalizer module ("Sysmon-izer")
//!
//! Converts kernel ETW field names to Sigma/Sysmon standard format.
//! Critical for mapping between kernel events and Sigma rule expectations.

mod field_maps;
mod mapper;

use crate::models::*;
use crate::state::{
    AggregationResult, ConnectionAggregator, DnsCache, ProcessCache, Protocol, SidCache,
};
#[cfg(windows)]
use crate::utils::query_process_command_line;
use crate::utils::{convert_nt_to_dos, parse_metadata};
use chrono::{DateTime, SecondsFormat, Utc};
use ferrisetw::parser::Parser;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tracing::debug;

/// Event normalizer that converts ETW events to Sigma-compatible format
pub struct Normalizer {
    schema_locator: SchemaLocator,
    process_cache: Arc<ProcessCache>,
    sid_cache: Arc<SidCache>,
    dns_cache: Arc<DnsCache>,
    connection_aggregator: Arc<ConnectionAggregator>,
    aggregation_enabled: bool,
}

impl Normalizer {
    /// Creates a new normalizer instance
    pub fn new(
        process_cache: Arc<ProcessCache>,
        sid_cache: Arc<SidCache>,
        dns_cache: Arc<DnsCache>,
        connection_aggregator: Arc<ConnectionAggregator>,
        aggregation_enabled: bool,
    ) -> Self {
        Self {
            schema_locator: SchemaLocator::default(),
            process_cache,
            sid_cache,
            dns_cache,
            connection_aggregator,
            aggregation_enabled,
        }
    }

    /// Normalize an ETW event to Sigma-compatible format
    pub fn normalize(
        &self,
        record: &EventRecord,
        category: EventCategory,
    ) -> Option<NormalizedEvent> {
        // Get timestamp
        let timestamp = format_timestamp(record);

        // Create parser for this event
        let schema = match self.schema_locator.event_schema(record) {
            Ok(schema) => schema,
            Err(e) => {
                // Downgraded to debug to reduce noise for providers without valid schemas (e.g. old ImageLoad)
                debug!(
                    "Failed to get schema for event: {:?} (Category: {:?}, ID: {})",
                    e,
                    category,
                    record.event_id()
                );
                return None;
            }
        };

        let parser = Parser::create(record, &schema);

        // Normalize based on category
        let fields = match category {
            EventCategory::Process => self.normalize_process(&parser, record),
            EventCategory::File => self.normalize_file(&parser, record),
            EventCategory::Registry => self.normalize_registry(&parser, record),
            EventCategory::Network => self.normalize_network(&parser, record),
            EventCategory::Dns => self.normalize_dns(&parser, record),
            EventCategory::ImageLoad => self.normalize_image_load(&parser, record),
            EventCategory::Scripting => self.normalize_powershell(&parser, record),
            EventCategory::Wmi => self.normalize_wmi(&parser, record),
            EventCategory::Service => self.normalize_service(&parser, record),
            EventCategory::Task => self.normalize_task(&parser, record),
            EventCategory::PipeEvent => self.normalize_pipe(&parser, record),
        };

        // DEBUG: Log when normalization fails to help diagnose field mapping issues
        if fields.is_none() && tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Failed to normalize event {} (Category: {:?}, OpCode: {})",
                record.event_id(),
                category,
                record.opcode()
            );
        }

        let fields = fields?;

        // Pipe events are detected inside file normalization; re-tag category for Sigma routing.
        let mut category = category;
        if matches!(fields, EventFields::PipeEvent(_)) {
            category = EventCategory::PipeEvent;
        }

        // Map Kernel ETW OpCode/EventID to Sysmon Event ID for Sigma rule compatibility
        let sysmon_event_id =
            mapper::map_to_sysmon_id(category, record.opcode(), record.event_id());
        let process_context = self.build_process_context(&fields, record);

        Some(NormalizedEvent {
            timestamp,
            category,
            event_id: sysmon_event_id,
            event_id_string: sysmon_event_id.to_string(), // Cache string for zero-copy flatten()
            opcode: record.opcode(),                      // Keep original OpCode for debugging
            fields,
            process_context,
        })
    }

    /// Normalize process creation/access events
    fn normalize_process(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::process_creation_mappings();

        // Extract CreateTime (critical for compound key)
        // Try multiple field names as ETW providers may use different names
        let creation_time_opt = try_get_uint_as_u64(parser, "CreateTime")
            .or_else(|| try_get_uint_as_u64(parser, "ProcessStartTime"));
        // Some providers expose a TimeStamp field, but it may be the event timestamp.
        let creation_time_opt_with_timestamp =
            creation_time_opt.or_else(|| try_get_uint_as_u64(parser, "TimeStamp"));

        // Extract raw paths from ETW (may be in NT Device format)
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
        let raw_current_directory =
            try_get_string(parser, mappings.get_etw_field("CurrentDirectory")?);

        // Step 1: Normalize paths (NT Device -> DOS)
        let image = raw_image.map(|p| convert_nt_to_dos(&p));
        let parent_image = raw_parent_image.map(|p| convert_nt_to_dos(&p));
        let current_directory = raw_current_directory.map(|p| convert_nt_to_dos(&p));

        // Step 2: Parse PE metadata (only on Process Start for performance)
        let opcode = record.opcode();
        let (pe_original_filename, pe_product, pe_description) = if opcode == 1 {
            if let Some(ref path) = image {
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
            original_file_name: pe_original_filename.clone(),
            product: pe_product.clone(),
            description: pe_description.clone(),
            target_image: try_get_string(parser, mappings.get_etw_field("TargetImage")?)
                .map(|p| convert_nt_to_dos(&p)),
            command_line: try_get_string(parser, mappings.get_etw_field("CommandLine")?),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
                .or_else(|| try_get_uint_from_payload(record)),
            parent_process_id: try_get_uint(parser, mappings.get_etw_field("ParentProcessId")?),
            parent_image: parent_image.clone(),
            parent_command_line: try_get_string(
                parser,
                mappings.get_etw_field("ParentCommandLine")?,
            ),
            current_directory,
            integrity_level: try_get_string(parser, mappings.get_etw_field("IntegrityLevel")?),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
            logon_id: try_get_string(parser, mappings.get_etw_field("LogonId")?),
            logon_guid: try_get_string(parser, mappings.get_etw_field("LogonGuid")?),
        };

        self.resolve_user_field(&mut fields.user);

        // Best-effort CommandLine enrichment if ETW did not provide it.
        #[cfg(windows)]
        if opcode == 1 && fields.command_line.is_none() {
            let pid = fields
                .process_id
                .as_ref()
                .and_then(|p| p.parse::<u32>().ok())
                .unwrap_or_else(|| record.process_id());
            if let Some(cmd) = query_process_command_line(pid) {
                fields.command_line = Some(cmd);
            }
        }

        // Update process cache based on OpCode
        if opcode == 1 {
            // Process Start - Enrich with parent metadata and add to cache
            if let Some(ref img) = fields.image {
                let creation_time = creation_time_opt_with_timestamp
                    .unwrap_or_else(|| record.raw_timestamp() as u64); // Fallback to event timestamp

                // FIXED: Use ProcessID from payload (child) instead of header (parent).
                // The event header process_id() in ProcessStart is the PARENT PID (creator).
                let pid = fields
                    .process_id
                    .as_ref()
                    .and_then(|p| p.parse::<u32>().ok())
                    .unwrap_or_else(|| record.process_id());

                // Parse parent PID as u32 for cache lookup
                let parent_pid_u32 = fields
                    .parent_process_id
                    .as_ref()
                    .and_then(|p| p.parse::<u32>().ok());

                // Enrichment: Look up parent metadata from cache
                let (parent_image_cached, parent_cmd_cached) = if let Some(ppid) = parent_pid_u32 {
                    if let Some(parent_meta) = self.process_cache.get_metadata(ppid) {
                        debug!(
                            "Enriched process PID={} with parent metadata from cache (PPID={})",
                            pid, ppid
                        );
                        (Some(parent_meta.image_name), parent_meta.command_line)
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                // If ParentImage/ParentCommandLine are missing from ETW, use cached values
                if fields.parent_image.is_none() {
                    fields.parent_image = parent_image_cached.clone();
                }
                if fields.parent_command_line.is_none() {
                    fields.parent_command_line = parent_cmd_cached.clone();
                }

                // Add to cache with compound key, enriched parent data, and PE metadata
                self.process_cache.add(
                    pid,
                    creation_time,
                    img.clone(),
                    fields.command_line.clone(),
                    fields.user.clone(),
                    parent_pid_u32,
                    fields.parent_image.clone(),
                    fields.parent_command_line.clone(),
                    pe_original_filename,
                    pe_product,
                    pe_description,
                    fields.current_directory.clone(),
                    fields.integrity_level.clone(),
                    fields.logon_id.clone(),
                    fields.logon_guid.clone(),
                );
                debug!(
                    "Added process to cache: PID={} CreateTime={} Image={}",
                    pid, creation_time, img
                );
            }
        } else if opcode == 2 {
            // Process Stop - Remove from cache
            // FIXED: Use ProcessID from payload to be consistent
            let pid = fields
                .process_id
                .as_ref()
                .and_then(|p| p.parse::<u32>().ok())
                .unwrap_or_else(|| record.process_id());
            let creation_time =
                creation_time_opt.or_else(|| self.process_cache.get_latest_creation_time(pid));
            if let Some(creation_time) = creation_time {
                self.process_cache.remove(pid, creation_time);
                debug!(
                    "Removed process from cache: PID={} CreateTime={}",
                    pid, creation_time
                );
            } else {
                debug!(
                    "Process stop missing CreateTime; no cache entry found for PID={}",
                    pid
                );
            }
            return None;
        }

        Some(EventFields::ProcessCreation(fields))
    }

    /// Normalize file events
    /// Also detects Named Pipe events for lateral movement detection
    fn normalize_file(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        // Determine which mapping to use based on event ID (if available)
        // For now, use generic file_event mappings
        let mappings = field_maps::file_event_mappings();

        // Check if this is a Named Pipe event
        let raw_target_filename = try_get_string(parser, mappings.get_etw_field("TargetFilename")?);

        if let Some(ref filename) = raw_target_filename {
            // Named Pipes have the path format: \Device\NamedPipe\<pipe_name>
            if filename.starts_with(r"\Device\NamedPipe\") {
                debug!("Detected Named Pipe event: {}", filename);

                // Extract pipe name by removing the \Device\NamedPipe\ prefix
                let pipe_name = filename
                    .strip_prefix(r"\Device\NamedPipe\")
                    .map(|s| s.to_string());

                let mut pipe_fields = PipeEventFields {
                    pipe_name,
                    process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
                    image: try_get_string(parser, mappings.get_etw_field("Image")?)
                        .map(|p| convert_nt_to_dos(&p)),
                    user: try_get_string(parser, mappings.get_etw_field("User")?),
                    event_type: Some(format!("OpCode:{}", record.opcode())),
                };

                // Enrich with cached process data if image is missing
                if pipe_fields.image.is_none() {
                    let pid = record.process_id();
                    if let Some(cached_image) = self.process_cache.get_image(pid) {
                        pipe_fields.image = Some(convert_nt_to_dos(&cached_image));
                        debug!("Enriched pipe event with cached image for PID={}", pid);
                    }
                }

                return Some(EventFields::PipeEvent(pipe_fields));
            }
        }

        // Regular file event - normalize target filename path
        let fields = FileEventFields {
            target_filename: raw_target_filename.map(|p| convert_nt_to_dos(&p)),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
            creation_utc_time: try_get_string(parser, mappings.get_etw_field("CreationUtcTime")?),
            previous_creation_utc_time: try_get_string(parser, "PreviousCreationTime"),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
        };

        let mut fields = fields;
        self.resolve_user_field(&mut fields.user);

        Some(EventFields::FileEvent(fields))
    }

    /// Normalize registry events
    fn normalize_registry(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        // Use registry_modify_mappings as default (most common)
        // In production, you'd check event ID to determine which mapping to use
        let mappings = field_maps::registry_modify_mappings();

        let mut fields = RegistryEventFields {
            target_object: try_get_string(parser, mappings.get_etw_field("TargetObject")?),
            details: try_get_string(parser, mappings.get_etw_field("Details")?),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
            event_type: try_get_string(parser, "EventType"),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
            new_name: try_get_string(parser, "NewName"),
        };

        self.resolve_user_field(&mut fields.user);

        // Enrich with cached process data if image is missing
        if fields.image.is_none() {
            let pid = record.process_id();
            if let Some(cached_image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&cached_image));
                debug!("Enriched registry event with cached image for PID={}", pid);
            }
        }

        Some(EventFields::RegistryEvent(fields))
    }

    /// Normalize network connection events
    fn normalize_network(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::network_connection_mappings();

        // DEBUG: Try multiple possible field names for network events
        // Microsoft-Windows-Kernel-Network may use different field names
        let destination_ip = try_get_ip(parser, "daddr")
            .or_else(|| try_get_ip(parser, "DestinationAddress"))
            .or_else(|| try_get_ip(parser, "RemoteAddress"))
            .or_else(|| try_get_ip(parser, "dstaddr"));

        let source_ip = try_get_ip(parser, "saddr")
            .or_else(|| try_get_ip(parser, "SourceAddress"))
            .or_else(|| try_get_ip(parser, "LocalAddress"))
            .or_else(|| try_get_ip(parser, "srcaddr"));

        // Ports are stored in network byte order (big-endian), need conversion
        let destination_port = try_get_port(parser, "dport")
            .or_else(|| try_get_port(parser, "DestinationPort"))
            .or_else(|| try_get_port(parser, "RemotePort"))
            .or_else(|| try_get_port(parser, "dstport"));

        let source_port = try_get_port(parser, "sport")
            .or_else(|| try_get_port(parser, "SourcePort"))
            .or_else(|| try_get_port(parser, "LocalPort"))
            .or_else(|| try_get_port(parser, "srcport"));

        debug!(
            "Network event (ID={}, OpCode={}): daddr={:?}, saddr={:?}, dport={:?}, sport={:?}",
            record.event_id(),
            record.opcode(),
            destination_ip,
            source_ip,
            destination_port,
            source_port
        );

        let mut fields = NetworkConnectionFields {
            destination_ip,
            source_ip,
            destination_port,
            source_port,
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
                .or_else(|| Some(record.process_id().to_string())),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
            destination_hostname: try_get_string(
                parser,
                mappings.get_etw_field("DestinationHostname")?,
            ),
        };

        // Enrich with cached process data if image is missing
        if fields.image.is_none() {
            let pid = record.process_id();
            if let Some(cached_image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&cached_image));
                debug!("Enriched network event with cached image for PID={}", pid);
            }
        }

        if fields.destination_hostname.is_none() {
            if let Some(ref destination_ip) = fields.destination_ip {
                if let Ok(ip) = destination_ip.parse::<IpAddr>() {
                    if let Some(hostname) = self.dns_cache.lookup(&ip) {
                        fields.destination_hostname = Some(hostname);
                    }
                }
            }
        }

        // Connection aggregation: suppress repeated connections to same destination
        if self.aggregation_enabled {
            if let (Some(ref image), Some(ref dest_ip_str), Some(ref dest_port_str)) = (
                &fields.image,
                &fields.destination_ip,
                &fields.destination_port,
            ) {
                if let (Ok(dest_ip), Ok(dest_port)) =
                    (dest_ip_str.parse::<IpAddr>(), dest_port_str.parse::<u16>())
                {
                    let pid = record.process_id();
                    // Determine protocol from ETW event ID (12=TCP, 14=UDP for Kernel-Network)
                    let protocol = match record.event_id() {
                        12 => Protocol::Tcp,
                        14 => Protocol::Udp,
                        _ => Protocol::Unknown,
                    };

                    let result = self
                        .connection_aggregator
                        .record(image, dest_ip, dest_port, protocol, pid);

                    if result == AggregationResult::Aggregated {
                        debug!(
                            "Suppressed aggregated connection: {} -> {}:{}",
                            image, dest_ip, dest_port
                        );
                        return None;
                    }
                }
            }
        }

        Some(EventFields::NetworkConnection(fields))
    }

    /// Normalize DNS query events
    fn normalize_dns(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::dns_query_mappings();

        let mut fields = DnsQueryFields {
            query_name: try_get_string(parser, mappings.get_etw_field("QueryName")?),
            query_results: try_get_string(parser, mappings.get_etw_field("QueryResults")?),
            query_status: try_get_uint(parser, mappings.get_etw_field("QueryStatus")?),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
        };

        // Enrich with cached process data if image is missing
        if fields.image.is_none() {
            let pid = record.process_id();
            if let Some(cached_image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&cached_image));
                debug!("Enriched DNS event with cached image for PID={}", pid);
            }
        }

        if let (Some(query_name), Some(query_results)) = (
            fields.query_name.as_deref(),
            fields.query_results.as_deref(),
        ) {
            let hostname = query_name.to_string();
            for ip in extract_ips_from_query_results(query_results) {
                self.dns_cache.update(ip, hostname.clone());
            }
        }

        Some(EventFields::DnsQuery(fields))
    }

    /// Normalize image load events
    fn normalize_image_load(&self, parser: &Parser, _record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::image_load_mappings();

        // Extract and normalize paths
        let raw_image_loaded = try_get_string(parser, mappings.get_etw_field("ImageLoaded")?);
        let image_loaded = raw_image_loaded.map(|p| convert_nt_to_dos(&p));

        // Parse PE metadata from the loaded image
        let (pe_original_filename, pe_product, pe_description) =
            if let Some(ref path) = image_loaded {
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
                .map(|p| convert_nt_to_dos(&p)),
            original_file_name: pe_original_filename,
            product: pe_product,
            description: pe_description,
            signed: try_get_string(parser, mappings.get_etw_field("Signed")?),
            signature: try_get_string(parser, mappings.get_etw_field("Signature")?),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
        };

        Some(EventFields::ImageLoad(fields))
    }

    /// Normalize PowerShell script events
    fn normalize_powershell(&self, parser: &Parser, _record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::powershell_script_mappings();

        let fields = PowerShellScriptFields {
            script_block_text: try_get_string(parser, mappings.get_etw_field("ScriptBlockText")?),
            script_block_id: try_get_string(parser, mappings.get_etw_field("ScriptBlockId")?),
            path: try_get_string(parser, mappings.get_etw_field("Path")?)
                .map(|p| convert_nt_to_dos(&p)),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
        };

        Some(EventFields::PowerShellScript(fields))
    }

    /// Normalize WMI events
    fn normalize_wmi(&self, parser: &Parser, _record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::wmi_event_mappings();

        let fields = WmiEventFields {
            operation: try_get_string(parser, mappings.get_etw_field("Operation")?),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
            query: try_get_string(parser, mappings.get_etw_field("Query")?),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
            event_namespace: try_get_string(parser, mappings.get_etw_field("EventNamespace")?),
            event_type: try_get_string(parser, mappings.get_etw_field("EventType")?),
            destination_hostname: try_get_string(
                parser,
                mappings.get_etw_field("DestinationHostname")?,
            ),
        };

        Some(EventFields::WmiEvent(fields))
    }

    /// Normalize service creation events
    /// Windows Event ID 7045 from Service Control Manager
    fn normalize_service(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::service_creation_mappings();

        let mut fields = ServiceCreationFields {
            service_name: try_get_string(parser, mappings.get_etw_field("ServiceName")?),
            service_file_name: try_get_string(parser, mappings.get_etw_field("ServiceFileName")?)
                .map(|p| convert_nt_to_dos(&p)),
            service_type: try_get_uint(parser, mappings.get_etw_field("ServiceType")?),
            start_type: try_get_uint(parser, mappings.get_etw_field("StartType")?),
            account_name: try_get_string(parser, mappings.get_etw_field("AccountName")?),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
        };

        // Enrich with cached process data if image is missing
        if fields.image.is_none() {
            let pid = record.process_id();
            if let Some(cached_image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&cached_image));
                debug!("Enriched service event with cached image for PID={}", pid);
            }
        }

        Some(EventFields::ServiceCreation(fields))
    }

    /// Normalize task scheduler events
    /// Windows Event ID 106 from Task Scheduler
    fn normalize_task(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::task_creation_mappings();

        let mut fields = TaskCreationFields {
            task_name: try_get_string(parser, mappings.get_etw_field("TaskName")?),
            task_content: try_get_string(parser, mappings.get_etw_field("TaskContent")?),
            user_name: try_get_string(parser, mappings.get_etw_field("UserName")?),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
        };

        // Enrich with cached process data if image is missing
        if fields.image.is_none() {
            let pid = record.process_id();
            if let Some(cached_image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&cached_image));
                debug!("Enriched task event with cached image for PID={}", pid);
            }
        }

        Some(EventFields::TaskCreation(fields))
    }

    /// Normalize named pipe events
    /// Detects lateral movement via SMB pipes (PsExec, Cobalt Strike beacons)
    fn normalize_pipe(&self, parser: &Parser, record: &EventRecord) -> Option<EventFields> {
        let mappings = field_maps::pipe_event_mappings();

        let mut fields = PipeEventFields {
            pipe_name: try_get_string(parser, mappings.get_etw_field("PipeName")?),
            process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
            image: try_get_string(parser, mappings.get_etw_field("Image")?)
                .map(|p| convert_nt_to_dos(&p)),
            user: try_get_string(parser, mappings.get_etw_field("User")?),
            event_type: try_get_string(parser, mappings.get_etw_field("EventType")?),
        };

        // Enrich with cached process data if image is missing
        if fields.image.is_none() {
            let pid = record.process_id();
            if let Some(cached_image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&cached_image));
                debug!("Enriched pipe event with cached image for PID={}", pid);
            }
        }

        Some(EventFields::PipeEvent(fields))
    }

    fn resolve_user_field(&self, user: &mut Option<String>) {
        let sid = match user.as_deref() {
            Some(value) if value.starts_with("S-1-") => value.to_string(),
            _ => return,
        };

        if let Some(resolved) = self.sid_cache.resolve(&sid) {
            *user = Some(resolved);
        }
    }

    fn build_process_context(
        &self,
        fields: &EventFields,
        record: &EventRecord,
    ) -> Option<ProcessContext> {
        if matches!(fields, EventFields::ProcessCreation(_)) {
            return None;
        }

        let pid_str = match fields {
            EventFields::FileEvent(f) => f.process_id.as_deref(),
            EventFields::RegistryEvent(f) => f.process_id.as_deref(),
            EventFields::NetworkConnection(f) => f.process_id.as_deref(),
            EventFields::DnsQuery(f) => f.process_id.as_deref(),
            EventFields::ImageLoad(f) => f.process_id.as_deref(),
            EventFields::PowerShellScript(f) => f.process_id.as_deref(),
            EventFields::WmiEvent(f) => f.process_id.as_deref(),
            EventFields::ServiceCreation(f) => f.process_id.as_deref(),
            EventFields::TaskCreation(f) => f.process_id.as_deref(),
            EventFields::PipeEvent(f) => f.process_id.as_deref(),
            EventFields::RemoteThread(f) => f.source_process_id.as_deref(),
            EventFields::ProcessCreation(_) | EventFields::Generic(_) => None,
        };

        let pid = pid_str
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| record.process_id());

        if pid == 0 {
            return None;
        }

        let meta = self.process_cache.get_metadata(pid)?;

        Some(ProcessContext {
            image: Some(meta.image_name),
            command_line: meta.command_line,
            process_id: Some(pid.to_string()),
            parent_process_id: meta.parent_pid.map(|value| value.to_string()),
            parent_image: meta.parent_image,
            parent_command_line: meta.parent_command_line,
            original_file_name: meta.original_filename,
            product: meta.product,
            description: meta.description,
            current_directory: meta.current_directory,
            integrity_level: meta.integrity_level,
            user: meta.user,
            logon_id: meta.logon_id,
            logon_guid: meta.logon_guid,
        })
    }
}

// ============================================================================
// ETW Property Extraction Utilities
// ============================================================================

/// Format event timestamp to ISO 8601 string
fn format_timestamp(record: &EventRecord) -> String {
    let timestamp = record.raw_timestamp();
    // Convert Windows FILETIME to Unix timestamp
    // FILETIME is 100-nanosecond intervals since 1601-01-01
    let unix_epoch_delta = 116444736000000000i64; // 100-ns intervals between 1601 and 1970
    let unix_100ns = if timestamp >= unix_epoch_delta {
        timestamp - unix_epoch_delta
    } else {
        0
    };
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;

    DateTime::<Utc>::from_timestamp(secs, nanos)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap())
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Try to extract a string property from the event
fn try_get_string(parser: &Parser, property_name: &str) -> Option<String> {
    match parser.try_parse::<String>(property_name) {
        Ok(value) => {
            // Handle null-terminated strings from kernel
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

/// Try multiple string properties and return the first non-empty value
fn try_get_string_any(parser: &Parser, property_names: &[&str]) -> Option<String> {
    for name in property_names {
        if let Some(value) = try_get_string(parser, name) {
            return Some(value);
        }
    }
    None
}

/// Try to extract a uint property from the event and convert to string
fn try_get_uint(parser: &Parser, property_name: &str) -> Option<String> {
    // Try different uint sizes
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

/// Try to extract a network port (handles big-endian to host byte order conversion)
/// Network ports in ETW are stored in network byte order (big-endian)
fn try_get_port(parser: &Parser, property_name: &str) -> Option<String> {
    // Try u16 first (most common for ports)
    if let Ok(value) = parser.try_parse::<u16>(property_name) {
        // Convert from network byte order (big-endian) to host byte order
        let port = u16::from_be(value);
        return Some(port.to_string());
    }
    // Try u32 in case it's stored as larger type
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        // Take lower 16 bits and swap
        let port = u16::from_be(value as u16);
        return Some(port.to_string());
    }
    None
}

/// Try to extract a uint property from the event as u64 (for timestamps)
fn try_get_uint_as_u64(parser: &Parser, property_name: &str) -> Option<u64> {
    // Try u64 first (most common for FILETIME)
    if let Ok(value) = parser.try_parse::<u64>(property_name) {
        return Some(value);
    }
    // Try i64 (signed variant)
    if let Ok(value) = parser.try_parse::<i64>(property_name) {
        return Some(value as u64);
    }
    // Try u32 and extend
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(value as u64);
    }
    None
}

/// Try to extract ProcessID from event payload (fallback)
fn try_get_uint_from_payload(record: &EventRecord) -> Option<String> {
    // Fallback: try to get ProcessID directly from event header
    Some(record.process_id().to_string())
}

/// Try to extract an IP address (handles both IPv4 and IPv6)
fn try_get_ip(parser: &Parser, property_name: &str) -> Option<String> {
    // Try using ferrisetw's IpAddr support
    if let Ok(ip) = parser.try_parse::<IpAddr>(property_name) {
        return Some(ip.to_string());
    }

    // Try as u32 (IPv4 as integer)
    if let Ok(addr) = parser.try_parse::<u32>(property_name) {
        let ipv4 = Ipv4Addr::from(addr.to_be_bytes());
        return Some(ipv4.to_string());
    }

    // Try as string (already formatted)
    try_get_string(parser, property_name)
}

/// Extract IPs from DNS query results (supports IPv4 and IPv6)
fn extract_ips_from_query_results(value: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let mut token = String::new();

    for ch in value.chars() {
        if ch.is_ascii_hexdigit() || ch == '.' || ch == ':' {
            token.push(ch);
        } else if !token.is_empty() {
            if let Ok(ip) = token.parse::<IpAddr>() {
                ips.push(ip);
            }
            token.clear();
        }
    }

    if !token.is_empty() {
        if let Ok(ip) = token.parse::<IpAddr>() {
            ips.push(ip);
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalizer_creation() {
        use crate::state::ConnectionAggregator;
        let process_cache = Arc::new(ProcessCache::new());
        let sid_cache = Arc::new(SidCache::new());
        let dns_cache = Arc::new(DnsCache::new());
        let connection_aggregator = Arc::new(ConnectionAggregator::new());
        let _normalizer = Normalizer::new(
            process_cache,
            sid_cache,
            dns_cache,
            connection_aggregator,
            true,
        );
    }

    #[test]
    fn test_timestamp_formatting() {
        // Test with a known FILETIME value
        // This is a placeholder - actual testing would need a real EventRecord
        // In practice, you'd mock or create test events
    }

    #[test]
    fn test_string_null_termination() {
        // Test that null-terminated strings are properly handled
        let test_str = "test\0\0\0";
        let trimmed = test_str.trim_end_matches('\0');
        assert_eq!(trimmed, "test");
    }
}
