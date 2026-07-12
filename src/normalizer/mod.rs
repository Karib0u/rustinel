//! Shared event normalizer.
//!
//! Converts decoded [`SensorEvent`](crate::sensor::SensorEvent) values into the
//! existing normalized event model while preserving shared enrichment and cache
//! behavior.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};

use crate::models::*;
use crate::sensor::{SensorAction, SensorEvent, SensorPayload};
use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, Protocol, SidCache};
use crate::utils::{convert_nt_to_dos, query_process_command_line};

/// Event normalizer that converts shared sensor events to normalized events.
pub struct Normalizer {
    process_cache: Arc<ProcessCache>,
    sid_cache: Arc<SidCache>,
    dns_cache: Arc<DnsCache>,
    connection_aggregator: Arc<ConnectionAggregator>,
    aggregation_enabled: bool,
}

impl Normalizer {
    /// Creates a new normalizer instance.
    pub fn new(
        process_cache: Arc<ProcessCache>,
        sid_cache: Arc<SidCache>,
        dns_cache: Arc<DnsCache>,
        connection_aggregator: Arc<ConnectionAggregator>,
        aggregation_enabled: bool,
    ) -> Self {
        Self {
            process_cache,
            sid_cache,
            dns_cache,
            connection_aggregator,
            aggregation_enabled,
        }
    }

    /// Normalize a shared sensor event to Sigma-compatible format.
    pub fn normalize(&self, event: &SensorEvent) -> Option<NormalizedEvent> {
        let fields = match &event.payload {
            SensorPayload::Process(fields) => self.normalize_process(event, fields),
            SensorPayload::Network(fields) => self.normalize_network(event, fields.clone()),
            SensorPayload::File(fields) => self.normalize_file(event, fields.clone()),
            SensorPayload::Dns(fields) => self.normalize_dns(event, fields.clone()),
            SensorPayload::Registry(fields) => self.normalize_registry(event, fields.clone()),
            SensorPayload::ImageLoad(fields) => self.normalize_image_load(fields.clone()),
            SensorPayload::Scripting(fields) => self.normalize_powershell(fields.clone()),
            SensorPayload::Wmi(fields) => self.normalize_wmi(fields.clone()),
            SensorPayload::Service(fields) => self.normalize_service(event, fields.clone()),
            SensorPayload::Task(fields) => self.normalize_task(event, fields.clone()),
        }?;

        Some(NormalizedEvent {
            timestamp: format_timestamp(event.timestamp),
            platform: event.platform,
            provider: event.provider.to_string(),
            category: event.category(),
            event_id: event.normalization.event_id,
            event_id_string: event.normalization.event_id.to_string(),
            opcode: event.normalization.action_code,
            fields,
            process_context: None,
        })
    }

    fn normalize_process(
        &self,
        event: &SensorEvent,
        fields: &ProcessCreationFields,
    ) -> Option<EventFields> {
        let pid = event_pid(event, fields.process_id.as_deref());

        if event.action == SensorAction::Stop {
            let creation_time = event
                .process_start_key
                .map(|key| key.start_time)
                .or_else(|| {
                    if pid == 0 {
                        None
                    } else {
                        self.process_cache.get_latest_creation_time(pid)
                    }
                });

            if let Some(creation_time) = creation_time {
                self.process_cache.remove(pid, creation_time);
            }
            return None;
        }

        let mut fields = fields.clone();
        self.resolve_user_field(&mut fields.user);
        if fields.process_start_time.is_none() {
            fields.process_start_time = event.process_start_key.map(|key| key.start_time);
        }

        if event.action == SensorAction::Start && fields.command_line.is_none() && pid != 0 {
            if let Some(command_line) = query_process_command_line(pid) {
                fields.command_line = Some(command_line);
            }
        }

        if event.action == SensorAction::Start {
            if let Some(image) = fields.image.clone() {
                let parent_pid = parse_optional_u32(fields.parent_process_id.as_deref());
                let (parent_image, parent_command_line) = if let Some(parent_pid) = parent_pid {
                    if let Some(parent_meta) = self.process_cache.get_metadata(parent_pid) {
                        (Some(parent_meta.image_name), parent_meta.command_line)
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                if fields.parent_image.is_none() {
                    fields.parent_image = parent_image;
                }
                if fields.parent_command_line.is_none() {
                    fields.parent_command_line = parent_command_line;
                }

                if pid != 0 {
                    let start_time = event
                        .process_start_key
                        .map(|key| key.start_time)
                        .unwrap_or_else(|| process_cache_time_fallback(event.timestamp));

                    self.process_cache.add(
                        pid,
                        start_time,
                        image,
                        fields.command_line.clone(),
                        fields.user.clone(),
                        parent_pid,
                        fields.parent_image.clone(),
                        fields.parent_command_line.clone(),
                        fields.original_file_name.clone(),
                        fields.product.clone(),
                        fields.description.clone(),
                        fields.current_directory.clone(),
                        fields.integrity_level.clone(),
                        fields.logon_id.clone(),
                        fields.logon_guid.clone(),
                    );
                }
            }
        }

        Some(EventFields::ProcessCreation(fields))
    }

    fn normalize_file(
        &self,
        event: &SensorEvent,
        mut fields: FileEventFields,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);

        let pid = event_pid(event, fields.process_id.as_deref());
        if pid != 0 {
            if let Some(image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&image));
            }
        }

        Some(EventFields::FileEvent(fields))
    }

    fn normalize_registry(
        &self,
        event: &SensorEvent,
        mut fields: RegistryEventFields,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);

        if fields.image.is_none() {
            let pid = event_pid(event, fields.process_id.as_deref());
            if let Some(image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&image));
            }
        }

        Some(EventFields::RegistryEvent(fields))
    }

    fn normalize_network(
        &self,
        event: &SensorEvent,
        mut fields: NetworkConnectionFields,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);

        if fields.image.is_none() {
            let pid = event_pid(event, fields.process_id.as_deref());
            if let Some(image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&image));
            }
        }

        if fields.destination_hostname.is_none() {
            if let Some(destination_ip) = fields.destination_ip.as_deref() {
                if let Ok(ip) = destination_ip.parse::<IpAddr>() {
                    if let Some(hostname) = self.dns_cache.lookup(&ip) {
                        fields.destination_hostname = Some(hostname);
                    }
                }
            }
        }

        if self.aggregation_enabled {
            if let (Some(image), Some(dest_ip), Some(dest_port)) = (
                fields.image.as_deref(),
                fields.destination_ip.as_deref(),
                fields.destination_port.as_deref(),
            ) {
                if let (Ok(dest_ip), Ok(dest_port)) =
                    (dest_ip.parse::<IpAddr>(), dest_port.parse::<u16>())
                {
                    let protocol = match fields.protocol.as_deref() {
                        Some("tcp") => Protocol::Tcp,
                        Some("udp") => Protocol::Udp,
                        _ => Protocol::Unknown,
                    };
                    let pid = event_pid(event, fields.process_id.as_deref());

                    // Aggregation is observational state for connection counts
                    // and interval statistics. Every raw event remains visible
                    // to Sigma and IOC detection.
                    self.connection_aggregator
                        .record(image, dest_ip, dest_port, protocol, pid);
                }
            }
        }

        Some(EventFields::NetworkConnection(fields))
    }

    fn normalize_dns(
        &self,
        event: &SensorEvent,
        mut fields: DnsQueryFields,
    ) -> Option<EventFields> {
        if fields.image.is_none() {
            let pid = event_pid(event, fields.process_id.as_deref());
            if let Some(image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&image));
            }
        }

        if let (Some(query_name), Some(query_results)) = (
            fields.query_name.as_deref(),
            fields.query_results.as_deref(),
        ) {
            for ip in extract_ips_from_query_results(query_results) {
                self.dns_cache.update(ip, query_name.to_string());
            }
        }

        Some(EventFields::DnsQuery(fields))
    }

    fn normalize_image_load(&self, mut fields: ImageLoadFields) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        Some(EventFields::ImageLoad(fields))
    }

    fn normalize_powershell(&self, mut fields: PowerShellScriptFields) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        Some(EventFields::PowerShellScript(fields))
    }

    fn normalize_wmi(&self, mut fields: WmiEventFields) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        Some(EventFields::WmiEvent(fields))
    }

    fn normalize_service(
        &self,
        event: &SensorEvent,
        mut fields: ServiceCreationFields,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);

        if fields.image.is_none() {
            let pid = event_pid(event, fields.process_id.as_deref());
            if let Some(image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&image));
            }
        }

        Some(EventFields::ServiceCreation(fields))
    }

    fn normalize_task(
        &self,
        event: &SensorEvent,
        mut fields: TaskCreationFields,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);

        if fields.image.is_none() {
            let pid = event_pid(event, fields.process_id.as_deref());
            if let Some(image) = self.process_cache.get_image(pid) {
                fields.image = Some(convert_nt_to_dos(&image));
            }
        }

        Some(EventFields::TaskCreation(fields))
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

    /// Build and attach process context lazily for alert enrichment.
    pub fn enrich_process_context(&self, event: &mut NormalizedEvent, fallback_pid: u32) {
        if event.process_context.is_some() {
            return;
        }
        event.process_context = self.build_process_context(&event.fields, fallback_pid);
    }

    fn build_process_context(
        &self,
        fields: &EventFields,
        fallback_pid: u32,
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
            EventFields::RemoteThread(f) => f.source_process_id.as_deref(),
            EventFields::ProcessCreation(_) | EventFields::Generic(_) => None,
        };

        let pid = pid_str
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(fallback_pid);

        if pid == 0 {
            return None;
        }

        let meta = self.process_cache.get_metadata(pid)?;

        Some(ProcessContext {
            image: Some(meta.image_name),
            command_line: meta.command_line,
            process_id: Some(pid.to_string()),
            process_start_time: Some(meta.creation_time),
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

fn event_pid(event: &SensorEvent, explicit_pid: Option<&str>) -> u32 {
    explicit_pid
        .and_then(|value| value.parse::<u32>().ok())
        .or(event.pid)
        .unwrap_or(0)
}

fn parse_optional_u32(value: Option<&str>) -> Option<u32> {
    value.and_then(|value| value.parse::<u32>().ok())
}

fn format_timestamp(timestamp: SystemTime) -> String {
    DateTime::<Utc>::from(timestamp).to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn process_cache_time_fallback(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::sensor::{Platform, ProcessStartKey, SensorNormalization};

    fn build_normalizer(aggregation_enabled: bool) -> Normalizer {
        Normalizer::new(
            Arc::new(ProcessCache::new()),
            Arc::new(SidCache::new()),
            Arc::new(DnsCache::new()),
            Arc::new(ConnectionAggregator::new()),
            aggregation_enabled,
        )
    }

    fn process_start_event(platform: Platform, provider: &'static str, pid: u32) -> SensorEvent {
        SensorEvent {
            platform,
            provider,
            action: SensorAction::Start,
            normalization: SensorNormalization {
                event_id: 1,
                action_code: 1,
            },
            pid: Some(pid),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            process_start_key: Some(ProcessStartKey {
                pid,
                start_time: 123_456,
            }),
            payload: SensorPayload::Process(ProcessCreationFields {
                image: Some("/usr/bin/curl".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: Some("/usr/bin/curl https://example.test".to_string()),
                process_id: Some(pid.to_string()),
                process_start_time: None,
                parent_process_id: Some("7".to_string()),
                parent_image: None,
                parent_command_line: None,
                current_directory: Some("/tmp".to_string()),
                integrity_level: None,
                user: Some("alice".to_string()),
                logon_id: None,
                logon_guid: None,
            }),
        }
    }

    fn process_stop_event(
        platform: Platform,
        provider: &'static str,
        pid: u32,
        with_start_key: bool,
    ) -> SensorEvent {
        SensorEvent {
            platform,
            provider,
            action: SensorAction::Stop,
            normalization: SensorNormalization {
                event_id: 5,
                action_code: 2,
            },
            pid: Some(pid),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            process_start_key: with_start_key.then_some(ProcessStartKey {
                pid,
                start_time: 123_456,
            }),
            payload: SensorPayload::Process(ProcessCreationFields {
                image: None,
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some(pid.to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some("alice".to_string()),
                logon_id: None,
                logon_guid: None,
            }),
        }
    }

    fn network_event(platform: Platform, provider: &'static str, pid: u32) -> SensorEvent {
        SensorEvent {
            platform,
            provider,
            action: SensorAction::Connect,
            normalization: SensorNormalization {
                event_id: 3,
                action_code: 12,
            },
            pid: Some(pid),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(30),
            process_start_key: None,
            payload: SensorPayload::Network(NetworkConnectionFields {
                destination_ip: Some("198.51.100.10".to_string()),
                source_ip: Some("10.0.0.5".to_string()),
                destination_port: Some("443".to_string()),
                source_port: Some("51324".to_string()),
                process_id: Some(pid.to_string()),
                image: None,
                user: Some("alice".to_string()),
                destination_hostname: None,
                protocol: None,
            }),
        }
    }

    fn file_event(platform: Platform, provider: &'static str, pid: u32) -> SensorEvent {
        SensorEvent {
            platform,
            provider,
            action: SensorAction::Create,
            normalization: SensorNormalization {
                event_id: 11,
                action_code: 64,
            },
            pid: Some(pid),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(40),
            process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                source_filename: None,
                target_filename: Some("/tmp/sample.txt".to_string()),
                process_id: Some(pid.to_string()),
                image: None,
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: Some("alice".to_string()),
            }),
        }
    }

    fn assert_shared_fields_equal(left: &NormalizedEvent, right: &NormalizedEvent, keys: &[&str]) {
        assert_eq!(left.category, right.category);
        for key in keys {
            assert_eq!(
                left.get_field(key),
                right.get_field(key),
                "normalized field mismatch for key {key}",
            );
        }
    }

    #[test]
    fn test_normalizer_creation() {
        let _normalizer = build_normalizer(true);
    }

    #[test]
    fn process_stop_events_only_maintain_cache() {
        let normalizer = build_normalizer(true);

        normalizer.process_cache.add(
            42,
            99,
            "C:\\test.exe".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let event = SensorEvent {
            platform: Platform::Windows,
            provider: "etw",
            action: SensorAction::Stop,
            normalization: SensorNormalization {
                event_id: 5,
                action_code: 2,
            },
            pid: Some(42),
            timestamp: SystemTime::UNIX_EPOCH,
            process_start_key: Some(ProcessStartKey {
                pid: 42,
                start_time: 99,
            }),
            payload: SensorPayload::Process(ProcessCreationFields {
                image: None,
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some("42".to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
        };

        assert!(normalizer.normalize(&event).is_none());
        assert_eq!(normalizer.process_cache.get_latest_creation_time(42), None);
    }

    #[test]
    fn linux_process_stop_without_process_start_key_uses_pid_fallback() {
        let normalizer = build_normalizer(false);

        let start = process_start_event(Platform::Linux, "ebpf", 42);
        let stop = process_stop_event(Platform::Linux, "ebpf", 42, false);

        let start_normalized = normalizer
            .normalize(&start)
            .expect("linux process start should normalize");
        assert_eq!(start_normalized.get_field("Image"), Some("/usr/bin/curl"));

        assert!(normalizer.normalize(&stop).is_none());
        assert_eq!(normalizer.process_cache.get_latest_creation_time(42), None);
    }

    #[test]
    fn network_aggregation_keeps_repeated_connections_for_detection() {
        let normalizer = build_normalizer(true);
        normalizer.process_cache.add(
            7,
            1,
            "C:\\curl.exe".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let build_event = || SensorEvent {
            platform: Platform::Windows,
            provider: "etw",
            action: SensorAction::Connect,
            normalization: SensorNormalization {
                event_id: 3,
                action_code: 12,
            },
            pid: Some(7),
            timestamp: SystemTime::UNIX_EPOCH,
            process_start_key: None,
            payload: SensorPayload::Network(NetworkConnectionFields {
                destination_ip: Some("198.51.100.10".to_string()),
                source_ip: Some("10.0.0.5".to_string()),
                destination_port: Some("443".to_string()),
                source_port: Some("51324".to_string()),
                process_id: Some("7".to_string()),
                image: Some("C:\\curl.exe".to_string()),
                user: None,
                destination_hostname: None,
                protocol: Some("tcp".to_string()),
            }),
        };

        assert!(normalizer.normalize(&build_event()).is_some());
        assert!(normalizer.normalize(&build_event()).is_some());

        let mut restarted = build_event();
        restarted.pid = Some(8);
        if let SensorPayload::Network(fields) = &mut restarted.payload {
            fields.process_id = Some("8".to_string());
            fields.user = Some("bob".to_string());
            fields.destination_hostname = Some("new.example.test".to_string());
        }

        let normalized = normalizer
            .normalize(&restarted)
            .expect("connection from a restarted process should remain visible");
        assert_eq!(normalized.get_field("ProcessId"), Some("8"));
        assert_eq!(normalized.get_field("User"), Some("bob"));
        assert_eq!(
            normalized.get_field("DestinationHostname"),
            Some("new.example.test")
        );

        let meta = normalizer
            .connection_aggregator
            .get_meta(
                "C:\\curl.exe",
                "198.51.100.10".parse().unwrap(),
                443,
                Protocol::Tcp,
            )
            .expect("connection aggregate should be tracked");
        assert_eq!(meta.connection_count, 3);
        assert_eq!(meta.unique_pids.len(), 2);
    }

    #[test]
    fn normalizer_preserves_sensor_supplied_compat_metadata() {
        let normalizer = build_normalizer(false);
        let event = SensorEvent {
            platform: Platform::Linux,
            provider: "ebpf",
            action: SensorAction::Create,
            normalization: SensorNormalization {
                event_id: 11,
                action_code: 64,
            },
            pid: Some(9),
            timestamp: SystemTime::UNIX_EPOCH,
            process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                source_filename: None,
                target_filename: Some("/tmp/test".to_string()),
                process_id: Some("9".to_string()),
                image: Some("/usr/bin/touch".to_string()),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: None,
            }),
        };

        let normalized = normalizer
            .normalize(&event)
            .expect("file event should normalize");
        assert_eq!(normalized.event_id, 11);
        assert_eq!(normalized.event_id_string, "11");
        assert_eq!(normalized.opcode, 64);
    }

    #[test]
    fn file_events_backfill_full_process_image_from_cache() {
        let normalizer = build_normalizer(false);
        normalizer.process_cache.add(
            9,
            1,
            "/usr/bin/touch".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let event = SensorEvent {
            platform: Platform::Linux,
            provider: "ebpf",
            action: SensorAction::Create,
            normalization: SensorNormalization {
                event_id: 11,
                action_code: 64,
            },
            pid: Some(9),
            timestamp: SystemTime::UNIX_EPOCH,
            process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                source_filename: None,
                target_filename: Some("/tmp/test".to_string()),
                process_id: Some("9".to_string()),
                image: Some("touch".to_string()),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: None,
            }),
        };

        let normalized = normalizer
            .normalize(&event)
            .expect("file event should normalize");

        match normalized.fields {
            EventFields::FileEvent(fields) => {
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/touch"));
            }
            other => panic!("unexpected fields: {:?}", other),
        }
    }

    #[test]
    fn linux_process_start_primes_cache_for_follow_on_network_enrichment() {
        let normalizer = build_normalizer(false);

        let start = process_start_event(Platform::Linux, "ebpf", 4242);
        let network = network_event(Platform::Linux, "ebpf", 4242);

        normalizer
            .normalize(&start)
            .expect("linux process start should normalize");

        let normalized = normalizer
            .normalize(&network)
            .expect("linux network event should normalize");

        match normalized.fields {
            EventFields::NetworkConnection(fields) => {
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/curl"));
                assert_eq!(fields.process_id.as_deref(), Some("4242"));
                assert_eq!(fields.destination_ip.as_deref(), Some("198.51.100.10"));
            }
            other => panic!("unexpected fields: {:?}", other),
        }
    }

    #[test]
    fn equivalent_windows_and_linux_process_events_normalize_same_shared_fields() {
        let windows = build_normalizer(false)
            .normalize(&process_start_event(Platform::Windows, "etw", 9001))
            .expect("windows process start should normalize");
        let linux = build_normalizer(false)
            .normalize(&process_start_event(Platform::Linux, "ebpf", 9001))
            .expect("linux process start should normalize");

        assert_shared_fields_equal(
            &windows,
            &linux,
            &[
                "Image",
                "CommandLine",
                "ProcessId",
                "ParentProcessId",
                "CurrentDirectory",
                "User",
            ],
        );
    }

    #[test]
    fn equivalent_windows_and_linux_network_events_normalize_same_shared_fields() {
        let windows_normalizer = build_normalizer(false);
        let linux_normalizer = build_normalizer(false);

        windows_normalizer
            .normalize(&process_start_event(Platform::Windows, "etw", 9002))
            .expect("windows process start should normalize");
        linux_normalizer
            .normalize(&process_start_event(Platform::Linux, "ebpf", 9002))
            .expect("linux process start should normalize");

        let windows = windows_normalizer
            .normalize(&network_event(Platform::Windows, "etw", 9002))
            .expect("windows network event should normalize");
        let linux = linux_normalizer
            .normalize(&network_event(Platform::Linux, "ebpf", 9002))
            .expect("linux network event should normalize");

        assert_shared_fields_equal(
            &windows,
            &linux,
            &[
                "DestinationIp",
                "SourceIp",
                "DestinationPort",
                "SourcePort",
                "ProcessId",
                "Image",
                "User",
                "DestinationHostname",
                "Protocol",
            ],
        );
    }

    #[test]
    fn equivalent_windows_and_linux_file_events_normalize_same_shared_fields() {
        let windows_normalizer = build_normalizer(false);
        let linux_normalizer = build_normalizer(false);

        windows_normalizer
            .normalize(&process_start_event(Platform::Windows, "etw", 9003))
            .expect("windows process start should normalize");
        linux_normalizer
            .normalize(&process_start_event(Platform::Linux, "ebpf", 9003))
            .expect("linux process start should normalize");

        let windows = windows_normalizer
            .normalize(&file_event(Platform::Windows, "etw", 9003))
            .expect("windows file event should normalize");
        let linux = linux_normalizer
            .normalize(&file_event(Platform::Linux, "ebpf", 9003))
            .expect("linux file event should normalize");

        assert_shared_fields_equal(
            &windows,
            &linux,
            &["TargetFilename", "ProcessId", "Image", "User"],
        );
    }
}
