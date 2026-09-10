//! Shared event normalizer.
//!
//! Converts decoded [`SensorEvent`](crate::sensor::SensorEvent) values into the
//! existing normalized event model while preserving shared enrichment and cache
//! behavior.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};

use crate::models::*;
use crate::sensor::{Platform, ProcessStartKey, SensorAction, SensorEvent, SensorPayload};
use crate::state::{DnsCache, ProcessCache, ProcessMetadata, SidCache};
use crate::utils::{convert_nt_to_dos, query_process_command_line};

/// Event normalizer that converts shared sensor events to normalized events.
pub struct Normalizer {
    process_cache: Arc<ProcessCache>,
    sid_cache: Arc<SidCache>,
    dns_cache: Arc<DnsCache>,
    ingest_seq: AtomicU64,
}

impl Normalizer {
    /// Creates a new normalizer instance.
    pub fn new(
        process_cache: Arc<ProcessCache>,
        sid_cache: Arc<SidCache>,
        dns_cache: Arc<DnsCache>,
    ) -> Self {
        Self {
            process_cache,
            sid_cache,
            dns_cache,
            ingest_seq: AtomicU64::new(0),
        }
    }

    /// Normalize a shared sensor event to Sigma-compatible format.
    pub fn normalize(&self, event: &SensorEvent) -> Option<NormalizedEvent> {
        let mut provenance = Provenance::default();
        let fields = match &event.payload {
            SensorPayload::Process(fields) => {
                self.normalize_process(event, fields, &mut provenance)
            }
            SensorPayload::Network(fields) => {
                self.normalize_network(event, fields.clone(), &mut provenance)
            }
            SensorPayload::File(fields) => {
                self.normalize_file(event, fields.clone(), &mut provenance)
            }
            SensorPayload::Dns(fields) => {
                self.normalize_dns(event, fields.clone(), &mut provenance)
            }
            SensorPayload::Registry(fields) => {
                self.normalize_registry(event, fields.clone(), &mut provenance)
            }
            SensorPayload::ImageLoad(fields) => self.normalize_image_load(fields.clone()),
            SensorPayload::Scripting(fields) => self.normalize_powershell(fields.clone()),
            SensorPayload::PowerShellModule(fields) => {
                self.normalize_powershell_module(fields.clone())
            }
            SensorPayload::Wmi(fields) => self.normalize_wmi(fields.clone()),
            SensorPayload::Service(fields) => {
                self.normalize_service(event, fields.clone(), &mut provenance)
            }
            SensorPayload::Task(fields) => {
                self.normalize_task(event, fields.clone(), &mut provenance)
            }
            SensorPayload::Security(fields) => Some(EventFields::SecurityAudit(fields.clone())),
        }?;

        let normalized = NormalizedEvent {
            timestamp: format_timestamp(event.timestamp),
            source_seq: event.source_seq,
            ingest_seq: self.ingest_seq.fetch_add(1, Ordering::Relaxed) + 1,
            platform: event.platform,
            provider: event.provider.to_string(),
            category: event.category(),
            event_id: event.normalization.event_id,
            event_id_string: event.normalization.event_id.to_string(),
            opcode: event.normalization.action_code,
            fields,
            provenance,
            process_context: None,
        };

        // Decoder contracts are checked at the shared boundary, so every
        // decoder test that normalizes its output fails if an `Always` field
        // disappears. Keep release telemetry flowing; debug and test builds
        // turn contract drift into an immediate, actionable failure.
        let missing_always = crate::field_availability::missing_always_fields(&normalized);
        debug_assert!(
            missing_always.is_empty(),
            "decoder omitted Always field(s) for {}: {:?}",
            crate::field_availability::category_name(normalized.category),
            missing_always
        );

        Some(normalized)
    }

    fn normalize_process(
        &self,
        event: &SensorEvent,
        fields: &ProcessCreationFields,
        provenance: &mut Provenance,
    ) -> Option<EventFields> {
        let pid = event_pid(event, fields.process_id.as_deref());

        if event.action == SensorAction::Stop {
            if let Some(key) = event.process_start_key {
                self.process_cache.remove(key.pid, key.start_time);
            }
            return None;
        }

        let mut fields = fields.clone();
        let measured_user = fields.user.clone();
        self.resolve_user_field(&mut fields.user);
        if fields.user != measured_user {
            provenance.mark_derived("User");
        }
        #[cfg(target_os = "linux")]
        if event.platform == Platform::Linux {
            if let Some(uid) = fields
                .linux_identity
                .effective_user_id
                .as_deref()
                .and_then(|id| id.parse::<u32>().ok())
            {
                // Account lookup belongs downstream, outside the ring drain.
                if let Some(name) = crate::utils::lookup_username_by_uid(uid) {
                    fields.user = Some(name);
                    provenance.mark_derived("User");
                }
            }
        }
        if fields.process_start_time.is_none() {
            fields.process_start_time = event.process_start_key.map(|key| key.start_time);
            if fields.process_start_time.is_some()
                && event.platform == Platform::Linux
                && event.provider == "ebpf"
            {
                provenance.mark_derived("ProcessStartTime");
            }
        }
        if fields
            .windows
            .as_ref()
            .is_some_and(|metadata| metadata.conflicting_live_command_line.is_some())
        {
            provenance.mark_derived("WindowsProcessMetadata.conflicting_live_command_line");
        }
        if fields
            .windows
            .as_ref()
            .is_some_and(|metadata| metadata.command_line_source.as_deref() == Some("live_query"))
            && fields.command_line.is_some()
        {
            provenance.mark_derived("CommandLine");
        }
        if fields.parent_process_id_derived && fields.parent_process_id.is_some() {
            provenance.mark_derived("ParentProcessId");
        }

        if event.action == SensorAction::Start
            && fields.command_line.is_none()
            && pid != 0
            && !(event.platform == Platform::Windows && event.provider == "etw")
        {
            if let Some(command_line) = query_process_command_line(pid) {
                fields.command_line = Some(command_line);
                if event.platform == Platform::Windows {
                    fields
                        .windows
                        .get_or_insert_with(Default::default)
                        .command_line_source = Some("live_query".into());
                }
                provenance.mark_derived("CommandLine");
            }
        }

        if event.platform == Platform::Windows && event.action == SensorAction::Start {
            crate::telemetry::WINDOWS_PROCESS_COMMAND_LINE.record(fields.command_line.is_some());
        }

        if event.action == SensorAction::Start {
            if let Some(image) = fields.image.clone() {
                let parent_pid = parse_optional_u32(fields.parent_process_id.as_deref());

                if let Some(parent) = event.parent_process_start_key.and_then(|key| {
                    self.process_cache
                        .get_metadata_by_key(key.pid, key.start_time)
                }) {
                    if fields.parent_image.is_none() {
                        fields.parent_image = Some(convert_nt_to_dos(&parent.image_name));
                        provenance.mark_derived("ParentImage");
                    }
                    if fields.parent_command_line.is_none() {
                        if let Some(command_line) = parent.command_line {
                            fields.parent_command_line = Some(command_line);
                            provenance.mark_derived("ParentCommandLine");
                        }
                    }
                }

                if let Some(key) = event.process_start_key.filter(|key| key.pid == pid) {
                    self.process_cache.add(
                        pid,
                        key.start_time,
                        image,
                        fields.command_line.clone(),
                        fields.user.clone(),
                        parent_pid,
                        fields.parent_image.clone(),
                        fields.parent_command_line.clone(),
                        fields.original_file_name.clone(),
                        fields.product.clone(),
                        fields.description.clone(),
                        fields.company.clone(),
                        fields.file_version.clone(),
                        fields.current_directory.clone(),
                        fields.integrity_level.clone(),
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
        provenance: &mut Provenance,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        self.enrich_image(event, &mut fields.image, provenance);

        Some(EventFields::FileEvent(fields))
    }

    fn normalize_registry(
        &self,
        event: &SensorEvent,
        mut fields: RegistryEventFields,
        provenance: &mut Provenance,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        self.enrich_image(event, &mut fields.image, provenance);

        Some(EventFields::RegistryEvent(fields))
    }

    fn normalize_network(
        &self,
        event: &SensorEvent,
        mut fields: NetworkConnectionFields,
        provenance: &mut Provenance,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        self.enrich_image(event, &mut fields.image, provenance);

        if fields.destination_hostname.is_none() {
            if let Some(destination_ip) = fields.destination_ip.as_deref() {
                if let Ok(ip) = destination_ip.parse::<IpAddr>() {
                    if let Some(hostname) = self.dns_cache.lookup(&ip) {
                        fields.destination_hostname = Some(hostname);
                    }
                }
            }
        }

        Some(EventFields::NetworkConnection(fields))
    }

    fn normalize_dns(
        &self,
        event: &SensorEvent,
        mut fields: DnsQueryFields,
        provenance: &mut Provenance,
    ) -> Option<EventFields> {
        self.enrich_image(event, &mut fields.image, provenance);

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

    fn normalize_powershell_module(
        &self,
        mut fields: PowerShellModuleFields,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        Some(EventFields::PowerShellModule(fields))
    }

    fn normalize_wmi(&self, mut fields: WmiEventFields) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        Some(EventFields::WmiEvent(fields))
    }

    fn normalize_service(
        &self,
        event: &SensorEvent,
        mut fields: ServiceCreationFields,
        provenance: &mut Provenance,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        self.enrich_image(event, &mut fields.image, provenance);

        Some(EventFields::ServiceCreation(fields))
    }

    fn normalize_task(
        &self,
        event: &SensorEvent,
        mut fields: TaskCreationFields,
        provenance: &mut Provenance,
    ) -> Option<EventFields> {
        self.resolve_user_field(&mut fields.user);
        self.enrich_image(event, &mut fields.image, provenance);

        Some(EventFields::TaskCreation(fields))
    }

    fn enrich_image(
        &self,
        event: &SensorEvent,
        image: &mut Option<String>,
        provenance: &mut Provenance,
    ) {
        if image.is_some() {
            return;
        }
        let Some(metadata) = self.metadata_for_event(event) else {
            return;
        };

        *image = Some(convert_nt_to_dos(&metadata.image_name));
        provenance.mark_derived("Image");
    }

    fn metadata_for_event(&self, event: &SensorEvent) -> Option<ProcessMetadata> {
        let key = event.process_start_key?;
        self.process_cache
            .get_metadata_by_key(key.pid, key.start_time)
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
    pub fn enrich_process_context(
        &self,
        event: &mut NormalizedEvent,
        process_start_key: Option<ProcessStartKey>,
    ) {
        if event.process_context.is_some() {
            return;
        }
        let Some(key) = process_start_key else {
            return;
        };
        let Some(context) = self.build_process_context(&event.fields, key) else {
            return;
        };
        mark_process_context_provenance(event, &context);
        event.process_context = Some(context);
    }

    fn build_process_context(
        &self,
        fields: &EventFields,
        process_start_key: ProcessStartKey,
    ) -> Option<ProcessContext> {
        if matches!(fields, EventFields::ProcessCreation(_)) {
            return None;
        }

        let meta = self
            .process_cache
            .get_metadata_by_key(process_start_key.pid, process_start_key.start_time)?;

        Some(ProcessContext {
            image: Some(meta.image_name),
            command_line: meta.command_line,
            process_id: Some(process_start_key.pid.to_string()),
            process_start_time: Some(meta.creation_time),
            parent_process_id: meta.parent_pid.map(|value| value.to_string()),
            parent_image: meta.parent_image,
            parent_command_line: meta.parent_command_line,
            original_file_name: meta.original_filename,
            product: meta.product,
            description: meta.description,
            company: meta.company,
            file_version: meta.file_version,
            current_directory: meta.current_directory,
            integrity_level: meta.integrity_level,
            user: meta.user,
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
    DateTime::<Utc>::from(timestamp).to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn mark_process_context_provenance(event: &mut NormalizedEvent, context: &ProcessContext) {
    let derived_fields = [
        ("Image", context.image.is_some()),
        ("CommandLine", context.command_line.is_some()),
        ("ProcessId", context.process_id.is_some()),
        ("ParentProcessId", context.parent_process_id.is_some()),
        ("ParentImage", context.parent_image.is_some()),
        ("ParentCommandLine", context.parent_command_line.is_some()),
        ("OriginalFileName", context.original_file_name.is_some()),
        ("Product", context.product.is_some()),
        ("Description", context.description.is_some()),
        ("Company", context.company.is_some()),
        ("FileVersion", context.file_version.is_some()),
        ("CurrentDirectory", context.current_directory.is_some()),
        ("IntegrityLevel", context.integrity_level.is_some()),
        ("User", context.user.is_some()),
    ];

    for (field, present) in derived_fields {
        if present && event.get_field(field).is_none() {
            event.provenance.mark_derived(field);
        }
    }
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

    fn build_normalizer() -> Normalizer {
        Normalizer::new(
            Arc::new(ProcessCache::new()),
            Arc::new(SidCache::new()),
            Arc::new(DnsCache::new()),
        )
    }

    #[test]
    fn windows_live_command_line_provenance_survives_recording() {
        let normalizer = build_normalizer();
        let mut event = process_start_event(Platform::Windows, "etw", 4242);
        if let SensorPayload::Process(fields) = &mut event.payload {
            fields.command_line = Some("cmd.exe /c test".into());
            fields
                .windows
                .get_or_insert_with(Default::default)
                .command_line_source = Some("live_query".into());
        }
        let normalized = normalizer.normalize(&event).unwrap();
        assert!(normalized
            .provenance
            .entries()
            .iter()
            .any(|entry| entry.field == "CommandLine" && entry.fidelity == Fidelity::Derived));
        let json = serde_json::to_vec(&normalized).unwrap();
        let replayed: NormalizedEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(replayed.provenance, normalized.provenance);
        if let SensorPayload::Process(fields) = &mut event.payload {
            fields
                .windows
                .get_or_insert_with(Default::default)
                .command_line_source = Some("classic".into());
        }
        let measured = normalizer.normalize(&event).unwrap();
        assert!(!measured
            .provenance
            .entries()
            .iter()
            .any(|entry| entry.field == "CommandLine"));
    }

    #[test]
    fn canonical_events_keep_nanoseconds_and_distinct_ordering() {
        let normalizer = build_normalizer();
        #[cfg(not(windows))]
        const EVENT_NANOS: u32 = 123_456_789;
        #[cfg(not(windows))]
        const EXPECTED_TIMESTAMP: &str = "1970-01-01T00:00:10.123456789Z";
        // Windows SystemTime uses FILETIME's native 100 ns resolution.
        #[cfg(windows)]
        const EVENT_NANOS: u32 = 123_456_700;
        #[cfg(windows)]
        const EXPECTED_TIMESTAMP: &str = "1970-01-01T00:00:10.123456700Z";

        for expected_ingest_seq in 1..=1_000 {
            let mut event = process_start_event(Platform::Linux, "ebpf", expected_ingest_seq);
            event.timestamp = SystemTime::UNIX_EPOCH + Duration::new(10, EVENT_NANOS);
            event.source_seq = Some(10_000 + u64::from(expected_ingest_seq));

            let normalized = normalizer.normalize(&event).expect("event normalizes");
            assert_eq!(normalized.timestamp, EXPECTED_TIMESTAMP);
            assert_eq!(
                normalized.source_seq,
                Some(10_000 + u64::from(expected_ingest_seq))
            );
            assert_eq!(normalized.ingest_seq, u64::from(expected_ingest_seq));
        }
    }

    #[test]
    fn windows_etw_ingest_order_does_not_flatten_session_time_skew() {
        let normalizer = build_normalizer();
        let mut process_session = process_start_event(Platform::Windows, "etw", 41);
        process_session.timestamp = SystemTime::UNIX_EPOCH + Duration::from_millis(10_005);
        let mut main_session = process_start_event(Platform::Windows, "etw", 42);
        main_session.timestamp = SystemTime::UNIX_EPOCH + Duration::from_millis(10_000);

        let first = normalizer
            .normalize(&process_session)
            .expect("process-session event normalizes");
        let second = normalizer
            .normalize(&main_session)
            .expect("main-session event normalizes");

        assert!(first.timestamp > second.timestamp);
        assert_eq!((first.ingest_seq, second.ingest_seq), (1, 2));
        assert!(first.source_seq.is_none());
        assert!(second.source_seq.is_none());
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
            source_seq: None,
            process_start_key: Some(ProcessStartKey {
                pid,
                start_time: 123_456,
            }),
            parent_process_start_key: None,
            payload: SensorPayload::Process(ProcessCreationFields {
                linux_identity: Box::new(LinuxProcessIdentity {
                    real_group_id: Some("1000".to_string()),
                    ..Default::default()
                }),
                cgroup_id: None,
                exec: Some(Box::new(ExecMetadata {
                    real_user_id: Some("1000".to_string()),
                    ..Default::default()
                })),
                parent_process_id_derived: false,
                windows: Default::default(),
                image: Some("/usr/bin/curl".to_string()),
                image_source: (platform == Platform::Linux).then(|| "proc".to_string()),
                image_truncated: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
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
            source_seq: None,
            process_start_key: with_start_key.then_some(ProcessStartKey {
                pid,
                start_time: 123_456,
            }),
            parent_process_start_key: None,
            payload: SensorPayload::Process(ProcessCreationFields {
                linux_identity: Default::default(),
                cgroup_id: None,
                exec: Default::default(),
                parent_process_id_derived: false,
                windows: Default::default(),
                image: None,
                image_source: None,
                image_truncated: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
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
            source_seq: None,
            process_start_key: Some(ProcessStartKey {
                pid,
                start_time: 123_456,
            }),
            parent_process_start_key: None,
            payload: SensorPayload::Network(NetworkConnectionFields {
                destination_ip: Some("198.51.100.10".to_string()),
                source_ip: (platform == Platform::Windows).then(|| "10.0.0.5".to_string()),
                destination_port: Some("443".to_string()),
                source_port: (platform == Platform::Windows).then(|| "51324".to_string()),
                process_id: Some(pid.to_string()),
                image: None,
                user: Some("alice".to_string()),
                destination_hostname: None,
                protocol: Some("tcp".to_string()),
                initiated: Some(true),
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
            source_seq: None,
            process_start_key: Some(ProcessStartKey {
                pid,
                start_time: 123_456,
            }),
            parent_process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                source_filename: None,
                target_filename: Some("/tmp/sample.txt".to_string()),
                process_id: Some(pid.to_string()),
                image: None,
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: Some("alice".to_string()),
                path_truncated: None,
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
        let _normalizer = build_normalizer();
    }

    #[test]
    fn process_stop_events_only_maintain_cache() {
        let normalizer = build_normalizer();

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
            source_seq: None,
            process_start_key: Some(ProcessStartKey {
                pid: 42,
                start_time: 99,
            }),
            parent_process_start_key: None,
            payload: SensorPayload::Process(ProcessCreationFields {
                linux_identity: Default::default(),
                cgroup_id: None,
                exec: Default::default(),
                parent_process_id_derived: false,
                windows: Default::default(),
                image: None,
                image_source: None,
                image_truncated: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
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
            }),
        };

        assert!(normalizer.normalize(&event).is_none());
        assert_eq!(normalizer.process_cache.count(), 0);
    }

    #[test]
    fn process_stop_without_identity_does_not_evict_by_pid() {
        let normalizer = build_normalizer();

        let start = process_start_event(Platform::Linux, "ebpf", 42);
        let stop = process_stop_event(Platform::Linux, "ebpf", 42, false);

        let start_normalized = normalizer
            .normalize(&start)
            .expect("linux process start should normalize");
        assert_eq!(start_normalized.get_field("Image"), Some("/usr/bin/curl"));

        assert!(normalizer.normalize(&stop).is_none());
        assert_eq!(normalizer.process_cache.count(), 1);
    }

    #[test]
    fn repeated_network_connections_stay_visible_to_detection() {
        let normalizer = build_normalizer();
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
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
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
                initiated: Some(true),
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
    }

    #[test]
    fn normalizer_preserves_sensor_supplied_compat_metadata() {
        let normalizer = build_normalizer();
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
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                source_filename: None,
                target_filename: Some("/tmp/test".to_string()),
                process_id: Some("9".to_string()),
                image: Some("/usr/bin/touch".to_string()),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: Some("alice".to_string()),
                path_truncated: None,
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
    fn sensor_measured_file_image_is_not_overwritten() {
        let normalizer = build_normalizer();
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
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                source_filename: None,
                target_filename: Some("/tmp/test".to_string()),
                process_id: Some("9".to_string()),
                image: Some("touch".to_string()),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: Some("alice".to_string()),
                path_truncated: None,
            }),
        };

        let normalized = normalizer
            .normalize(&event)
            .expect("file event should normalize");

        match normalized.fields {
            EventFields::FileEvent(fields) => {
                assert_eq!(fields.image.as_deref(), Some("touch"));
            }
            other => panic!("unexpected fields: {:?}", other),
        }
        assert!(normalized.provenance.is_empty());
    }

    #[test]
    fn linux_process_start_primes_cache_for_follow_on_network_enrichment() {
        let normalizer = build_normalizer();

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
        assert_eq!(
            normalized.provenance.entries(),
            &[FieldProvenance {
                field: "Image".to_string(),
                fidelity: Fidelity::Derived,
            }]
        );
    }

    fn process_start_with_identity(pid: u32, start_time: u64, image: &str) -> SensorEvent {
        let mut event = process_start_event(Platform::Linux, "ebpf", pid);
        event.process_start_key = Some(ProcessStartKey { pid, start_time });
        if let SensorPayload::Process(fields) = &mut event.payload {
            fields.image = Some(image.to_string());
        }
        event
    }

    #[test]
    fn delayed_file_event_uses_original_identity_after_pid_reuse() {
        let normalizer = build_normalizer();
        let pid = 4242;
        let old_start = process_start_with_identity(pid, 100, "/usr/bin/old");
        let mut old_stop = process_stop_event(Platform::Linux, "ebpf", pid, true);
        old_stop.process_start_key = Some(ProcessStartKey {
            pid,
            start_time: 100,
        });
        let new_start = process_start_with_identity(pid, 200, "/usr/bin/new");
        let mut delayed = file_event(Platform::Linux, "ebpf", pid);
        delayed.process_start_key = Some(ProcessStartKey {
            pid,
            start_time: 100,
        });

        normalizer
            .normalize(&old_start)
            .expect("old process starts");
        assert!(normalizer.normalize(&old_stop).is_none());
        normalizer
            .normalize(&new_start)
            .expect("new process starts");

        let normalized = normalizer.normalize(&delayed).expect("file normalizes");
        assert_eq!(normalized.get_field("Image"), Some("/usr/bin/old"));
        assert_eq!(
            normalized.provenance.entries()[0].fidelity,
            Fidelity::Derived
        );
    }

    #[test]
    fn delayed_event_keeps_pre_exec_identity() {
        let normalizer = build_normalizer();
        let pid = 4242;
        let before_exec = process_start_with_identity(pid, 100, "/usr/bin/old");
        let after_exec = process_start_with_identity(pid, 200, "/usr/bin/new");
        let mut delayed = network_event(Platform::Linux, "ebpf", pid);
        delayed.process_start_key = Some(ProcessStartKey {
            pid,
            start_time: 100,
        });

        normalizer
            .normalize(&before_exec)
            .expect("first execution starts");
        normalizer
            .normalize(&after_exec)
            .expect("second execution starts");

        let normalized = normalizer
            .normalize(&delayed)
            .expect("network event normalizes");
        assert_eq!(normalized.get_field("Image"), Some("/usr/bin/old"));
    }

    #[test]
    fn process_parent_fields_use_exact_parent_identity() {
        let normalizer = build_normalizer();
        let parent_pid = 4000;
        let child_pid = 4001;
        let parent = process_start_with_identity(parent_pid, 100, "/usr/bin/parent");
        let mut child = process_start_with_identity(child_pid, 200, "/usr/bin/child");
        child.parent_process_start_key = Some(ProcessStartKey {
            pid: parent_pid,
            start_time: 100,
        });
        if let SensorPayload::Process(fields) = &mut child.payload {
            fields.parent_process_id = Some(parent_pid.to_string());
        }

        normalizer.normalize(&parent).expect("parent starts");
        let normalized = normalizer.normalize(&child).expect("child starts");

        assert_eq!(normalized.get_field("ParentImage"), Some("/usr/bin/parent"));
        assert_eq!(
            normalized.get_field("ParentCommandLine"),
            Some("/usr/bin/curl https://example.test")
        );
        assert_eq!(
            normalized.provenance.entries(),
            &[
                FieldProvenance {
                    field: "ProcessStartTime".to_string(),
                    fidelity: Fidelity::Derived,
                },
                FieldProvenance {
                    field: "ParentImage".to_string(),
                    fidelity: Fidelity::Derived,
                },
                FieldProvenance {
                    field: "ParentCommandLine".to_string(),
                    fidelity: Fidelity::Derived,
                },
            ]
        );
    }

    #[test]
    fn equivalent_windows_and_linux_process_events_normalize_same_shared_fields() {
        let windows = build_normalizer()
            .normalize(&process_start_event(Platform::Windows, "etw", 9001))
            .expect("windows process start should normalize");
        let linux = build_normalizer()
            .normalize(&process_start_event(Platform::Linux, "ebpf", 9001))
            .expect("linux process start should normalize");

        assert_shared_fields_equal(
            &windows,
            &linux,
            &["Image", "CommandLine", "ProcessId", "ParentProcessId"],
        );
    }

    #[test]
    fn equivalent_windows_and_linux_network_events_normalize_same_shared_fields() {
        let windows_normalizer = build_normalizer();
        let linux_normalizer = build_normalizer();

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
                "DestinationPort",
                "ProcessId",
                "Image",
                "User",
                "DestinationHostname",
                "Protocol",
                "Initiated",
            ],
        );
    }

    #[test]
    fn equivalent_windows_and_linux_file_events_normalize_same_shared_fields() {
        let windows_normalizer = build_normalizer();
        let linux_normalizer = build_normalizer();

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
