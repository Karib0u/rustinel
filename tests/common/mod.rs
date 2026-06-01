#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustinel::config::IocConfig;
use rustinel::models::ecs::EcsAlert;
use rustinel::models::{
    Alert, DnsQueryFields, EventFields, FileEventFields, NetworkConnectionFields, NormalizedEvent,
    ProcessCreationFields,
};
use rustinel::normalizer::Normalizer;
use rustinel::sensor::{
    Platform, ProcessStartKey, SensorAction, SensorEvent, SensorNormalization, SensorPayload,
};
use rustinel::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
use serde_json::Value;
use tempfile::TempDir;

pub const TEST_TIMESTAMP_SECS: u64 = 1_767_225_600;
pub const TEST_PROCESS_START_TIME: u64 = 123_456_789;
pub const TEST_PID: u32 = 4242;
pub const TEST_PARENT_PID: u32 = 1000;
pub const TEST_USER: &str = "alice";
pub const TEST_SOURCE_IP: &str = "10.0.0.5";
pub const TEST_SOURCE_PORT: u16 = 51324;
pub const TEST_DESTINATION_IP: &str = "198.51.100.10";
pub const TEST_DESTINATION_PORT: u16 = 443;
pub const TEST_DOMAIN: &str = "example.test";
pub const TEST_YARA_MARKER: &str = "RUSTINEL_TEST_MARKER";

pub struct TestNormalizer {
    pub normalizer: Normalizer,
    pub process_cache: Arc<ProcessCache>,
    pub sid_cache: Arc<SidCache>,
    pub dns_cache: Arc<DnsCache>,
    pub connection_aggregator: Arc<ConnectionAggregator>,
}

impl TestNormalizer {
    pub fn new(aggregation_enabled: bool) -> Self {
        let process_cache = Arc::new(ProcessCache::new());
        let sid_cache = Arc::new(SidCache::new());
        let dns_cache = Arc::new(DnsCache::new());
        let connection_aggregator = Arc::new(ConnectionAggregator::new());
        let normalizer = Normalizer::new(
            Arc::clone(&process_cache),
            Arc::clone(&sid_cache),
            Arc::clone(&dns_cache),
            Arc::clone(&connection_aggregator),
            aggregation_enabled,
        );

        Self {
            normalizer,
            process_cache,
            sid_cache,
            dns_cache,
            connection_aggregator,
        }
    }
}

pub fn test_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_TIMESTAMP_SECS)
}

pub fn provider_for(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => "etw",
        Platform::Linux => "ebpf",
        Platform::MacOS => "esf",
    }
}

pub fn image_for(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => r"C:\Windows\System32\curl.exe",
        Platform::Linux | Platform::MacOS => "/usr/bin/curl",
    }
}

pub fn parent_image_for(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => r"C:\Windows\explorer.exe",
        Platform::Linux | Platform::MacOS => "/usr/bin/bash",
    }
}

pub fn test_file_path(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => r"C:\Users\alice\AppData\Local\Temp\rustinel-fixture.txt",
        Platform::Linux | Platform::MacOS => "/tmp/rustinel-fixture.txt",
    }
}

pub fn renamed_test_file_path(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => r"C:\Users\alice\AppData\Local\Temp\rustinel-renamed.txt",
        Platform::Linux | Platform::MacOS => "/tmp/rustinel-renamed.txt",
    }
}

pub fn process_start_event(platform: Platform) -> SensorEvent {
    let image = image_for(platform);
    SensorEvent {
        platform,
        provider: provider_for(platform),
        action: SensorAction::Start,
        normalization: SensorNormalization {
            event_id: 1,
            action_code: 1,
        },
        pid: Some(TEST_PID),
        timestamp: test_time(),
        process_start_key: Some(ProcessStartKey {
            pid: TEST_PID,
            start_time: TEST_PROCESS_START_TIME,
        }),
        payload: SensorPayload::Process(ProcessCreationFields {
            image: Some(image.to_string()),
            original_file_name: Some("curl.exe".to_string()),
            product: Some("curl".to_string()),
            description: Some("test process".to_string()),
            target_image: None,
            command_line: Some(format!("{image} https://{TEST_DOMAIN}")),
            process_id: Some(TEST_PID.to_string()),
            process_start_time: None,
            parent_process_id: Some(TEST_PARENT_PID.to_string()),
            parent_image: Some(parent_image_for(platform).to_string()),
            parent_command_line: Some("parent-shell".to_string()),
            current_directory: Some(temp_current_directory(platform).to_string()),
            integrity_level: None,
            user: Some(TEST_USER.to_string()),
            logon_id: None,
            logon_guid: None,
        }),
    }
}

pub fn network_connect_event(platform: Platform) -> SensorEvent {
    SensorEvent {
        platform,
        provider: provider_for(platform),
        action: SensorAction::Connect,
        normalization: SensorNormalization {
            event_id: 3,
            action_code: 12,
        },
        pid: Some(TEST_PID),
        timestamp: test_time(),
        process_start_key: None,
        payload: SensorPayload::Network(NetworkConnectionFields {
            destination_ip: Some(TEST_DESTINATION_IP.to_string()),
            source_ip: Some(TEST_SOURCE_IP.to_string()),
            destination_port: Some(TEST_DESTINATION_PORT.to_string()),
            source_port: Some(TEST_SOURCE_PORT.to_string()),
            process_id: Some(TEST_PID.to_string()),
            image: None,
            user: Some(TEST_USER.to_string()),
            destination_hostname: None,
            protocol: Some("tcp".to_string()),
        }),
    }
}

pub fn file_create_event(platform: Platform) -> SensorEvent {
    file_event(
        platform,
        SensorAction::Create,
        11,
        64,
        None,
        Some(test_file_path(platform)),
    )
}

pub fn file_delete_event(platform: Platform) -> SensorEvent {
    file_event(
        platform,
        SensorAction::Delete,
        23,
        70,
        None,
        Some(test_file_path(platform)),
    )
}

pub fn file_rename_event(platform: Platform) -> SensorEvent {
    file_event(
        platform,
        SensorAction::Rename,
        71,
        71,
        Some(test_file_path(platform)),
        Some(renamed_test_file_path(platform)),
    )
}

pub fn dns_query_event(platform: Platform) -> SensorEvent {
    SensorEvent {
        platform,
        provider: provider_for(platform),
        action: SensorAction::Query,
        normalization: SensorNormalization {
            event_id: 22,
            action_code: 0,
        },
        pid: Some(TEST_PID),
        timestamp: test_time(),
        process_start_key: None,
        payload: SensorPayload::Dns(DnsQueryFields {
            query_name: Some(TEST_DOMAIN.to_string()),
            query_results: Some(TEST_DESTINATION_IP.to_string()),
            record_type: Some("A".to_string()),
            query_status: Some("NOERROR".to_string()),
            process_id: Some(TEST_PID.to_string()),
            image: None,
        }),
    }
}

fn file_event(
    platform: Platform,
    action: SensorAction,
    event_id: u16,
    action_code: u8,
    source_filename: Option<&str>,
    target_filename: Option<&str>,
) -> SensorEvent {
    SensorEvent {
        platform,
        provider: provider_for(platform),
        action,
        normalization: SensorNormalization {
            event_id,
            action_code,
        },
        pid: Some(TEST_PID),
        timestamp: test_time(),
        process_start_key: None,
        payload: SensorPayload::File(FileEventFields {
            source_filename: source_filename.map(ToString::to_string),
            target_filename: target_filename.map(ToString::to_string),
            process_id: Some(TEST_PID.to_string()),
            image: None,
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: Some(TEST_USER.to_string()),
        }),
    }
}

fn temp_current_directory(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => r"C:\Users\alice\AppData\Local\Temp",
        Platform::Linux | Platform::MacOS => "/tmp",
    }
}

pub struct SigmaFixture {
    _tempdir: TempDir,
    rules_dir: PathBuf,
}

impl SigmaFixture {
    pub fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("create sigma fixture tempdir");
        let rules_dir = tempdir.path().join("sigma");
        fs::create_dir_all(&rules_dir).expect("create sigma rules dir");
        Self {
            _tempdir: tempdir,
            rules_dir,
        }
    }

    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }

    pub fn write_rule(&self, filename: &str, yaml: &str) -> PathBuf {
        write_fixture_file(&self.rules_dir, filename, yaml.as_bytes())
    }

    pub fn write_process_rule(&self, platform: Platform) -> PathBuf {
        let product = platform_product(platform);
        let image_suffix = match platform {
            Platform::Windows => "curl.exe",
            Platform::Linux | Platform::MacOS => "/curl",
        };
        self.write_rule(
            "process.yml",
            &format!(
                r#"title: Test Process Curl
logsource:
  product: {product}
  category: process_creation
detection:
  selection:
    Image|endswith: "{image_suffix}"
    CommandLine|contains: "{TEST_DOMAIN}"
  condition: selection
level: high
"#
            ),
        )
    }

    pub fn write_network_rule(&self, platform: Platform) -> PathBuf {
        let product = platform_product(platform);
        self.write_rule(
            "network.yml",
            &format!(
                r#"title: Test Network Destination
logsource:
  product: {product}
  category: network_connection
detection:
  selection:
    DestinationIp: "{TEST_DESTINATION_IP}"
    DestinationPort: "{TEST_DESTINATION_PORT}"
  condition: selection
level: medium
"#
            ),
        )
    }

    pub fn write_file_rule(&self, platform: Platform) -> PathBuf {
        let product = platform_product(platform);
        self.write_rule(
            "file.yml",
            &format!(
                r#"title: Test File Event
logsource:
  product: {product}
  category: file_event
detection:
  selection:
    TargetFilename|endswith: "rustinel-fixture.txt"
  condition: selection
level: low
"#
            ),
        )
    }
}

pub struct YaraFixture {
    _tempdir: TempDir,
    rules_dir: PathBuf,
    sample_dir: PathBuf,
}

impl YaraFixture {
    pub fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("create yara fixture tempdir");
        let rules_dir = tempdir.path().join("yara");
        let sample_dir = tempdir.path().join("samples");
        fs::create_dir_all(&rules_dir).expect("create yara rules dir");
        fs::create_dir_all(&sample_dir).expect("create yara samples dir");
        Self {
            _tempdir: tempdir,
            rules_dir,
            sample_dir,
        }
    }

    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }

    pub fn sample_dir(&self) -> &Path {
        &self.sample_dir
    }

    pub fn write_rule(&self, filename: &str, rule_name: &str, marker: &str) -> PathBuf {
        let rule = format!(
            r#"rule {rule_name} {{
    strings:
        $marker = "{marker}" ascii wide
    condition:
        $marker
}}
"#
        );
        write_fixture_file(&self.rules_dir, filename, rule.as_bytes())
    }

    pub fn write_default_rule(&self) -> PathBuf {
        self.write_rule("marker.yar", "TestMarkerString", TEST_YARA_MARKER)
    }

    pub fn write_sample(&self, filename: &str, bytes: &[u8]) -> PathBuf {
        write_fixture_file(&self.sample_dir, filename, bytes)
    }

    pub fn write_marker_sample(&self) -> PathBuf {
        self.write_sample("marker.bin", TEST_YARA_MARKER.as_bytes())
    }

    pub fn write_clean_sample(&self) -> PathBuf {
        self.write_sample("clean.bin", b"harmless bytes with no known marker")
    }
}

pub struct IocFixture {
    _tempdir: TempDir,
    root: PathBuf,
    hashes_path: PathBuf,
    ips_path: PathBuf,
    domains_path: PathBuf,
    paths_regex_path: PathBuf,
}

impl IocFixture {
    pub fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("create ioc fixture tempdir");
        let root = tempdir.path().join("ioc");
        fs::create_dir_all(&root).expect("create ioc dir");

        let fixture = Self {
            hashes_path: root.join("hashes.txt"),
            ips_path: root.join("ips.txt"),
            domains_path: root.join("domains.txt"),
            paths_regex_path: root.join("paths_regex.txt"),
            _tempdir: tempdir,
            root,
        };

        fixture.write_hashes("");
        fixture.write_ips("");
        fixture.write_domains("");
        fixture.write_paths_regex("");
        fixture
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> IocConfig {
        IocConfig {
            enabled: true,
            hashes_path: self.hashes_path.clone(),
            ips_path: self.ips_path.clone(),
            domains_path: self.domains_path.clone(),
            paths_regex_path: self.paths_regex_path.clone(),
            default_severity: "high".to_string(),
            max_file_size_mb: 16,
            hash_allowlist_paths: Vec::new(),
        }
    }

    pub fn write_hashes(&self, content: &str) -> PathBuf {
        write_fixture_file(&self.root, "hashes.txt", content.as_bytes())
    }

    pub fn write_ips(&self, content: &str) -> PathBuf {
        write_fixture_file(&self.root, "ips.txt", content.as_bytes())
    }

    pub fn write_domains(&self, content: &str) -> PathBuf {
        write_fixture_file(&self.root, "domains.txt", content.as_bytes())
    }

    pub fn write_paths_regex(&self, content: &str) -> PathBuf {
        write_fixture_file(&self.root, "paths_regex.txt", content.as_bytes())
    }
}

pub fn ecs_json(alert: &Alert) -> Value {
    serde_json::to_value(EcsAlert::from(alert)).expect("serialize ECS alert")
}

pub fn assert_ecs_field_eq(json: &Value, field: &str, expected: impl Into<Value>) {
    assert_eq!(
        json.get(field),
        Some(&expected.into()),
        "unexpected ECS field {field}"
    );
}

pub fn assert_ecs_field_present(json: &Value, field: &str) {
    assert!(json.get(field).is_some(), "missing ECS field {field}");
}

pub fn assert_normalized_field_eq(event: &NormalizedEvent, field: &str, expected: &str) {
    assert_eq!(
        event.get_field(field),
        Some(expected),
        "unexpected normalized field {field}"
    );
}

pub fn event_fields_from_payload(event: SensorEvent) -> EventFields {
    match event.payload {
        SensorPayload::Process(fields) => EventFields::ProcessCreation(fields),
        SensorPayload::Network(fields) => EventFields::NetworkConnection(fields),
        SensorPayload::File(fields) => EventFields::FileEvent(fields),
        SensorPayload::Dns(fields) => EventFields::DnsQuery(fields),
        SensorPayload::Registry(fields) => EventFields::RegistryEvent(fields),
        SensorPayload::ImageLoad(fields) => EventFields::ImageLoad(fields),
        SensorPayload::Scripting(fields) => EventFields::PowerShellScript(fields),
        SensorPayload::Wmi(fields) => EventFields::WmiEvent(fields),
        SensorPayload::Service(fields) => EventFields::ServiceCreation(fields),
        SensorPayload::Task(fields) => EventFields::TaskCreation(fields),
    }
}

pub struct ChildProcessGuard {
    child: Child,
}

impl ChildProcessGuard {
    pub fn spawn(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let child = Command::new(path.as_ref())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self { child })
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub fn terminate(mut self) -> std::io::Result<()> {
        self.kill_and_wait()
    }

    fn kill_and_wait(&mut self) -> std::io::Result<()> {
        if self.child.try_wait()?.is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for ChildProcessGuard {
    fn drop(&mut self) {
        let _ = self.kill_and_wait();
    }
}

fn write_fixture_file(root: &Path, filename: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(filename);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture parent dir");
    }
    fs::write(&path, bytes).expect("write fixture file");
    path
}

fn platform_product(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::MacOS => "macos",
    }
}
