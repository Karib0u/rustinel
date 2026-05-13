#[cfg(test)]
mod common;

use common::{
    dns_query_event, file_create_event, network_connect_event, process_start_event, TestNormalizer,
};
use rustinel::{engine::Engine, models::EventFields, sensor::Platform};

#[cfg(target_os = "linux")]
fn write_cstr<const N: usize>(dst: &mut [u8; N], value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len().min(N.saturating_sub(1));
    dst[..len].copy_from_slice(&bytes[..len]);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_ebpf_raw_events_map_to_sensor_events() {
    use rustinel::sensor::linux::events::{
        mapping, DnsEvent, FileEvent, NetworkEvent, ProcessEvent,
    };
    use rustinel::sensor::{SensorAction, SensorPayload};

    let mut process = ProcessEvent {
        kind: 1,
        pid: 42,
        uid: 1000,
        _pad: 0,
        comm: [0; 16],
        image: [0; 128],
    };
    write_cstr(&mut process.image, "/usr/bin/curl");
    let mapped = mapping::process_event_to_sensor(&process);
    assert_eq!(mapped.action, SensorAction::Start);
    assert_eq!(mapped.normalization.event_id, 1);

    process.kind = 2;
    let mapped = mapping::process_event_to_sensor(&process);
    assert_eq!(mapped.action, SensorAction::Stop);
    assert_eq!(mapped.normalization.event_id, 5);

    let mut network = NetworkEvent {
        pid: 42,
        uid: 1000,
        fd: 3,
        _pad0: 0,
        dport: 443,
        sport: 51324,
        af: 2,
        _pad1: 0,
        daddr: [0; 16],
        saddr: [0; 16],
    };
    network.daddr[..4].copy_from_slice(&[198, 51, 100, 10]);
    network.saddr[..4].copy_from_slice(&[10, 0, 0, 5]);
    let mapped = mapping::network_event_to_sensor(&network);
    match mapped.payload {
        SensorPayload::Network(fields) => {
            assert_eq!(fields.destination_ip.as_deref(), Some("198.51.100.10"));
            assert_eq!(fields.source_port.as_deref(), Some("51324"));
        }
        _ => panic!("expected network payload"),
    }

    let mut file = FileEvent {
        kind: 3,
        pid: 42,
        uid: 1000,
        _pad0: 0,
        path: [0; 96],
        aux_path: [0; 96],
        comm: [0; 16],
    };
    write_cstr(&mut file.path, "/tmp/new.txt");
    write_cstr(&mut file.aux_path, "/tmp/old.txt");
    let mapped = mapping::file_event_to_sensor(&file);
    assert_eq!(mapped.action, SensorAction::Rename);
    match mapped.payload {
        SensorPayload::File(fields) => {
            assert_eq!(fields.source_filename.as_deref(), Some("/tmp/old.txt"));
            assert_eq!(fields.target_filename.as_deref(), Some("/tmp/new.txt"));
        }
        _ => panic!("expected file payload"),
    }

    let mut dns = DnsEvent {
        kind: 1,
        pid: 42,
        uid: 1000,
        fd: 3,
        payload_len: 0,
        _pad0: 0,
        query_name: [0; 96],
        query_results: [0; 96],
        record_type: [0; 16],
        payload: [0; 256],
    };
    write_cstr(&mut dns.query_name, "example.test");
    write_cstr(&mut dns.query_results, "198.51.100.10");
    write_cstr(&mut dns.record_type, "A");
    let mapped = mapping::dns_event_to_sensor(&dns);
    match mapped.payload {
        SensorPayload::Dns(fields) => {
            assert_eq!(fields.query_name.as_deref(), Some("example.test"));
            assert_eq!(fields.query_results.as_deref(), Some("198.51.100.10"));
            assert_eq!(fields.record_type.as_deref(), Some("A"));
        }
        _ => panic!("expected dns payload"),
    }
}

#[cfg(windows)]
#[test]
fn windows_etw_compatibility_mapping_uses_sysmon_ids() {
    use rustinel::{models::EventCategory, sensor::windows::mapper::map_to_sysmon_id};

    assert_eq!(map_to_sysmon_id(EventCategory::Process, 1, 999), 1);
    assert_eq!(map_to_sysmon_id(EventCategory::Process, 2, 999), 5);
    assert_eq!(map_to_sysmon_id(EventCategory::ImageLoad, 10, 999), 7);
    assert_eq!(map_to_sysmon_id(EventCategory::File, 64, 999), 11);
    assert_eq!(map_to_sysmon_id(EventCategory::File, 70, 999), 23);
    assert_eq!(map_to_sysmon_id(EventCategory::Registry, 36, 999), 12);
    assert_eq!(map_to_sysmon_id(EventCategory::Registry, 39, 999), 13);
    assert_eq!(map_to_sysmon_id(EventCategory::Network, 12, 999), 3);
}

#[test]
fn equivalent_windows_and_linux_events_normalize_to_shared_sigma_fields() {
    for build in [
        process_start_event,
        network_connect_event,
        file_create_event,
        dns_query_event,
    ] {
        let harness = TestNormalizer::new(false);
        let windows = harness
            .normalizer
            .normalize(&build(Platform::Windows))
            .expect("windows event normalizes");
        let linux = harness
            .normalizer
            .normalize(&build(Platform::Linux))
            .expect("linux event normalizes");

        assert_eq!(windows.category, linux.category);
        assert_ne!(windows.provider, linux.provider);
        match (&windows.fields, &linux.fields) {
            (EventFields::ProcessCreation(w), EventFields::ProcessCreation(l)) => {
                assert!(w.image.is_some());
                assert!(l.image.is_some());
                assert_eq!(w.process_id, l.process_id);
            }
            (EventFields::NetworkConnection(w), EventFields::NetworkConnection(l)) => {
                assert_eq!(w.destination_ip, l.destination_ip);
                assert_eq!(w.destination_port, l.destination_port);
            }
            (EventFields::FileEvent(w), EventFields::FileEvent(l)) => {
                assert!(w.target_filename.is_some());
                assert!(l.target_filename.is_some());
            }
            (EventFields::DnsQuery(w), EventFields::DnsQuery(l)) => {
                assert_eq!(w.query_name, l.query_name);
                assert_eq!(w.record_type, l.record_type);
            }
            _ => panic!("event shape mismatch"),
        }
    }
}

#[test]
fn generic_sigma_rule_matches_equivalent_linux_and_windows_process_events() {
    let fixture = common::SigmaFixture::new();
    fixture.write_rule(
        "generic-process.yml",
        r#"title: Generic Curl Process
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: "example.test"
  condition: selection
level: medium
"#,
    );

    for platform in [Platform::Windows, Platform::Linux] {
        let mut engine = Engine::new_for_platform(platform);
        engine
            .load_rules(fixture.rules_dir())
            .expect("load generic rule");
        let event = TestNormalizer::new(false)
            .normalizer
            .normalize(&process_start_event(platform))
            .expect("normalize process");
        assert!(engine.check_event(&event).is_some());
    }
}
