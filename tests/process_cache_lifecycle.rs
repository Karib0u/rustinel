use std::time::SystemTime;

use rustinel::sensor::{
    Platform, ProcessStartKey, RawLinuxProcess, RawLinuxProcessIdentity, RawProcessEvent,
    RawProcessPlatform, SensorAction, SensorEvent, SensorNormalization, SensorPayload,
};
use rustinel::state::{HostState, StateLimits};

fn process_event(pid: u32, start_time: u64, action: SensorAction) -> SensorEvent {
    SensorEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Linux,
        provider: "ebpf",
        action,
        normalization: SensorNormalization {
            event_id: 1,
            action_code: match action {
                SensorAction::Start => 1,
                SensorAction::Stop => 2,
                SensorAction::Fork => 3,
                _ => unreachable!(),
            },
        },
        pid: Some(pid),
        timestamp: SystemTime::UNIX_EPOCH,
        source_seq: None,
        process_start_key: Some(ProcessStartKey { pid, start_time }),
        parent_process_start_key: None,
        payload: SensorPayload::Process(RawProcessEvent {
            process_id: pid,
            parent_process_id: None,
            process_start_time: None,
            image: Some(format!("/usr/bin/process-{start_time}")),
            command_line: Some(format!("process-{start_time} --test")),
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            platform: Box::new(RawProcessPlatform::Linux(RawLinuxProcess {
                real_user_id: Some(0),
                identity: RawLinuxProcessIdentity {
                    real_group_id: Some(0),
                    ..Default::default()
                },
                cgroup_id: None,
                image_source: Some("execve".to_string()),
                image_truncated: None,
                parent_process_id_derived: false,
            })),
        }),
    }
}

fn fork_event(pid: u32, start_time: u64) -> SensorEvent {
    let mut event = process_event(pid, start_time, SensorAction::Fork);
    event.parent_process_start_key = Some(ProcessStartKey {
        pid: 1,
        start_time: 1,
    });
    let SensorPayload::Process(process) = &mut event.payload else {
        unreachable!()
    };
    process.parent_process_id = Some(1);
    event
}

#[test]
fn fork_exec_exit_leaves_no_live_child_identity() {
    let host = HostState::default();
    host.canonicalize(process_event(1, 1, SensorAction::Start))
        .unwrap();
    assert!(host.canonicalize(fork_event(2, 100)).is_none());
    assert_eq!(host.snapshot().processes, 2);

    host.canonicalize(process_event(2, 200, SensorAction::Start))
        .unwrap();
    assert_eq!(host.snapshot().processes, 2);
    // A delayed event or a child's parent reference still gets the old image.
    assert_eq!(
        host.processes
            .get_metadata_by_key(2, 100)
            .unwrap()
            .image_name,
        "/usr/bin/process-1"
    );
    assert!(host
        .canonicalize(process_event(2, 200, SensorAction::Stop))
        .is_none());
    assert!(host
        .canonicalize(process_event(1, 1, SensorAction::Stop))
        .is_none());
    assert_eq!(host.snapshot().processes, 0);
    assert_eq!(host.snapshot().retired_processes, 3);
}

#[test]
fn repeated_exec_and_delayed_stop_keep_only_the_current_identity_live() {
    let host = HostState::default();
    for start_time in [100, 200, 300] {
        host.canonicalize(process_event(2, start_time, SensorAction::Start))
            .unwrap();
        assert_eq!(host.snapshot().processes, 1);
    }
    host.canonicalize(process_event(2, 100, SensorAction::Stop));
    assert_eq!(host.snapshot().processes, 1);
    assert_eq!(
        host.processes
            .get_metadata_by_key(2, 300)
            .unwrap()
            .image_name,
        "/usr/bin/process-300"
    );
    host.canonicalize(process_event(2, 300, SensorAction::Stop));
    assert_eq!(host.snapshot().processes, 0);
}

#[test]
fn bursts_of_fork_exec_exit_preserve_long_lived_parent_enrichment() {
    let host = HostState::new(StateLimits {
        processes: 8,
        ..Default::default()
    });
    host.canonicalize(process_event(1, 1, SensorAction::Start))
        .unwrap();
    for pid in 2..1002 {
        let fork_time = u64::from(pid) * 2;
        host.canonicalize(fork_event(pid, fork_time));
        host.canonicalize(process_event(pid, fork_time + 1, SensorAction::Start))
            .unwrap();
        host.canonicalize(process_event(pid, fork_time + 1, SensorAction::Stop));
        let snapshot = host.snapshot();
        assert_eq!(snapshot.processes, 1);
        assert!(snapshot.retired_processes <= snapshot.limits.processes);
    }
    assert!(host.processes.get_metadata_by_key(1, 1).is_some());
    assert_eq!(host.snapshot().attribution_loss, 0);
    host.canonicalize(fork_event(1002, 2004));
    assert_eq!(
        host.processes
            .get_metadata_by_key(1002, 2004)
            .unwrap()
            .parent_image
            .as_deref(),
        Some("/usr/bin/process-1")
    );
}
