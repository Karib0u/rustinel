#![cfg(target_os = "linux")]

#[cfg(test)]
mod common;

use arc_swap::ArcSwap;
use rustinel::{
    alerts::AlertSink,
    config::ResponseConfig,
    engine::{DetectorStore, Engine},
    ioc::IocEngine,
    memory::MemoryScanConfig,
    models::MatchDebugLevel,
    response::ResponseEngine,
    runtime::yara::spawn_yara_memory_worker,
    scanner::{Scanner, YaraEventHandler},
    sensor::{
        linux::EbpfSensor, Platform, RawProcessPlatform, RawUserId, Sensor, SensorAction,
        SensorEventHandler, SensorPayload,
    },
    state::ProcessCache,
    utils::query_process_identity,
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::MetadataExt, process::CommandExt},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

#[test]
#[ignore = "subprocess for privileged task identity validation"]
fn identity_child() {
    assert_eq!(std::env::var("RUSTINEL_IDENTITY_CHILD").as_deref(), Ok("1"));
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    std::fs::write(
        format!("/tmp/task433-{}", std::process::id()),
        b"identity probe",
    )
    .unwrap();
    std::io::stdin().read_exact(&mut byte).unwrap();
    panic!("exec failed: {}", Command::new("/bin/cat").exec());
}

fn child() -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", "identity_child", "--nocapture"])
        .env("RUSTINEL_IDENTITY_CHILD", "1")
        .stdin(Stdio::piped());
    command
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_file(format!("/tmp/task433-{}", self.0.id()));
    }
}

fn assert_verifier_acceptance() {
    let snapshot = rustinel::telemetry::LINUX_EBPF.snapshot().unwrap();
    for feature in snapshot.features {
        for reason in feature.unavailable_hooks {
            assert!(!reason.contains("BPF_PROG_LOAD"), "{reason}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root, tracefs, kernel BTF, and a built eBPF object"]
async fn live_task_identity_matches_proc() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let plans = rustinel::sensor::linux::task_btf::TaskPlans::load();
    assert!(plans.warnings.is_empty(), "{:?}", plans.warnings);
    // This child predates attachment and must reconcile through the inventory.
    let mut existing = Child(child().spawn().unwrap());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cache = Arc::new(ProcessCache::new());
    let sensor = EbpfSensor::with_process_cache(Arc::clone(&cache));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
    sensor.start(tx).unwrap();
    assert_verifier_acceptance();
    existing.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    let mut command = Command::new("/bin/cat");
    command.stdin(Stdio::piped()).stdout(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let master = libc::posix_openpt(libc::O_RDWR);
            if master < 0 || libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let slave = libc::open(libc::ptsname(master), libc::O_RDWR);
            if slave < 0 || libc::ioctl(slave, libc::TIOCSCTTY, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Model the real/effective credentials of a setuid-root exec.
            if libc::setresgid(1000, 0, 0) != 0 || libc::setresuid(1000, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let target = Child(command.spawn().unwrap());
    let target_pid = target.0.id();
    let mut saw_exec = false;
    let mut saw_inventory = false;
    let mut inventory_key = None;
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(event) = rx.recv().await {
            if event.pid == Some(existing.0.id()) && matches!(event.payload, SensorPayload::File(_))
            {
                let key = event
                    .process_start_key
                    .expect("inventory must produce an identity");
                assert!(cache.get_metadata_by_key(key.pid, key.start_time).is_some());
                saw_inventory = true;
                inventory_key = Some(key);
            }
            if event.pid == Some(target_pid) && event.action == SensorAction::Start {
                let SensorPayload::Process(fields) = event.payload else {
                    continue;
                };
                let RawProcessPlatform::Linux(source) = fields.platform.as_ref() else {
                    panic!("expected Linux process facts");
                };
                let identity = &source.identity;
                let status = std::fs::read_to_string(format!("/proc/{target_pid}/status")).unwrap();
                let ids = |key: &str| -> Vec<String> {
                    status
                        .lines()
                        .find(|line| line.starts_with(key))
                        .unwrap()
                        .split_whitespace()
                        .skip(1)
                        .map(str::to_owned)
                        .collect()
                };
                let uid = ids("Uid:");
                let gid = ids("Gid:");
                assert_eq!(uid[0], "1000");
                assert_eq!(uid[1], "0");
                assert_eq!(fields.user, Some(RawUserId::Unix(uid[1].parse().unwrap())));
                assert_eq!(source.real_user_id, Some(uid[0].parse::<u32>().unwrap()));
                assert_eq!(identity.real_group_id, Some(gid[0].parse::<u32>().unwrap()));
                assert_eq!(identity.effective_group_id, Some(gid[1].parse().unwrap()));
                for (name, value) in [
                    ("mnt", &identity.mount_namespace),
                    ("pid", &identity.pid_namespace),
                    ("net", &identity.network_namespace),
                ] {
                    let inode = std::fs::metadata(format!("/proc/{target_pid}/ns/{name}"))
                        .unwrap()
                        .ino();
                    assert_eq!(*value, Some(inode), "{name}");
                }
                let active = std::fs::metadata(format!("/proc/{target_pid}/ns/pid"))
                    .unwrap()
                    .ino();
                let children = std::fs::metadata(format!("/proc/{target_pid}/ns/pid_for_children"))
                    .ok()
                    .map(|meta| meta.ino());
                assert_ne!(
                    Some(active),
                    children,
                    "exercise the active PID namespace distinction"
                );
                let stat = std::fs::read_to_string(format!("/proc/{target_pid}/stat")).unwrap();
                let tail: Vec<_> = stat
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .split_whitespace()
                    .collect();
                assert_eq!(identity.session_id, Some(tail[3].parse().unwrap()));
                let tty = tail[4].parse::<u32>().unwrap() as u64;
                let major = (tty >> 8) & 0xfff;
                let minor = (tty & 0xff) | ((tty >> 12) & 0xfff00);
                let (raw_major, raw_minor, index) = identity.controlling_tty.unwrap();
                assert_eq!((raw_major, raw_minor + index), (major, minor));
                let start = identity.kernel_start_boottime.unwrap();
                let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
                assert_eq!(
                    start / 1_000_000_000 * hz + start % 1_000_000_000 * hz / 1_000_000_000,
                    tail[19].parse::<u64>().unwrap()
                );
                assert_ne!(
                    event.process_start_key.unwrap().start_time,
                    start,
                    "execution identity remains separate from kernel birth time"
                );
                saw_exec = true;
            }
            if saw_exec && saw_inventory {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(saw_exec && saw_inventory);
    existing.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = rx.recv().await {
            if event.pid == Some(existing.0.id()) && event.action == SensorAction::Start {
                assert_ne!(
                    event.process_start_key, inventory_key,
                    "exec must mint a new execution identity"
                );
                let SensorPayload::Process(fields) = event.payload else {
                    continue;
                };
                let RawProcessPlatform::Linux(source) = *fields.platform else {
                    panic!("expected Linux process facts");
                };
                let start = source.identity.kernel_start_boottime.unwrap();
                let ticks = rustinel::utils::query_process_details(existing.0.id())
                    .unwrap()
                    .start_time
                    .unwrap();
                let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
                assert_eq!(
                    start / 1_000_000_000 * hz + start % 1_000_000_000 * hz / 1_000_000_000,
                    ticks
                );
                return;
            }
        }
        panic!("no repeated exec event");
    })
    .await
    .unwrap();
    sensor.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root, process-memory access, kernel BTF, and a built eBPF object and memory_target example"]
async fn live_ebpf_process_reaches_yara_memory_scan() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let plans = rustinel::sensor::linux::task_btf::TaskPlans::load();
    assert!(plans.warnings.is_empty(), "{:?}", plans.warnings);

    let executable = "target/debug/examples/memory_target";
    assert!(
        std::path::Path::new(executable).exists(),
        "binary not found at {executable}; run cargo build --example memory_target"
    );

    let sensor = EbpfSensor::new();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(8192);
    sensor.start(event_tx).unwrap();
    assert_verifier_acceptance();

    let mut target = Child(
        Command::new(executable)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn memory target"),
    );
    let target_pid = target.0.id();
    let mut ready = String::new();
    BufReader::new(target.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), format!("READY:{target_pid}"));

    let event = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(event) = event_rx.recv().await {
            if event.pid == Some(target_pid) && event.action == SensorAction::Start {
                return event;
            }
        }
        panic!("eBPF event channel closed before target exec");
    })
    .await
    .expect("timed out waiting for target exec event");
    sensor.shutdown();

    let SensorPayload::Process(fields) = &event.payload else {
        panic!("target exec did not carry process fields");
    };
    let RawProcessPlatform::Linux(source) = fields.platform.as_ref() else {
        panic!("expected Linux process facts");
    };
    assert!(source.identity.kernel_start_boottime.is_some());

    let (file_tx, mut file_rx) = tokio::sync::mpsc::channel(1);
    let (queued_tx, mut queued_rx) = tokio::sync::mpsc::channel(1);
    let handler = YaraEventHandler {
        tx: file_tx,
        memory_tx: Some(queued_tx),
        allowlist_paths: Vec::new(),
    };
    let canonical = common::TestNormalizer::new()
        .host_state
        .canonicalize(event.clone())
        .expect("event canonicalizes");
    handler.handle_event(&canonical);
    assert!(
        file_rx.try_recv().is_ok(),
        "exec must also reach file scanning"
    );
    let job = queued_rx.try_recv().expect("exec must queue a memory scan");
    let proc_identity = query_process_identity(target_pid).expect("live target identity");
    assert_eq!(
        job.expected_identity.start_time, proc_identity.start_time,
        "queued eBPF identity must use /proc clock ticks"
    );
    assert_ne!(
        job.expected_identity.start_time,
        event.process_start_key.map(|key| key.start_time),
        "raw eBPF nanoseconds must not reach /proc identity validation"
    );

    let yara_fixture = common::YaraFixture::new();
    yara_fixture.write_default_rule();
    let detectors = DetectorStore::new(
        Arc::new(Engine::new_for_platform(Platform::Linux)),
        Arc::new(Scanner::new(yara_fixture.rules_dir()).unwrap()),
        Arc::new(IocEngine::disabled()),
    );
    let alert_dir = tempfile::tempdir().unwrap();
    let alert_path = alert_dir.path().join("alerts.ndjson");
    let alert_file = std::fs::File::create(&alert_path).unwrap();
    let (writer, guard) = tracing_appender::non_blocking(alert_file);
    let response_config = Arc::new(ArcSwap::from(Arc::new(ResponseConfig {
        enabled: false,
        prevention_enabled: false,
        min_severity: "critical".to_string(),
        channel_capacity: 4,
        allowlist_images: Vec::new(),
        allowlist_paths: Vec::new(),
    })));
    let (response, response_handle) = ResponseEngine::new(response_config);
    let (worker_tx, worker_rx) = tokio::sync::mpsc::channel(1);
    let worker = spawn_yara_memory_worker(
        detectors,
        AlertSink::new(writer),
        response,
        MemoryScanConfig {
            max_process_bytes: 64 * 1024 * 1024,
            max_region_bytes: 8 * 1024 * 1024,
            include_private: true,
            include_image: true,
            include_mapped: false,
            delay_ms: 0,
        },
        MatchDebugLevel::Off,
        worker_rx,
        Platform::Linux,
        "yara-memory",
    );
    worker_tx.send(job).await.unwrap();
    drop(worker_tx);
    tokio::time::timeout(Duration::from_secs(20), worker)
        .await
        .expect("memory worker timed out")
        .expect("memory worker failed");
    response_handle.abort();
    drop(guard);

    let alerts = std::fs::read_to_string(alert_path).unwrap();
    assert!(alerts.contains("TestMarkerString"), "{alerts}");
    assert!(alerts.contains("yara-memory"), "{alerts}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires an isolated root VM with /sys/kernel/btf hidden"]
async fn live_without_btf_keeps_base_telemetry() {
    let plans = rustinel::sensor::linux::task_btf::TaskPlans::load();
    assert!(plans.plans.iter().all(|plan| plan.len == 0));
    assert_eq!(plans.warnings.len(), 10);
    let sensor = EbpfSensor::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
    sensor.start(tx).unwrap();
    assert_verifier_acceptance();
    let target = Child(
        Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = rx.recv().await {
            if event.pid == Some(target.0.id()) && event.action == SensorAction::Start {
                let SensorPayload::Process(fields) = event.payload else {
                    continue;
                };
                assert!(fields.user.is_none());
                let RawProcessPlatform::Linux(source) = *fields.platform else {
                    panic!("expected Linux process facts");
                };
                assert!(source.identity.effective_user_id.is_none());
                assert!(source.identity.mount_namespace.is_none());
                assert!(source.identity.kernel_start_boottime.is_none());
                assert_eq!(source.real_user_id, Some(0));
                assert!(event.process_start_key.is_some());
                sensor.shutdown();
                return;
            }
        }
        panic!("no process event");
    })
    .await
    .unwrap();
}
