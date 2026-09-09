#![cfg(target_os = "linux")]

use rustinel::{
    sensor::{linux::EbpfSensor, Sensor, SensorAction, SensorPayload},
    state::ProcessCache,
};
use std::{
    io::{Read, Write},
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
                let identity = &fields.linux_identity;
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
                assert_eq!(fields.user.as_deref(), Some(uid[1].as_str()));
                assert_eq!(
                    fields
                        .exec
                        .as_ref()
                        .and_then(|exec| exec.real_user_id.as_deref()),
                    Some(uid[0].as_str())
                );
                assert_eq!(identity.real_group_id.as_deref(), Some(gid[0].as_str()));
                assert_eq!(
                    identity.effective_group_id.as_deref(),
                    Some(gid[1].as_str())
                );
                for (name, value) in [
                    ("mnt", &identity.mount_namespace),
                    ("pid", &identity.pid_namespace),
                    ("net", &identity.network_namespace),
                ] {
                    let inode = std::fs::metadata(format!("/proc/{target_pid}/ns/{name}"))
                        .unwrap()
                        .ino();
                    assert_eq!(value.as_deref(), Some(inode.to_string().as_str()), "{name}");
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
                assert_eq!(identity.session_id.as_deref(), Some(tail[3]));
                let tty = tail[4].parse::<u32>().unwrap() as u64;
                let major = (tty >> 8) & 0xfff;
                let minor = (tty & 0xff) | ((tty >> 12) & 0xfff00);
                assert_eq!(
                    identity.controlling_tty.as_deref(),
                    Some(format!("{major}:{minor}").as_str())
                );
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
                let start = fields.linux_identity.kernel_start_boottime.unwrap();
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
                assert!(fields.linux_identity.effective_user_id.is_none());
                assert!(fields.linux_identity.mount_namespace.is_none());
                assert!(fields.linux_identity.kernel_start_boottime.is_none());
                assert_eq!(
                    fields
                        .exec
                        .as_ref()
                        .and_then(|exec| exec.real_user_id.as_deref()),
                    Some("0")
                );
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
