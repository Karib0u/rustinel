#![cfg(windows)]

use std::collections::HashSet;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustinel::engine::Engine;
use rustinel::models::EventFields;
use rustinel::sensor::windows::EtwSensor;
use rustinel::sensor::{Platform, Sensor};
use rustinel::state::HostState;

const BURST: usize = 64;

struct TemporaryService(String);

impl Drop for TemporaryService {
    fn drop(&mut self) {
        let _ = Command::new("sc.exe").args(["delete", &self.0]).status();
    }
}

#[test]
#[ignore = "requires Administrator privileges; run manually on a Windows lab host"]
fn process_users_survive_a_short_lived_burst_and_system_service_start() {
    let host = Arc::new(HostState::default());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
    let sensor = Arc::new(EtwSensor::new().with_host_state(Arc::clone(&host)));
    let worker_sensor = Arc::clone(&sensor);
    let worker = thread::spawn(move || worker_sensor.start(tx));
    thread::sleep(Duration::from_secs(2));

    let test_id = std::process::id();
    let parent_marker = format!("rustinel-user-parent-{test_id}");
    let child_prefix = format!("rustinel-user-child-{test_id}-");
    let script = format!(
        "$null = '{parent_marker}'; Start-Sleep -Seconds 2; for ($i = 0; $i -lt {BURST}; $i++) {{ & $env:ComSpec /d /s /c \"rem {child_prefix}$i\" }}"
    );
    let mut burst_parent = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .spawn()
        .expect("start burst parent");

    let mut parent_user = None;
    let mut child_ids = HashSet::new();
    let mut child_users = 0;
    let mut child_parent_users = 0;
    let burst_deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < burst_deadline && child_ids.len() < BURST {
        match rx.try_recv() {
            Ok(event) => {
                let Some(event) = host.canonicalize(event) else {
                    continue;
                };
                let EventFields::ProcessCreation(fields) = &event.normalized().fields else {
                    continue;
                };
                let image = fields.image.as_deref().unwrap_or_default();
                let command_line = fields.command_line.as_deref().unwrap_or_default();
                if image.to_ascii_lowercase().ends_with("powershell.exe")
                    && command_line.contains(&parent_marker)
                    && parent_user.is_none()
                {
                    parent_user = fields.user.clone();
                }
                if !image.to_ascii_lowercase().ends_with("cmd.exe") {
                    continue;
                }
                let Some(marker) = command_line
                    .split_whitespace()
                    .find(|part| part.contains(&child_prefix))
                else {
                    continue;
                };
                if child_ids.insert(marker.trim_matches('"').to_string()) {
                    child_users += usize::from(fields.user.is_some());
                    child_parent_users += usize::from(fields.parent_user == parent_user);
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }
    let _ = burst_parent.wait();

    let service_marker = format!("rustinel-system-user-{test_id}");
    let service_name = format!("RustinelProcessUser{test_id}");
    let bin_path = format!(r#"C:\Windows\System32\cmd.exe /d /s /c "rem {service_marker}""#);
    let temporary_service = TemporaryService(service_name.clone());
    let create = Command::new("sc.exe")
        .args([
            "create",
            &service_name,
            "binPath=",
            &bin_path,
            "start=",
            "demand",
            "obj=",
            "LocalSystem",
        ])
        .output()
        .expect("sc.exe must be available");
    assert!(
        create.status.success(),
        "failed to create test service: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let mut service_start = Command::new("sc.exe")
        .args(["start", &service_name])
        .spawn()
        .expect("start temporary service");

    let system_deadline = Instant::now() + Duration::from_secs(20);
    let mut system_event = None;
    while Instant::now() < system_deadline && system_event.is_none() {
        match rx.try_recv() {
            Ok(event) => {
                let Some(event) = host.canonicalize(event) else {
                    continue;
                };
                let EventFields::ProcessCreation(fields) = &event.normalized().fields else {
                    continue;
                };
                if fields
                    .image
                    .as_deref()
                    .is_some_and(|image| image.to_ascii_lowercase().ends_with("cmd.exe"))
                    && fields
                        .command_line
                        .as_deref()
                        .is_some_and(|line| line.contains(&service_marker))
                {
                    system_event = Some(event.normalized().clone());
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    let _ = service_start.kill();
    let _ = service_start.wait();
    sensor.shutdown();
    let sensor_result = worker.join().expect("sensor worker must not panic");
    drop(temporary_service);
    sensor_result.expect("sensor must stop cleanly");

    assert!(parent_user.is_some(), "burst parent must expose User");
    assert_eq!(
        child_ids.len(),
        BURST,
        "every burst process must be observed"
    );
    assert_eq!(child_users, BURST, "every burst process must expose User");
    assert_eq!(
        child_parent_users, BURST,
        "every burst process must expose the stable parent's User"
    );

    let system_event = system_event.expect("LocalSystem service process must be observed");
    assert_eq!(system_event.get_field("User"), Some("NT AUTHORITY\\SYSTEM"));

    let rules = tempfile::tempdir().expect("create temporary rules directory");
    std::fs::write(
        rules.path().join("system-user.yml"),
        format!(
            "title: Test SYSTEM Process User\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    User: 'NT AUTHORITY\\SYSTEM'\n    CommandLine|contains: '{service_marker}'\n  condition: selection\nlevel: high\n"
        ),
    )
    .expect("write temporary Sigma rule");
    let mut engine = Engine::new_for_platform(Platform::Windows);
    engine
        .load_rules(rules.path())
        .expect("load temporary Sigma rule");
    assert_eq!(engine.check_event(&system_event).len(), 1);

    println!(
        "short-lived process population: User {child_users}/{BURST}, ParentUser {child_parent_users}/{BURST}; SYSTEM rule matched"
    );
}
