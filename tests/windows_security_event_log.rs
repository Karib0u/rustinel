#![cfg(windows)]

//! Privileged smoke test for the Security channel source.
//!
//! Unlike System 7045, nothing in the Security channel is audited by default
//! except logons, so the test turns the *Security System Extension*
//! subcategory on, produces a service installation, and restores whatever the
//! host had before. That restore is what keeps the test safe to run on a lab
//! box that is also used for other work.

use std::path::PathBuf;
use std::process::{self, Command};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustinel::sensor::windows::EtwSensor;
use rustinel::sensor::{Sensor, SensorPayload};

/// The *Security System Extension* audit subcategory, which is what makes
/// Windows log event 4697.
///
/// Addressed by GUID rather than by name: `auditpol` takes the subcategory's
/// *localized* name, so `"Security System Extension"` is not a valid argument
/// on a non-English Windows. The GUID is the same everywhere.
const SUBCATEGORY: &str = "{0CCE9211-69AE-11D9-BED3-505054503030}";

struct TemporaryService(String);

impl Drop for TemporaryService {
    fn drop(&mut self) {
        let _ = Command::new("sc.exe").args(["delete", &self.0]).status();
    }
}

/// Enables the subcategory for the duration of the test and puts the host's
/// audit policy back exactly as it was afterwards, however the test ends.
///
/// The restore is a full `auditpol` backup rather than an inverse `/set`, so
/// nothing is inferred about what the setting was: the file holds the whole
/// policy, and applying it is exact.
struct AuditPolicy {
    backup: PathBuf,
}

impl AuditPolicy {
    fn enable_success() -> Self {
        let backup = std::env::temp_dir().join(format!("rustinel-auditpol-{}.csv", process::id()));

        let status = Command::new("auditpol.exe")
            .arg("/backup")
            .arg(format!("/file:{}", backup.display()))
            .status()
            .expect("auditpol.exe must be available");
        assert!(
            status.success(),
            "failed to back up the audit policy; the test needs Administrator"
        );

        let policy = Self { backup };
        let status = Command::new("auditpol.exe")
            .arg("/set")
            .arg(format!("/subcategory:{SUBCATEGORY}"))
            .arg("/success:enable")
            .status()
            .expect("auditpol.exe must be available");
        assert!(status.success(), "failed to enable the 4697 audit");

        policy
    }
}

impl Drop for AuditPolicy {
    fn drop(&mut self) {
        let _ = Command::new("auditpol.exe")
            .arg("/restore")
            .arg(format!("/file:{}", self.backup.display()))
            .status();
        let _ = std::fs::remove_file(&self.backup);
    }
}

#[test]
#[ignore = "requires Administrator privileges and changes audit policy; runs in the Windows privileged smoke job"]
fn a_service_installation_reaches_the_sensor_as_security_event_4697() {
    let _audit_policy = AuditPolicy::enable_success();

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let sensor = Arc::new(EtwSensor::new());
    let worker_sensor = Arc::clone(&sensor);
    let worker = thread::spawn(move || worker_sensor.start(tx));

    // Both Event Log subscriptions start on the sensor's worker thread; give
    // them a window to become ready before producing the one-shot event.
    thread::sleep(Duration::from_secs(2));

    let service_name = format!("Rustinel4697Test{}", process::id());
    let temporary_service = TemporaryService(service_name.clone());
    let create = Command::new("sc.exe")
        .args([
            "create",
            &service_name,
            "binPath=",
            r"C:\Windows\System32\cmd.exe /c exit 0",
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

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut matched = None;
    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(event) => {
                if event.normalization.event_id != 4697 {
                    continue;
                }
                if let SensorPayload::Security(fields) = &event.payload {
                    if fields.get("ServiceName") == Some(service_name.as_str()) {
                        matched = Some(event.clone());
                        break;
                    }
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    sensor.shutdown();
    let sensor_result = worker.join().expect("sensor worker must not panic");
    drop(temporary_service);
    sensor_result.expect("sensor must stop cleanly");

    let event = matched.expect("Security event 4697 must reach the sensor channel");
    assert_eq!(event.provider, "windows_event_log");
    let SensorPayload::Security(fields) = event.payload else {
        unreachable!();
    };
    assert_eq!(fields.get("ServiceName"), Some(service_name.as_str()));
    assert!(
        fields
            .get("ServiceFileName")
            .is_some_and(|path| path.contains("cmd.exe")),
        "ServiceFileName should name the service binary: {fields:?}"
    );
    // The identity block is what separates a Security audit record from the
    // System channel's account-less 7045.
    assert!(fields.get("SubjectUserName").is_some());
    assert!(fields.get("SubjectLogonId").is_some());
}
