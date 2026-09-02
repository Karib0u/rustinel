#![cfg(windows)]

use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustinel::sensor::windows::EtwSensor;
use rustinel::sensor::{Sensor, SensorPayload};

struct TemporaryService(String);

impl Drop for TemporaryService {
    fn drop(&mut self) {
        let _ = Command::new("sc.exe").args(["delete", &self.0]).status();
    }
}

#[test]
#[ignore = "requires Administrator privileges; run manually on a Windows lab host"]
fn service_installation_reaches_the_normalized_sensor_channel() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let sensor = Arc::new(EtwSensor::new());
    let worker_sensor = Arc::clone(&sensor);
    let worker = thread::spawn(move || worker_sensor.start(tx));

    // The subscription startup does not return until EvtSubscribe succeeds,
    // but the sensor owns that startup on its worker thread. Give both sources a
    // short window to become ready before producing the one-shot test event.
    thread::sleep(Duration::from_secs(2));

    let service_name = format!("Rustinel7045Test{}", std::process::id());
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

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut matched = None;
    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(event) => {
                if let SensorPayload::Service(fields) = &event.payload {
                    if fields.service_name.as_deref() == Some(service_name.as_str()) {
                        matched = Some(event);
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

    let event = matched.expect("System event 7045 must reach the sensor channel");
    assert_eq!(event.provider, "windows_event_log");
    assert_eq!(event.normalization.event_id, 7045);
    let SensorPayload::Service(fields) = event.payload else {
        unreachable!();
    };
    // `event.provider` names the sensor; `Provider_Name` names the Windows
    // provider that wrote the record, which is what `service: system` rules
    // select on.
    assert_eq!(
        fields.provider_name.as_deref(),
        Some("Service Control Manager")
    );
    assert_eq!(fields.service_name.as_deref(), Some(service_name.as_str()));
    assert!(fields.service_file_name.is_some());
    assert!(fields.service_type.is_some());
    assert!(fields.start_type.is_some());
    assert!(fields.account_name.is_some());
}
