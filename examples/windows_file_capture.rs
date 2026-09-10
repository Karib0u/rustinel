//! Native file attribution check with handles opened before sensor startup.
//! Run as administrator. Optional argument: idle observation seconds (default 30).
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use rustinel::{
        sensor::{windows::etw::EtwSensor, Sensor, SensorPayload},
        telemetry::TelemetrySnapshot,
    };
    use std::{io::Write, sync::Arc, time::Duration};
    let seconds: u64 = std::env::args()
        .nth(1)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(30);
    let dir = std::env::temp_dir().join(format!("rustinel428-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let mut files = Vec::new();
    for index in 0..100 {
        files.push(std::fs::File::create(
            dir.join(format!("held-{index}.txt")),
        )?);
    }
    let sensor = Arc::new(EtwSensor::with_flush_intervals(20, 5));
    let (tx, mut rx) = tokio::sync::mpsc::channel(65536);
    let s = sensor.clone();
    let worker = std::thread::spawn(move || s.start(tx));
    let expected_directory = format!("{}\\", dir.display()).to_ascii_lowercase();
    let consumer = std::thread::spawn(move || {
        let mut targets = std::collections::BTreeSet::new();
        while let Some(event) = rx.blocking_recv() {
            if let SensorPayload::File(fields) = event.payload {
                if let Some(path) = fields.target_filename.filter(|p| {
                    p.to_ascii_lowercase().starts_with(&expected_directory) && p.contains("\\held-")
                }) {
                    targets.insert(path);
                }
            }
        }
        targets
    });
    std::thread::sleep(Duration::from_secs(seconds));
    let idle = TelemetrySnapshot::capture();
    for file in &mut files {
        file.write_all(b"pre-existing handle write\n")?;
        file.sync_all()?;
    }
    std::thread::sleep(Duration::from_secs(2));
    drop(files);
    sensor.shutdown();
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("sensor panicked"))??;
    let targets = consumer
        .join()
        .map_err(|_| anyhow::anyhow!("consumer panicked"))?;
    let mut memory = windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS::default();
    unsafe {
        windows::Win32::System::ProcessStatus::GetProcessMemoryInfo(
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut memory,
            std::mem::size_of::<windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS>()
                as u32,
        )?;
    }
    println!(
        "{}",
        serde_json::json!({"directory":dir,"expected_files":100,"peak_working_set_bytes":memory.PeakWorkingSetSize,"idle":idle, "final":TelemetrySnapshot::capture(), "held_targets":targets, "kernel_lost":sensor.events_lost()})
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Run this capture on Windows.");
}
