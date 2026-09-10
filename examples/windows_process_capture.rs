//! Repeatable native process capture comparison. Run as administrator.
//! Arguments: child count, launch interval in ms, optional `wow64`, optional flush ms.

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use rustinel::normalizer::Normalizer;
    use rustinel::sensor::windows::etw::EtwSensor;
    use rustinel::sensor::{Sensor, SensorAction, SensorPayload};
    use rustinel::state::{DnsCache, ProcessCache, SidCache};
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args.get(1).map(|x| x.parse()).transpose()?.unwrap_or(100);
    let interval: u64 = args.get(2).map(|x| x.parse()).transpose()?.unwrap_or(10);
    let wow64 = args.get(3).is_some_and(|x| x == "wow64");
    let long = args.get(3).is_some_and(|x| x == "long");
    let flush: u64 = args.get(4).map(|x| x.parse()).transpose()?.unwrap_or(5);
    let sensor = Arc::new(EtwSensor::with_flush_intervals(20, flush));
    let (tx, mut rx) = tokio::sync::mpsc::channel(65536);
    let worker_sensor = Arc::clone(&sensor);
    let worker = std::thread::spawn(move || worker_sensor.start(tx));
    let consumer = std::thread::spawn(move || {
        let normalizer = Normalizer::new(
            Arc::new(ProcessCache::new()),
            Arc::new(SidCache::new()),
            Arc::new(DnsCache::new()),
        );
        let mut events = Vec::new();
        while let Some(event) = rx.blocking_recv() {
            if event.action == SensorAction::Start
                && matches!(event.payload, SensorPayload::Process(_))
            {
                let latency = SystemTime::now()
                    .duration_since(event.timestamp)
                    .unwrap_or_default()
                    .as_secs_f64()
                    * 1000.0;
                if let Some(normalized) = normalizer.normalize(&event) {
                    events.push(json!({"pid":event.pid, "latency_ms":latency,"event":normalized}));
                }
            }
        }
        events
    });
    std::thread::sleep(Duration::from_secs(3));
    let started = Instant::now();
    let mut children = Vec::new();
    let image = format!(
        "{}\\{}\\cmd.exe",
        std::env::var("WINDIR")?,
        if wow64 { "SysWOW64" } else { "System32" }
    );
    for index in 0..count {
        let marker = format!(
            "RUSTINEL_393_{index}_été{}",
            if long {
                "x".repeat(20000)
            } else {
                String::new()
            }
        );
        let child = std::process::Command::new(&image)
            .args(["/d", "/c", "rem", &marker])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        children.push((child, marker));
        if interval > 0 {
            std::thread::sleep(Duration::from_millis(interval));
        }
    }
    let mut expected = Vec::new();
    for (mut child, marker) in children {
        expected.push(json!({"pid": child.id(), "marker": marker}));
        child.wait()?;
    }
    let workload_seconds = started.elapsed().as_secs_f64();
    std::thread::sleep(Duration::from_secs(3));
    sensor.shutdown();
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("sensor panicked"))??;
    let events = consumer
        .join()
        .map_err(|_| anyhow::anyhow!("consumer panicked"))?;
    let mut creation = windows::Win32::Foundation::FILETIME::default();
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    unsafe {
        windows::Win32::System::Threading::GetProcessTimes(
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )?;
    }
    let ticks = |t: windows::Win32::Foundation::FILETIME| {
        (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
    };
    let cpu_seconds = (ticks(kernel) + ticks(user)) as f64 / 10_000_000.0;
    println!(
        "{}",
        json!({"count":count, "interval_ms":interval, "wow64":wow64,
        "workload_seconds":workload_seconds,"expected":expected,"events":events,
        "kernel_lost":sensor.events_lost(), "cpu_seconds":cpu_seconds, "telemetry":rustinel::telemetry::TelemetrySnapshot::capture()})
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Run this capture comparison on Windows.");
}
