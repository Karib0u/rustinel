//! One-shot classic FileIo_Name snapshot. Manifest collection starts first;
//! its consumer starts after the snapshot has been validated and installed.

use super::{
    classic,
    parser::{try_get_string, try_get_uint_as_u64},
    state::EtwState,
};
use crate::telemetry::{FileRundownSnapshot, WINDOWS_FILE_ATTRIBUTION};
use anyhow::{bail, Context, Result};
use ferrisetw::{
    parser::Parser,
    provider::{
        kernel_providers::{KernelProvider, FILE_IO_PROVIDER},
        Provider,
    },
    trace::{
        DumpFileLoggingMode, DumpFileParams, FileTrace, KernelTrace, TraceProperties, TraceTrait,
    },
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_STOP;

const SESSION_NAME: &str = "rustinel-etw-file-rundown";
const MAX_ENTRIES: usize = 65_536;
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;
const MAX_CAPTURE_MIB: u32 = 64;

#[derive(Default)]
struct Snapshot {
    entries: HashMap<u64, (String, i64)>,
    records: u64,
    decode_failed: u64,
    path_bytes: usize,
    overflow: bool,
}

impl Snapshot {
    fn insert(&mut self, key: u64, path: String, at: i64) {
        if self.overflow {
            return;
        }
        let previous = self.entries.get(&key).map_or(0, |(path, _)| path.len());
        let bytes = self.path_bytes - previous + path.len();
        if bytes > MAX_PATH_BYTES || (self.entries.len() == MAX_ENTRIES && previous == 0) {
            self.overflow = true;
            return;
        }
        self.path_bytes = bytes;
        self.entries.insert(key, (path, at));
    }

    fn validate(&self, lost: u64) -> Result<()> {
        if lost != 0 || self.decode_failed != 0 || self.overflow || self.entries.is_empty() {
            bail!("Incomplete file rundown: {} lost, {} decode failures, capacity exceeded: {}, {} entries",
                lost, self.decode_failed, self.overflow, self.entries.len());
        }
        Ok(())
    }
}

fn collect(
    snapshot: Arc<Mutex<Snapshot>>,
    lost: &mut (u64, u64),
    properties: TraceProperties,
) -> Result<()> {
    // ferrisetw's DISK_FILE_IO_PROVIDER registers the DiskIo GUID. The flag
    // enables FileIo_Name, whose callback must use the FileIo GUID instead.
    let kernel = KernelProvider::new(FILE_IO_PROVIDER.guid, 0x200); // EVENT_TRACE_FLAG_DISK_FILE_IO
    let decode = move |record: &ferrisetw::EventRecord,
                       locator: &ferrisetw::schema_locator::SchemaLocator| {
        if record.provider_id() != FILE_IO_PROVIDER.guid {
            return;
        }
        if record.opcode() != 36 {
            return;
        } // FileRundown, not live names
        let mut snapshot = snapshot.lock().unwrap_or_else(|e| e.into_inner());
        snapshot.records += 1;
        let decoded = locator.event_schema(record).ok().and_then(|schema| {
            let parser = Parser::create(record, &schema);
            Some((
                try_get_uint_as_u64(&parser, "FileObject")?,
                try_get_string(&parser, "FileName")?,
            ))
        });
        match decoded {
            Some((key, path)) if key != 0 => snapshot.insert(key, path, record.raw_timestamp()),
            _ => snapshot.decode_failed += 1,
        }
    };
    let provider = Provider::kernel(&kernel).build();
    let directory = tempfile::Builder::new()
        .prefix("rustinel-file-rundown-")
        .tempdir()?;
    let path = directory.path().join("names.etl");
    // Do not stop a pre-existing logger: start failure is an optional-feature
    // failure, and must not interfere with another collector's ownership.
    let (trace, handle) = classic::build_session(SESSION_NAME, properties, [provider])
        .set_etl_dump_file(DumpFileParams {
            file_path: path.clone(),
            file_logging_mode: DumpFileLoggingMode::EVENT_TRACE_FILE_MODE_SEQUENTIAL,
            max_size: Some(MAX_CAPTURE_MIB),
        })
        .start()
        .map_err(|e| anyhow::anyhow!("File rundown start failed: {e:?}"))?;
    let worker = std::thread::Builder::new()
        .name("etw-file-rundown".into())
        .spawn(move || KernelTrace::process_from_handle(handle))
        .context("File rundown consumer could not start")?;
    // STOP emits rundown and drains its buffers to the already running consumer.
    // Retain the trace (and callbacks) until that consumer has finished.
    let stopped =
        super::super::loss::query_with_buffer_loss(SESSION_NAME, EVENT_TRACE_CONTROL_STOP);
    let trace = if stopped.is_err() {
        drop(trace);
        None
    } else {
        Some(trace)
    };
    let processed = worker
        .join()
        .map_err(|_| anyhow::anyhow!("File rundown consumer panicked"));
    drop(trace);
    *lost = stopped?;
    processed?.map_err(|e| anyhow::anyhow!("File rundown consumer failed: {e:?}"))?;
    // Real-time-only STOP statistics can precede the rundown's loss. The
    // finalized ETL header includes the burst and is checked independently.
    if std::fs::metadata(&path)?.len() >= u64::from(MAX_CAPTURE_MIB) * 1024 * 1024 {
        bail!("File rundown reached its capture size limit");
    }
    let final_loss = final_file_loss(&path)?;
    lost.0 = lost.0.max(final_loss.0);
    lost.1 = lost.1.max(final_loss.1);
    if lost.0 != 0 || lost.1 != 0 {
        bail!("File rundown lost {} events and {} buffers", lost.0, lost.1);
    }
    let (mut file, _) = FileTrace::new(path, decode)
        .start()
        .map_err(|e| anyhow::anyhow!("File rundown ETL could not open: {e:?}"))?;
    file.process()
        .map_err(|e| anyhow::anyhow!("File rundown ETL decode failed: {e:?}"))?;
    drop(file);
    directory
        .close()
        .context("File rundown temporary capture cleanup failed")?;
    Ok(())
}

fn final_file_loss(path: &std::path::Path) -> Result<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PWSTR,
        Win32::System::Diagnostics::Etw::{
            CloseTrace, OpenTraceW, EVENT_TRACE_LOGFILEW, PROCESS_TRACE_MODE_EVENT_RECORD,
        },
    };
    let mut name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LogFileName: PWSTR(name.as_mut_ptr()),
        ..Default::default()
    };
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    // SAFETY: the terminated name and logfile remain alive through OpenTrace.
    // No callbacks are registered; this handle only reads the finalized header.
    let handle = unsafe { OpenTraceW(&mut logfile) };
    if handle.Value == u64::MAX {
        bail!("Could not read file rundown ETL loss header");
    }
    // SAFETY: OpenTrace populated the documented statistics variant of the header.
    let lost = (
        u64::from(unsafe { logfile.LogfileHeader.Anonymous2.Anonymous.EventsLost }),
        u64::from(logfile.LogfileHeader.BuffersLost),
    );
    // SAFETY: OpenTrace returned a valid handle owned solely by this function.
    unsafe { CloseTrace(handle) }
        .ok()
        .context("Could not close file rundown ETL header")?;
    Ok(lost)
}

fn properties() -> TraceProperties {
    TraceProperties {
        buffer_size: 64,
        min_buffer: 128,
        max_buffer: 128,
        flush_timer: Duration::from_secs(1),
        ..Default::default()
    }
}

pub(super) fn seed(state: &EtwState) {
    let started = Instant::now();
    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
    let mut lost = (0, 0);
    let result = collect(Arc::clone(&snapshot), &mut lost, properties());
    let mut snapshot = snapshot.lock().unwrap_or_else(|e| e.into_inner());
    let result = result.and_then(|()| snapshot.validate(lost.0.saturating_add(lost.1)));
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let seeded = if result.is_ok() {
        snapshot.entries.len()
    } else {
        0
    };
    WINDOWS_FILE_ATTRIBUTION.set_rundown(FileRundownSnapshot {
        seeded,
        records: snapshot.records,
        decode_failed: snapshot.decode_failed,
        events_lost: lost.0,
        buffers_lost: lost.1,
        duration_ms,
        path_bytes: snapshot.path_bytes,
        index_capacity: snapshot.entries.capacity(),
        rejected: result.is_err(),
    });
    match result {
        Ok(()) => {
            state.paths().seed(std::mem::take(&mut snapshot.entries));
            tracing::info!(
                seeded,
                duration_ms,
                path_bytes = snapshot.path_bytes,
                "File rundown seeded pre-existing name keys"
            );
        }
        Err(error) => tracing::warn!(%error, duration_ms,
            "File rundown rejected; retaining live-only file attribution"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduce the buffer tuning on an idle elevated Windows lab desktop.
    #[test]
    #[ignore = "requires administrator rights and runs repeated kernel rundowns"]
    fn native_buffer_sweep() {
        for buffers in [32, 64, 80, 96, 112, 128] {
            for _ in 0..3 {
                let snapshot = Arc::new(Mutex::new(Snapshot::default()));
                let mut lost = (0, 0);
                let started = Instant::now();
                let result = collect(
                    Arc::clone(&snapshot),
                    &mut lost,
                    TraceProperties {
                        min_buffer: buffers,
                        max_buffer: buffers,
                        ..properties()
                    },
                );
                let snapshot = snapshot.lock().unwrap();
                println!("buffers={buffers} lost={lost:?} entries={} path_bytes={} capacity={} ms={} result={result:?}",
                    snapshot.entries.len(), snapshot.path_bytes, snapshot.entries.capacity(), started.elapsed().as_millis());
            }
        }
    }

    #[test]
    #[ignore = "requires administrator rights; deliberately exhausts a tiny rundown pool"]
    fn native_lossy_rundown_is_rejected() {
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let mut lost = (0, 0);
        let result = collect(
            Arc::clone(&snapshot),
            &mut lost,
            TraceProperties {
                buffer_size: 16,
                min_buffer: 2,
                max_buffer: 2,
                ..properties()
            },
        );
        assert!(result.is_err());
        assert!(
            lost.0 > 0 || lost.1 > 0,
            "expected kernel loss, got {result:?}"
        );
        assert!(
            snapshot.lock().unwrap().entries.is_empty(),
            "lossy capture must not be decoded into seed entries"
        );
    }

    #[test]
    fn partial_snapshots_are_never_accepted() {
        let mut snapshot = Snapshot::default();
        assert!(snapshot.validate(0).is_err());
        snapshot.insert(1, "C:\\a".into(), 10);
        assert!(snapshot.validate(0).is_ok());
        assert!(snapshot.validate(1).is_err());
        snapshot.decode_failed = 1;
        assert!(snapshot.validate(0).is_err());
    }

    #[test]
    fn capacity_rejects_instead_of_evicting_snapshot_entries() {
        let mut snapshot = Snapshot::default();
        for key in 1..=MAX_ENTRIES as u64 {
            snapshot.insert(key, "a".into(), 10);
        }
        assert!(snapshot.validate(0).is_ok());
        snapshot.insert(MAX_ENTRIES as u64 + 1, "a".into(), 10);
        assert_eq!(snapshot.entries.len(), MAX_ENTRIES);
        assert!(snapshot.validate(0).is_err());
    }

    #[test]
    fn path_bytes_are_bounded_and_replacements_are_accounted() {
        let mut snapshot = Snapshot::default();
        snapshot.insert(1, "long name".into(), 10);
        snapshot.insert(1, "short".into(), 11);
        assert_eq!(snapshot.path_bytes, 5);
        snapshot.insert(2, "x".repeat(MAX_PATH_BYTES), 12);
        assert_eq!(snapshot.entries.len(), 1);
        assert!(snapshot.validate(0).is_err());
    }
}
