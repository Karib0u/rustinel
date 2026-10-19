//! Fixture recording: `RUSTINEL_ESF_RECORD=<file>` appends one JSON object per
//! mapped Endpoint Security message, holding everything the decoders read.
//!
//! This is a developer tool for building the fixtures under
//! `tests/fixtures/esf`; see `docs/development.md`. It is off unless the
//! variable is set, and capped by `RUSTINEL_ESF_RECORD_MAX` (default 5000) so a
//! forgotten variable cannot fill a disk.
//!
//! Recording only happens while a file named `<file>.on` exists, so a workload
//! can bracket the messages it wants out of the machine's background noise.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use super::view::{EsMessage, EsRecord};

const DEFAULT_MAX_RECORDS: usize = 5000;

struct Recorder {
    gate: PathBuf,
    /// Milliseconds since `started` at which the gate was last checked, plus
    /// one; zero means never.
    checked_at: AtomicU64,
    open: AtomicBool,
    started: Instant,
    file: Mutex<File>,
    written: AtomicUsize,
    max: usize,
}

impl Recorder {
    /// Whether the gate file exists, looked up at most every 50 ms.
    fn gate_open(&self) -> bool {
        let now = self.started.elapsed().as_millis() as u64 + 1;
        let last = self.checked_at.load(Ordering::Relaxed);
        if last == 0 || now.saturating_sub(last) >= 50 {
            self.checked_at.store(now, Ordering::Relaxed);
            self.open.store(self.gate.exists(), Ordering::Relaxed);
        }
        self.open.load(Ordering::Relaxed)
    }
}

fn recorder() -> Option<&'static Recorder> {
    static RECORDER: OnceLock<Option<Recorder>> = OnceLock::new();
    RECORDER
        .get_or_init(|| {
            let path = std::env::var_os("RUSTINEL_ESF_RECORD")?;
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|err| {
                    tracing::warn!("ESF recording disabled, cannot open {path:?}: {err}")
                })
                .ok()?;
            let max = std::env::var("RUSTINEL_ESF_RECORD_MAX")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT_MAX_RECORDS);
            tracing::warn!(
                "Recording Endpoint Security messages to {path:?} (max {max}); \
                 this is a developer tool and captures command lines and paths"
            );
            let gate = PathBuf::from(format!("{}.on", path.to_string_lossy()));
            Some(Recorder {
                gate,
                checked_at: AtomicU64::new(0),
                open: AtomicBool::new(false),
                started: Instant::now(),
                file: Mutex::new(file),
                written: AtomicUsize::new(0),
                max,
            })
        })
        .as_ref()
}

/// Append `msg` to the recording when recording is on and its gate is open.
pub(super) fn record(msg: &impl EsMessage) {
    let Some(recorder) = recorder() else { return };
    if !recorder.gate_open() || recorder.written.load(Ordering::Relaxed) >= recorder.max {
        return;
    }
    let Some(record) = EsRecord::capture(msg) else {
        return;
    };
    let Ok(line) = serde_json::to_string(&record) else {
        return;
    };
    recorder.written.fetch_add(1, Ordering::Relaxed);
    let mut file = recorder.file.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(file, "{line}");
}
