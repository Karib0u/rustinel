//! Written-file targets: which file events are inspected, the settle table
//! that debounces them, and the extension and magic-byte qualification gate.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::job::ArtifactJob;
use super::target::{ArtifactTarget, ExpectedIdentity};
use crate::models::{CanonicalEvent, FileEventFields, FileObjectIdentity};
use crate::sensor::{Platform, SensorAction};

/// Written files get their own queue and I/O slots so file churn cannot shed
/// images. They need room for a burst's settle window.
pub(super) const WRITTEN_FILE_QUEUE_CAPACITY: usize = 8192;
/// Bound filesystem lookups per new target under settle-table pressure.
const WRITTEN_FILE_RECLAIM_BATCH: usize = 64;
/// File create and modify events can arrive before the writer has finished.
/// Delay their background resolution so short writes settle before opening.
pub(super) const WRITTEN_FILE_SETTLE_DELAY: Duration = Duration::from_millis(250);
const WRITTEN_FILE_MAGIC_BYTES: usize = 16;

/// Chooses which canonical file events become written-file artifact targets.
///
/// The selector rejects events using only sensor-provided facts. Settling,
/// extension, magic-byte, and size gates run on selected targets in the
/// resolver, together with identity validation, allowlists, and caching.
pub(crate) type WrittenFileSelector =
    Arc<dyn Fn(&CanonicalEvent, &FileEventFields) -> bool + Send + Sync>;

/// Select complete canonical file paths for written-file content inspection.
/// Content qualification happens on the resolver's identity-validated handle.
pub(crate) fn written_file_scan_selector() -> WrittenFileSelector {
    // An unknown extension can still qualify by magic. File events carry no
    // content or size, so narrowing extensions here would lose those scans.
    Arc::new(|event, fields| {
        fields.path_truncated.is_none()
            && fields
                .target_filename
                .as_ref()
                .is_some_and(|path| !path.is_empty())
            && !is_windows_cache_flush(event)
    })
}

/// The Windows System process (PID 4) writing to an existing file: the cache
/// manager's lazy writer or the mapped page writer flushing pages that a
/// process wrote earlier, typically a few hundred milliseconds later. That
/// process's own write already queued the scan, so rescanning would repeat
/// the alert and credit `System` with it. Content written only through a
/// mapped view is still read through the cache on the creating event.
fn is_windows_cache_flush(event: &CanonicalEvent) -> bool {
    const WINDOWS_SYSTEM_PID: u32 = 4;
    event.normalized().platform == Platform::Windows
        && event.action == SensorAction::Modify
        && event.pid == Some(WINDOWS_SYSTEM_PID)
}

/// A bounded debounce table with one deadline entry per path and object.
/// Replacing a write removes its old deadline, so repeated writes cannot
/// grow the deadline queue beyond the table's capacity.
#[derive(Default)]
pub(super) struct WrittenFileSettler {
    by_target: HashMap<(PathBuf, Option<ExpectedIdentity>), (Instant, u64)>,
    by_deadline: BTreeMap<(Instant, u64), ArtifactJob>,
    /// The latest object measured on arrival for each pending path, so writes
    /// to it need no further open. See [`super::target::measures_identity_on_arrival`].
    pub(super) measured: HashMap<PathBuf, FileObjectIdentity>,
    sequence: u64,
    /// Resume pressure checks after the last inspected deadline, wrapping at
    /// the end so live early arrivals cannot hide vanished later entries.
    reclaim_cursor: Option<(Instant, u64)>,
}

impl WrittenFileSettler {
    pub(super) fn is_full_for(&self, target: &ArtifactTarget) -> bool {
        self.by_target.len() >= WRITTEN_FILE_QUEUE_CAPACITY
            && !self
                .by_target
                .contains_key(&(target.path.clone(), target.expected.clone()))
    }

    /// Reclaim only paths known to be absent. Access errors keep the job for
    /// its normal identity-validated resolution. Checks read no file content.
    pub(super) fn reclaim_missing(
        &mut self,
        mut exists: impl FnMut(&Path) -> io::Result<bool>,
    ) -> usize {
        use std::ops::Bound::{Excluded, Unbounded};

        let checks = WRITTEN_FILE_RECLAIM_BATCH.min(self.by_deadline.len());
        let entries: Vec<_> = match self.reclaim_cursor {
            Some(cursor) => self
                .by_deadline
                .range((Excluded(cursor), Unbounded))
                .chain(self.by_deadline.range(..=cursor))
                .take(checks)
                .map(|(deadline, job)| (*deadline, matches!(exists(&job.target.path), Ok(false))))
                .collect(),
            None => self
                .by_deadline
                .iter()
                .take(checks)
                .map(|(deadline, job)| (*deadline, matches!(exists(&job.target.path), Ok(false))))
                .collect(),
        };
        if let Some((deadline, _)) = entries.last() {
            self.reclaim_cursor = Some(*deadline);
        }
        let mut reclaimed = 0;
        for (deadline, missing) in entries {
            if missing {
                self.remove(deadline);
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Returns whether an earlier write was coalesced, or the rejected job.
    pub(super) fn insert(&mut self, job: ArtifactJob) -> Result<bool, Box<ArtifactJob>> {
        let key = (job.target.path.clone(), job.target.expected.clone());
        let previous = self.by_target.get(&key).copied();
        if previous.is_none() && self.by_target.len() >= WRITTEN_FILE_QUEUE_CAPACITY {
            return Err(Box::new(job));
        }
        if let Some(deadline) = previous {
            self.by_deadline.remove(&deadline);
        }
        let ready_at = job.enqueued_at + WRITTEN_FILE_SETTLE_DELAY;
        let deadline = (ready_at, self.sequence);
        self.sequence = self.sequence.wrapping_add(1);
        self.by_target.insert(key, deadline);
        if job.target.measured_on_arrival {
            if let Some(ExpectedIdentity::Object(object)) = job.target.expected {
                self.measured.insert(job.target.path.clone(), object);
            }
        }
        self.by_deadline.insert(deadline, job);
        Ok(previous.is_some())
    }

    /// The object a pending job for `path` was bound to on arrival.
    pub(super) fn measured_object(&self, path: &Path) -> Option<FileObjectIdentity> {
        self.measured.get(path).copied()
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.by_deadline.first_key_value().map(|(key, _)| key.0)
    }

    pub(super) fn pop_ready(&mut self, now: Instant) -> Option<ArtifactJob> {
        if self.next_deadline()? > now {
            return None;
        }
        let deadline = *self.by_deadline.first_key_value()?.0;
        self.remove(deadline)
    }

    pub(super) fn remove(&mut self, deadline: (Instant, u64)) -> Option<ArtifactJob> {
        let job = self.by_deadline.remove(&deadline)?;
        self.by_target
            .remove(&(job.target.path.clone(), job.target.expected.clone()));
        if let Some(ExpectedIdentity::Object(object)) = &job.target.expected {
            if self.measured.get(&job.target.path) == Some(object) {
                self.measured.remove(&job.target.path);
            }
        }
        Some(job)
    }
}

pub(super) fn written_file_qualifies(path: &Path, file: &mut File, size: u64) -> io::Result<bool> {
    if size == 0 {
        return Ok(false);
    }
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(qualifying_written_file_extension)
    {
        return Ok(true);
    }

    let mut magic = [0u8; WRITTEN_FILE_MAGIC_BYTES];
    let read = file.read(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(qualifying_written_file_magic(&magic[..read]))
}

fn qualifying_written_file_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "com"
            | "cpl"
            | "msi"
            | "msp"
            | "ps1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "wsh"
            | "hta"
            | "jar"
            | "class"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "py"
            | "pyw"
            | "pl"
            | "rb"
            | "php"
            | "elf"
            | "so"
            | "dylib"
            | "dmg"
            | "pkg"
            | "deb"
            | "rpm"
            | "apk"
            | "zip"
            | "rar"
            | "7z"
            | "gz"
            | "bz2"
            | "xz"
            | "tar"
            | "cab"
            | "iso"
            | "img"
            | "pdf"
            | "doc"
            | "docx"
            | "docm"
            | "xls"
            | "xlsx"
            | "xlsm"
            | "ppt"
            | "pptx"
            | "pptm"
            | "rtf"
            | "lnk"
    )
}

fn qualifying_written_file_magic(bytes: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"MZ",
        b"\x7fELF",
        b"#!",
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"Rar!\x1a\x07",
        b"7z\xbc\xaf\x27\x1c",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"%PDF-",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ];
    PREFIXES.iter().any(|prefix| bytes.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{self};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::artifact::target::*;
    use crate::artifact::test_support::*;
    use crate::models::{CanonicalEvent, EventFields, FileObjectIdentity};
    use crate::sensor::{Platform, SensorAction};

    #[test]
    fn arrival_measured_object_lives_as_long_as_its_pending_job() {
        let now = Instant::now();
        let mut settling = WrittenFileSettler::default();
        let measured = |inode| {
            let mut job = settling_job("a", inode, now);
            job.target.measured_on_arrival = true;
            job
        };
        let mut sensor_measured = settling_job("b", 9, now);
        sensor_measured.target.measured_on_arrival = false;
        assert!(settling.insert(sensor_measured).is_ok());
        assert_eq!(settling.measured_object(Path::new("b")), None);

        assert!(settling.insert(measured(1)).is_ok());
        assert_eq!(settling.measured_object(Path::new("a")).unwrap().inode, 1);
        // A replacement measured later is what the next write reuses.
        assert!(settling.insert(measured(2)).is_ok());
        assert_eq!(settling.measured_object(Path::new("a")).unwrap().inode, 2);

        let ready = now + WRITTEN_FILE_SETTLE_DELAY;
        while settling.pop_ready(ready).is_some() {}
        assert_eq!(settling.measured_object(Path::new("a")), None);
        assert!(settling.measured.is_empty());
    }

    #[test]
    fn settle_deadlines_refresh_without_stale_entries_and_keep_object_identity() {
        let now = Instant::now();
        let mut settling = WrittenFileSettler::default();
        assert!(matches!(
            settling.insert(settling_job("a", 1, now)),
            Ok(false)
        ));
        assert!(matches!(
            settling.insert(settling_job("b", 2, now)),
            Ok(false)
        ));
        for offset in 1..1000 {
            assert!(matches!(
                settling.insert(settling_job("a", 1, now + Duration::from_micros(offset))),
                Ok(true)
            ));
        }
        assert_eq!(settling.by_target.len(), 2);
        assert_eq!(settling.by_deadline.len(), 2);
        // A replacement at the same path must not coalesce with the old object.
        assert!(matches!(
            settling.insert(settling_job("a", 3, now)),
            Ok(false)
        ));
        assert!(settling.pop_ready(now).is_none());
        let ready = now + WRITTEN_FILE_SETTLE_DELAY;
        assert_eq!(
            settling.pop_ready(ready).unwrap().target.path,
            Path::new("b")
        );
        assert_eq!(
            settling.pop_ready(ready).unwrap().target.expected,
            Some(ExpectedIdentity::Object(FileObjectIdentity {
                device: 1,
                inode: 3
            }))
        );
        assert!(settling.pop_ready(ready).is_none());
        assert_eq!(
            settling
                .pop_ready(ready + Duration::from_millis(1))
                .unwrap()
                .target
                .path,
            Path::new("a")
        );
        assert!(settling.by_target.is_empty());
        assert!(settling.by_deadline.is_empty());
    }

    #[test]
    fn full_settle_table_still_coalesces_existing_paths() {
        let now = Instant::now();
        let mut settling = WrittenFileSettler::default();
        for inode in 0..WRITTEN_FILE_QUEUE_CAPACITY as u64 {
            assert!(settling
                .insert(settling_job(&format!("file-{inode}"), inode, now))
                .is_ok());
        }
        assert!(settling.insert(settling_job("overflow", 999, now)).is_err());
        assert!(matches!(
            settling.insert(settling_job("file-0", 0, now + Duration::from_millis(1))),
            Ok(true)
        ));
        assert_eq!(settling.by_target.len(), WRITTEN_FILE_QUEUE_CAPACITY);
        assert_eq!(settling.by_deadline.len(), WRITTEN_FILE_QUEUE_CAPACITY);
    }

    #[test]
    fn pressure_reclaims_renamed_and_deleted_paths_without_displacing_survivors() {
        let temp = tempfile::tempdir().unwrap();
        let deleted = temp.path().join("deleted.py");
        let renamed = temp.path().join("renamed.py");
        let survivor = temp.path().join("survivor.py");
        for path in [&deleted, &renamed, &survivor] {
            std::fs::write(path, b"content").unwrap();
        }
        let now = Instant::now();
        let mut settling = WrittenFileSettler::default();
        for (inode, path) in [&deleted, &renamed].into_iter().enumerate() {
            let mut job = settling_job(path.to_str().unwrap(), inode as u64, now);
            job.target.measured_on_arrival = true;
            assert!(settling.insert(job).is_ok());
        }
        for inode in 2..WRITTEN_FILE_QUEUE_CAPACITY as u64 {
            assert!(settling
                .insert(settling_job(survivor.to_str().unwrap(), inode, now))
                .is_ok());
        }
        std::fs::remove_file(&deleted).unwrap();
        std::fs::rename(&renamed, temp.path().join("moved.py")).unwrap();
        let payload = settling_job("payload.py", 99, now);
        assert!(settling.is_full_for(&payload.target));

        assert_eq!(settling.reclaim_missing(Path::try_exists), 2);
        assert_eq!(settling.measured_object(&deleted), None);
        assert_eq!(settling.measured_object(&renamed), None);
        assert!(!settling.is_full_for(&payload.target));
        assert!(settling.insert(payload).is_ok());
        assert_eq!(settling.by_target.len(), WRITTEN_FILE_QUEUE_CAPACITY - 1);
        assert_eq!(settling.by_deadline.len(), settling.by_target.len());
        let ready = now + WRITTEN_FILE_SETTLE_DELAY;
        let mut resolved = 0;
        while let Some(job) = settling.pop_ready(ready) {
            assert!(job.target.path == survivor || job.target.path == Path::new("payload.py"));
            resolved += 1;
        }
        assert_eq!(resolved, WRITTEN_FILE_QUEUE_CAPACITY - 1);
        assert!(settling.by_target.is_empty());
        assert!(settling.measured.is_empty());
    }

    #[test]
    fn pressure_checks_are_bounded_and_rotate_past_survivors_and_access_errors() {
        let now = Instant::now();
        let mut settling = WrittenFileSettler::default();
        for inode in 0..WRITTEN_FILE_QUEUE_CAPACITY as u64 {
            assert!(settling
                .insert(settling_job(&format!("file-{inode}"), inode, now))
                .is_ok());
        }
        let missing = PathBuf::from(format!("file-{}", WRITTEN_FILE_QUEUE_CAPACITY - 1));
        let rounds = WRITTEN_FILE_QUEUE_CAPACITY / WRITTEN_FILE_RECLAIM_BATCH;
        for round in 0..rounds {
            let mut checks = 0;
            let reclaimed = settling.reclaim_missing(|path| {
                checks += 1;
                if path == Path::new("file-0") {
                    Err(io::Error::from(io::ErrorKind::PermissionDenied))
                } else {
                    Ok(path != missing)
                }
            });
            assert_eq!(checks, WRITTEN_FILE_RECLAIM_BATCH);
            assert_eq!(reclaimed, usize::from(round == rounds - 1));
        }
        assert_eq!(settling.by_target.len(), WRITTEN_FILE_QUEUE_CAPACITY - 1);
        assert_eq!(settling.by_deadline.len(), settling.by_target.len());
        // The next batch wraps back to the oldest entry rather than repeatedly
        // inspecting the end of the table. A newly vanished survivor is found.
        assert_eq!(
            settling.reclaim_missing(|path| Ok(path != Path::new("file-0"))),
            1
        );
        assert!(settling.insert(settling_job("payload.py", 99, now)).is_ok());
        assert_eq!(settling.by_target.len(), WRITTEN_FILE_QUEUE_CAPACITY - 1);
    }

    #[test]
    fn written_file_selector_rejects_truncated_paths() {
        let selector = written_file_scan_selector();
        let complete = file_event(Path::new("/tmp/payload.exe"), FILE_CREATE_OPCODE, None);
        let EventFields::FileEvent(complete_fields) = &complete.normalized().fields else {
            unreachable!();
        };
        assert!(selector(&complete, complete_fields));

        let mut truncated = complete.clone().into_normalized();
        let EventFields::FileEvent(fields) = &mut truncated.fields else {
            unreachable!();
        };
        fields.path_truncated = Some("target".into());
        let truncated = CanonicalEvent::from_normalized(truncated);
        let EventFields::FileEvent(truncated_fields) = &truncated.normalized().fields else {
            unreachable!();
        };
        assert!(!selector(&truncated, truncated_fields));
    }

    #[test]
    fn written_file_selector_skips_windows_cache_flushes() {
        let selector = written_file_scan_selector();
        let select = |platform: Platform, action: SensorAction, pid: u32| {
            let mut normalized =
                file_event(Path::new(r"C:\drop\payload.py"), FILE_CREATE_OPCODE, None)
                    .into_normalized();
            normalized.platform = platform;
            let mut event = CanonicalEvent::from_normalized(normalized);
            event.action = action;
            event.pid = Some(pid);
            let EventFields::FileEvent(fields) = &event.normalized().fields else {
                unreachable!();
            };
            selector(&event, fields)
        };
        assert!(!select(Platform::Windows, SensorAction::Modify, 4));
        assert!(
            select(Platform::Windows, SensorAction::Create, 4),
            "a System create is new content"
        );
        assert!(select(Platform::Windows, SensorAction::Modify, 3368));
        assert!(select(Platform::Linux, SensorAction::Modify, 4));
    }

    #[test]
    fn written_file_gate_accepts_extension_or_magic_but_not_partial_content() {
        let temp = tempfile::tempdir().unwrap();

        let extension = temp.path().join("payload.EXE");
        std::fs::write(&extension, b"plain bytes").unwrap();
        let mut extension_file = File::open(&extension).unwrap();
        let extension_size = extension_file.metadata().unwrap().len();
        assert!(written_file_qualifies(&extension, &mut extension_file, extension_size).unwrap());

        let magic = temp.path().join("payload.unknown");
        std::fs::write(&magic, b"\x7fELFmore bytes").unwrap();
        let mut magic_file = File::open(&magic).unwrap();
        let magic_size = magic_file.metadata().unwrap().len();
        assert!(written_file_qualifies(&magic, &mut magic_file, magic_size).unwrap());

        for (name, bytes) in [("empty", &b""[..]), ("partial", &b"M"[..])] {
            let path = temp.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            let mut file = File::open(&path).unwrap();
            let size = file.metadata().unwrap().len();
            assert!(!written_file_qualifies(&path, &mut file, size).unwrap());
        }
    }

    #[test]
    fn file_events_become_targets_only_through_the_selector() {
        let path = Path::new("/tmp/dropped.bin");
        let created = file_event(path, FILE_CREATE_OPCODE, None);
        assert!(ArtifactTarget::from_event(&created, None).is_none());
        let reject: WrittenFileSelector = Arc::new(|_, _| false);
        assert!(ArtifactTarget::from_event(&created, Some(&reject)).is_none());

        let target = ArtifactTarget::from_event(&created, Some(&select_all())).unwrap();
        assert_eq!(target.kind, ArtifactKind::WrittenFile);
        assert_eq!(target.display_path, "/tmp/dropped.bin");
        assert_eq!(target.pid, 43);

        let deleted = file_event(path, FILE_DELETE_OPCODE, None);
        assert!(ArtifactTarget::from_event(&deleted, Some(&select_all())).is_none());
    }
}
