//! Linux authentication log source: follows the systemd journal.
//!
//! The reader runs `journalctl --follow --output=json` restricted to the
//! `auth` and `authpriv` syslog facilities, and hands every line to
//! [`crate::sensor::auth_log`], which applies the sender trust gate and the
//! parsers. journalctl is used rather than linking `libsystemd`, which the
//! static musl build cannot do; its JSON output is a stable interface.
//!
//! Resume follows the Windows Event Log model. The cursor of the last record
//! read is saved beside the logs and the next start continues after it. A
//! first start, or a start whose saved cursor cannot be read, begins at the
//! journal's tail rather than replaying history. Before resuming, the oldest
//! record still in the journal is compared with the saved cursor, and a cursor
//! that retention has already passed is counted as a downtime loss of unknown
//! size, never inferred from sequence gaps: the facility filter skips numbers.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::sensor::auth_log::{self, JournalEntry, AUTH_FACILITIES};
use crate::sensor::{RawEvent, Sensor};
use crate::telemetry::JournalHealth;
use crate::utils::LogRateLimiter;

/// Where journalctl may live. Only root-owned files that nobody else can
/// write are run.
const JOURNALCTL: [&str; 2] = ["/usr/bin/journalctl", "/bin/journalctl"];
/// The cursor file inside the checkpoint directory.
const CURSOR_FILE: &str = "auth.cursor";
/// How often a moving cursor is written to disk.
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(1);
const RESTART_MIN: Duration = Duration::from_secs(1);
const RESTART_MAX: Duration = Duration::from_secs(60);
/// A reader that ran this long before exiting is not in a crash loop.
const HEALTHY_RUN: Duration = Duration::from_secs(60);
const WAIT_SLICE: Duration = Duration::from_millis(200);
/// Bytes of journalctl's stderr kept for `last_error`.
const STDERR_TAIL: usize = 2048;

pub struct JournalAuthSensor {
    health: Arc<JournalHealth>,
    directory: PathBuf,
    shutdown: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl JournalAuthSensor {
    /// A reader that keeps its cursor in `directory`.
    pub fn new(host: &crate::state::HostState, directory: PathBuf) -> Self {
        Self {
            health: Arc::clone(&host.extension::<super::LinuxHostExtension>().journal),
            directory,
            shutdown: Arc::new(AtomicBool::new(false)),
            child: Arc::new(Mutex::new(None)),
            worker: Mutex::new(None),
        }
    }

    /// Wait for the reader to stop and write its last cursor.
    pub fn join(&self) {
        let worker = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }
}

impl Sensor for JournalAuthSensor {
    fn start(&self, tx: Sender<RawEvent>) -> Result<()> {
        let journalctl = find_journalctl()?;
        probe(&journalctl)?;
        self.shutdown.store(false, Ordering::SeqCst);
        self.health.update(|health| health.active = false);
        let reader = Reader {
            journalctl,
            checkpoint: self.directory.join(CURSOR_FILE),
            tx,
            shutdown: Arc::clone(&self.shutdown),
            child: Arc::clone(&self.child),
            health: Arc::clone(&self.health),
            decode_warnings: LogRateLimiter::new(Duration::from_secs(60)),
            users: UserNames::default(),
        };
        let worker = thread::Builder::new()
            .name("journal-auth".into())
            .spawn(move || reader.run())
            .context("failed to spawn the auth journal reader")?;
        *self.worker.lock().unwrap_or_else(|e| e.into_inner()) = Some(worker);
        Ok(())
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Killing journalctl closes its stdout, which ends the blocking read.
        if let Some(child) = self
            .child
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            let _ = child.kill();
        }
    }
}

fn find_journalctl() -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    for candidate in JOURNALCTL {
        let Ok(metadata) = fs::metadata(candidate) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("{candidate} is not owned by root or is writable by other users");
        }
        return Ok(PathBuf::from(candidate));
    }
    bail!("journalctl was not found; this host does not run systemd-journald")
}

fn journalctl_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    // A localized error message is no use in `last_error`.
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null());
    command
}

/// Fail the start, instead of a silent reader, when the journal is unreadable.
fn probe(path: &Path) -> Result<()> {
    let output = journalctl_command(path)
        .args(["--quiet", "--no-pager", "--lines=0", "--output=json"])
        .output()
        .with_context(|| format!("failed to run {}", path.display()))?;
    if !output.status.success() {
        bail!(
            "{} cannot read the journal ({}): {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Why one journalctl run ended.
enum RunEnd {
    Shutdown,
    ChannelClosed,
    Exited(String),
}

struct Reader {
    journalctl: PathBuf,
    checkpoint: PathBuf,
    tx: Sender<RawEvent>,
    shutdown: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    health: Arc<JournalHealth>,
    decode_warnings: LogRateLimiter,
    users: UserNames,
}

/// Account names by UID, through NSS, cached for the reader's lifetime.
///
/// Only records whose sender exited before journald read its capabilities
/// need a lookup, so the cache stays small; it is cleared when full rather
/// than grown.
#[derive(Default)]
struct UserNames {
    cache: std::cell::RefCell<std::collections::HashMap<u32, Option<String>>>,
}

impl UserNames {
    const CAPACITY: usize = 1024;

    fn name(&self, uid: u32) -> Option<String> {
        let mut cache = self.cache.borrow_mut();
        if let Some(name) = cache.get(&uid) {
            return name.clone();
        }
        if cache.len() >= Self::CAPACITY {
            cache.clear();
        }
        let name = lookup_user_name(uid);
        cache.insert(uid, name.clone());
        name
    }
}

fn lookup_user_name(uid: u32) -> Option<String> {
    let mut buffer = vec![0u8; 4096];
    loop {
        // SAFETY: `passwd` is plain old data, for which all zeroes is valid.
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `passwd` and `result` are plain out-parameters, and
        // `buffer` is writable for its full length, which is passed with it.
        // On success `result` points at `passwd`, whose strings live in
        // `buffer`, which outlives their use below.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || result.is_null() || passwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: `pw_name` is a NUL-terminated string inside `buffer`.
        let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) };
        return name.to_str().ok().map(str::to_string);
    }
}

impl Reader {
    fn run(mut self) {
        let mut delay = RESTART_MIN;
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }
            let cursor = self.load_cursor();
            if let Some(cursor) = &cursor {
                self.check_retention(cursor);
            }
            let started = Instant::now();
            let reason = match self.follow(cursor.as_deref()) {
                Ok(RunEnd::Shutdown) | Ok(RunEnd::ChannelClosed) => break,
                Ok(RunEnd::Exited(reason)) => reason,
                Err(err) => format!("{err:#}"),
            };
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }
            self.health.update(|health| {
                health.active = false;
                health.reader_restarts += 1;
                health.last_error = Some(reason.clone());
            });
            if started.elapsed() >= HEALTHY_RUN {
                delay = RESTART_MIN;
            }
            warn!(
                error = %reason,
                retry_in_ms = delay.as_millis() as u64,
                "Auth journal reader stopped; restarting from the saved cursor"
            );
            if !self.sleep(delay) {
                break;
            }
            delay = (delay * 2).min(RESTART_MAX);
        }
        self.health.update(|health| health.active = false);
    }

    fn sleep(&self, total: Duration) -> bool {
        let deadline = Instant::now() + total;
        while !self.shutdown.load(Ordering::SeqCst) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return true;
            }
            thread::sleep(remaining.min(WAIT_SLICE));
        }
        false
    }

    /// The saved cursor, or `None` to start at the tail.
    fn load_cursor(&self) -> Option<String> {
        match fs::read_to_string(&self.checkpoint) {
            Ok(text) => {
                let cursor = text.trim();
                if auth_log::cursor_position(cursor).is_some() {
                    return Some(cursor.to_string());
                }
                self.health.update(|health| {
                    health.checkpoint_errors += 1;
                    health.last_error = Some(format!(
                        "{} does not hold a journal cursor; starting at the tail",
                        self.checkpoint.display()
                    ));
                });
                warn!(path = %self.checkpoint.display(), "Invalid auth journal cursor; starting at the tail");
                None
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                self.health.update(|health| {
                    health.checkpoint_errors += 1;
                    health.last_error = Some(format!("failed to read the auth cursor: {err}"));
                });
                warn!(error = %err, "Auth journal cursor unreadable; starting at the tail");
                None
            }
        }
    }

    /// Count a resume that retention or a journal reset has already broken.
    fn check_retention(&self, cursor: &str) {
        let oldest = match self.oldest_cursor() {
            Ok(Some(oldest)) => oldest,
            Ok(None) => return,
            Err(err) => {
                debug!(error = %err, "Could not read the oldest journal record");
                return;
            }
        };
        match auth_log::resume_check(cursor, &oldest) {
            auth_log::ResumeCheck::Continuous | auth_log::ResumeCheck::Unknown => {}
            auth_log::ResumeCheck::ForeignSequence => {
                self.health.update(|health| {
                health.resume_failures += 1;
                health.last_error = Some(
                    "the saved cursor belongs to another journal sequence; auth records written while the agent was down may be missing"
                        .into(),
                );
            });
                warn!("Auth journal cursor is from another journal sequence; downtime loss is unknown");
            }
            auth_log::ResumeCheck::RetentionPassed { saved, oldest } => {
                self.health.update(|health| health.retention_wraps += 1);
                warn!(
                    saved,
                    oldest,
                    "Journal retention passed the saved auth cursor; matching records lost is unknown"
                );
            }
        }
    }

    /// The cursor of the oldest record in the journal, unfiltered.
    fn oldest_cursor(&self) -> Result<Option<String>> {
        let mut child = journalctl_command(&self.journalctl)
            .args([
                "--quiet",
                "--no-pager",
                "--output=json",
                "--output-fields=__CURSOR",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut line = String::new();
        let read = child
            .stdout
            .take()
            .map(|stdout| BufReader::new(stdout).read_line(&mut line));
        let _ = child.kill();
        let _ = child.wait();
        read.transpose()?;
        if line.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(JournalEntry::from_json(&line)?.cursor))
    }

    fn follow(&mut self, cursor: Option<&str>) -> Result<RunEnd> {
        let mut command = journalctl_command(&self.journalctl);
        command.args([
            "--follow",
            "--output=json",
            "--all",
            "--quiet",
            "--no-pager",
        ]);
        match cursor {
            Some(cursor) => command.arg(format!("--after-cursor={cursor}")),
            None => command.arg("--lines=0"),
        };
        for facility in AUTH_FACILITIES {
            command.arg(format!("SYSLOG_FACILITY={facility}"));
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to start journalctl")?;
        let stdout = child.stdout.take().context("journalctl has no stdout")?;
        let stderr = child.stderr.take().map(spawn_stderr_tail);
        *self.child.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
        // A shutdown that arrived while spawning found no child to kill.
        if self.shutdown.load(Ordering::SeqCst) {
            self.reap();
            return Ok(RunEnd::Shutdown);
        }
        self.health.update(|health| health.active = true);
        info!(resume = cursor.is_some(), "Auth journal reader started");

        let mut pending: Option<String> = None;
        let mut last_write = Instant::now();
        let mut end = None;
        for line in BufReader::new(stdout).split(b'\n') {
            let line = match line {
                Ok(line) => line,
                Err(err) => {
                    end = Some(RunEnd::Exited(format!("reading journalctl failed: {err}")));
                    break;
                }
            };
            if line.is_empty() {
                continue;
            }
            match self.handle(&String::from_utf8_lossy(&line)) {
                Handled::Cursor(cursor) => pending = Some(cursor),
                Handled::Undecodable => {}
                Handled::ChannelClosed(cursor) => {
                    pending = Some(cursor);
                    end = Some(RunEnd::ChannelClosed);
                    break;
                }
            }
            if pending.is_some() && last_write.elapsed() >= CHECKPOINT_INTERVAL {
                self.persist(pending.take());
                last_write = Instant::now();
            }
        }
        self.persist(pending);
        let status = self.reap();
        let stderr = stderr.and_then(|tail| tail.join().ok()).unwrap_or_default();
        if let Some(end) = end {
            return Ok(end);
        }
        if self.shutdown.load(Ordering::SeqCst) {
            return Ok(RunEnd::Shutdown);
        }
        let status = status.map_or_else(|| "an unknown status".to_string(), |s| s.to_string());
        Ok(RunEnd::Exited(if stderr.is_empty() {
            format!("journalctl exited with {status}")
        } else {
            format!("journalctl exited with {status}: {stderr}")
        }))
    }

    /// Kill and wait for the running journalctl, under the lock `shutdown`
    /// takes, so a kill can never reach a reused PID.
    fn reap(&self) -> Option<std::process::ExitStatus> {
        let mut slot = self.child.lock().unwrap_or_else(|e| e.into_inner());
        let mut child = slot.take()?;
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill();
        }
        child.wait().ok()
    }

    fn handle(&mut self, line: &str) -> Handled {
        self.health.update(|health| health.read += 1);
        let entry = match JournalEntry::from_json(line) {
            Ok(entry) => entry,
            Err(err) => {
                let mut total = 0;
                self.health.update(|health| {
                    health.decode_errors += 1;
                    total = health.decode_errors;
                });
                let decision = self.decode_warnings.should_emit("decode");
                if decision.should_emit {
                    warn!(error = %err, decode_errors = total,
                        suppressed_warnings = decision.suppressed_since_last_emit,
                        "Unreadable auth journal record");
                }
                return Handled::Undecodable;
            }
        };
        let seqnum = entry
            .seqnum
            .or_else(|| auth_log::cursor_position(&entry.cursor).map(|(_, seqnum)| seqnum));
        self.health.update(|health| health.last_seqnum = seqnum);
        let event = match auth_log::decode_record(&entry, |uid| self.users.name(uid)) {
            auth_log::Decoded::Accepted(event) => event,
            auth_log::Decoded::AcceptedSameUser(event) => {
                self.health.update(|health| health.same_user += 1);
                event
            }
            auth_log::Decoded::Untrusted => {
                self.health.update(|health| health.untrusted += 1);
                return Handled::Cursor(entry.cursor);
            }
        };
        match crate::telemetry::try_send_sensor_event(&self.tx, event) {
            Ok(()) => self.health.update(|health| health.delivered += 1),
            Err(TrySendError::Full(_)) => self.health.update(|health| health.dropped += 1),
            Err(TrySendError::Closed(_)) => return Handled::ChannelClosed(entry.cursor),
        }
        Handled::Cursor(entry.cursor)
    }

    fn persist(&self, cursor: Option<String>) {
        let Some(cursor) = cursor else {
            return;
        };
        if let Err(err) = write_checkpoint(&self.checkpoint, &cursor) {
            self.health.update(|health| {
                health.checkpoint_errors += 1;
                health.last_error = Some(format!("failed to save the auth cursor: {err:#}"));
            });
            warn!(error = %err, "Failed to save the auth journal cursor");
        }
    }
}

enum Handled {
    /// The record was read; resume after this cursor.
    Cursor(String),
    /// Not a journal record; the cursor does not move.
    Undecodable,
    ChannelClosed(String),
}

fn spawn_stderr_tail(stderr: impl Read + Send + 'static) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut tail = Vec::new();
        let mut buffer = [0u8; 1024];
        let mut stderr = stderr;
        while let Ok(read) = stderr.read(&mut buffer) {
            if read == 0 {
                break;
            }
            tail.extend_from_slice(&buffer[..read]);
            if tail.len() > STDERR_TAIL {
                tail.drain(..tail.len() - STDERR_TAIL);
            }
        }
        String::from_utf8_lossy(&tail).trim().to_string()
    })
}

fn write_checkpoint(path: &Path, cursor: &str) -> Result<()> {
    let directory = path
        .parent()
        .context("the cursor file needs a parent directory")?;
    fs::create_dir_all(directory)?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(cursor.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|err| err.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_names_resolve_through_nss() {
        let users = UserNames::default();
        assert_eq!(users.name(0).as_deref(), Some("root"));
        assert_eq!(users.name(0).as_deref(), Some("root"));
        assert_eq!(users.name(u32::MAX - 1), None);
    }

    #[test]
    fn a_cursor_survives_a_round_trip_through_its_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join(CURSOR_FILE);
        let cursor = "s=15fc2ba76e6547fc8db29565b3577db7;i=5864f;b=1e7f3b75a2a14db29c7ba2324a72d3f2;m=5bf6a13;t=660b1f266f477;x=15987952613ed38c";
        write_checkpoint(&path, cursor).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), cursor);
    }
}
