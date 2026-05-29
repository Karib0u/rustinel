//! macOS Endpoint Security sensor.
//!
//! [`EsfSensor`] implements [`Sensor`] for macOS using Apple's Endpoint
//! Security framework via the `endpoint-sec` crate. On `start()` it spawns a
//! dedicated thread that owns the ES client — the client must be created and
//! released on the same thread — subscribes to process events, and translates
//! each message into a [`SensorEvent`] for the shared pipeline.
//!
//! Endpoint Security delivers messages on its own dispatch queue, so the
//! keepalive thread simply holds the client alive until shutdown; the actual
//! work happens in the message handler.
//!
//! Requirements: root, the `com.apple.developer.endpoint-security.client`
//! entitlement, and user approval (TCC). Dev builds can run with SIP/AMFI
//! relaxed.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use endpoint_sec::{
    Client, Event, EventClose, EventCreate, EventCreateDestinationFile, EventExec, EventRename,
    EventRenameDestinationFile, EventUnlink, Message,
};
use endpoint_sec_sys::es_event_type_t;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::models::{FileEventFields, ProcessCreationFields};
use crate::sensor::{
    Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorNormalization,
    SensorPayload,
};

/// Poll interval for the keepalive thread to observe the shutdown flag.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// Sysmon-compatible event ID emitted for process-create events.
const EVENT_ID_PROCESS_CREATE: u16 = 1;
/// Sysmon-compatible event ID emitted for process-terminate events.
const EVENT_ID_PROCESS_TERMINATE: u16 = 5;
/// Sysmon-compatible event IDs emitted for file events.
const EVENT_ID_FILE_CREATE: u16 = 11;
const EVENT_ID_FILE_DELETE: u16 = 23;
const EVENT_ID_FILE_RENAME: u16 = 71;

/// Endpoint Security event subscriptions for the macOS sensor.
const SUBSCRIPTIONS: &[es_event_type_t] = &[
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CLOSE,
];

/// macOS Endpoint Security sensor. Implements [`Sensor`].
pub struct EsfSensor {
    shutdown: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl EsfSensor {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        }
    }
}

impl Default for EsfSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for EsfSensor {
    /// Spawn the Endpoint Security client thread and block until the client is
    /// created and subscribed, so initialization errors (missing entitlement,
    /// not root, TCC denial) surface synchronously to the caller.
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

        let handle = std::thread::Builder::new()
            .name("rustinel-esf".to_string())
            .spawn(move || run_client(tx, shutdown, ready_tx))
            .map_err(|e| anyhow!("failed to spawn Endpoint Security thread: {e}"))?;

        *self.thread.lock().expect("esf thread mutex poisoned") = Some(handle);

        match ready_rx.recv() {
            Ok(Ok(())) => {
                info!("Endpoint Security client subscribed");
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow!("Endpoint Security client init failed: {e}")),
            Err(_) => Err(anyhow!(
                "Endpoint Security thread exited before signaling readiness"
            )),
        }
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self
            .thread
            .lock()
            .expect("esf thread mutex poisoned")
            .take()
        {
            let _ = handle.join();
        }
    }
}

/// Body of the Endpoint Security client thread.
///
/// Creates the client, subscribes, signals readiness, then keeps the client
/// alive until shutdown. The client is dropped (released) on this thread, as
/// Endpoint Security requires.
fn run_client(
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let handler = move |_client: &mut Client<'_>, msg: Message| {
        if let Some(event) = build_sensor_event(&msg) {
            try_send(&tx, event);
        }
    };

    let mut client = match Client::new(handler) {
        Ok(client) => client,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("es_new_client failed: {e:?}")));
            return;
        }
    };

    if let Err(e) = client.subscribe(SUBSCRIPTIONS) {
        let _ = ready_tx.send(Err(format!("es_subscribe failed: {e:?}")));
        return;
    }

    let _ = ready_tx.send(Ok(()));

    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SHUTDOWN_POLL);
    }

    info!("Endpoint Security sensor shutting down");
}

/// Translate an Endpoint Security message into a shared [`SensorEvent`].
///
/// Returns `None` for messages that carry no detection signal or are not yet
/// mapped. Per-event-class translation is filled in incrementally.
fn build_sensor_event(msg: &Message) -> Option<SensorEvent> {
    match msg.event()? {
        Event::NotifyExec(exec) => build_exec_event(msg, &exec),
        Event::NotifyExit(_) => build_exit_event(msg),
        Event::NotifyCreate(create) => build_create_event(msg, &create),
        Event::NotifyUnlink(unlink) => build_unlink_event(msg, &unlink),
        Event::NotifyRename(rename) => build_rename_event(msg, &rename),
        Event::NotifyClose(close) => build_close_event(msg, &close),
        _ => None,
    }
}

/// Plain, FFI-free description of an exec, extracted from an ESF event.
///
/// Keeping this separate from the Endpoint Security types lets the
/// `SensorEvent` assembly be unit-tested without a live ES client.
struct RawExec {
    pid: u32,
    image: String,
    command_line: Option<String>,
    parent_pid: i32,
    parent_image: Option<String>,
    current_directory: Option<String>,
    user: String,
    /// Process start time, as nanoseconds since the Unix epoch.
    start_time: u64,
    event_time: SystemTime,
}

/// Extract the fields we care about from an ESF exec event.
fn build_exec_event(msg: &Message, exec: &EventExec) -> Option<SensorEvent> {
    let target = exec.target();
    let token = target.audit_token();

    let image = osstr_to_string(target.executable().path());
    if image.is_empty() {
        return None;
    }

    let command_line = {
        let parts: Vec<String> = exec.args().map(osstr_to_string).collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    };

    let current_directory = exec
        .cwd()
        .map(|cwd| osstr_to_string(cwd.path()))
        .filter(|value| !value.is_empty());

    let event_time = msg.time();
    let start_time = target
        .start_time()
        .map(system_time_nanos)
        .unwrap_or_else(|| system_time_nanos(event_time));

    let parent_pid = target.ppid();
    let parent_image = (parent_pid > 0)
        .then(|| crate::utils::process_image_path(parent_pid as u32))
        .flatten();

    Some(process_start_event(RawExec {
        pid: token.pid() as u32,
        image,
        command_line,
        parent_pid,
        parent_image,
        current_directory,
        user: token.ruid().to_string(),
        start_time,
        event_time,
    }))
}

/// Assemble a process-start [`SensorEvent`] from FFI-free exec fields.
fn process_start_event(raw: RawExec) -> SensorEvent {
    let parent_process_id = (raw.parent_pid > 0).then(|| raw.parent_pid.to_string());

    SensorEvent {
        platform: Platform::MacOS,
        provider: "esf",
        action: SensorAction::Start,
        normalization: SensorNormalization {
            event_id: EVENT_ID_PROCESS_CREATE,
            action_code: 1,
        },
        pid: Some(raw.pid),
        timestamp: raw.event_time,
        process_start_key: Some(ProcessStartKey {
            pid: raw.pid,
            start_time: raw.start_time,
        }),
        payload: SensorPayload::Process(ProcessCreationFields {
            image: Some(raw.image),
            original_file_name: None,
            product: None,
            description: None,
            target_image: None,
            command_line: raw.command_line,
            process_id: Some(raw.pid.to_string()),
            process_start_time: Some(raw.start_time),
            parent_process_id,
            parent_image: raw.parent_image,
            // ESF exec events do not carry the parent's command line.
            parent_command_line: None,
            current_directory: raw.current_directory,
            // Windows-specific; absent on macOS.
            integrity_level: None,
            user: Some(raw.user),
            logon_id: None,
            logon_guid: None,
        }),
    }
}

/// Extract the exiting process from an ESF exit event.
///
/// ESF reports the exiting process as the message's acting process; the exit
/// status is not carried in the shared payload (matching the Linux sensor).
fn build_exit_event(msg: &Message) -> Option<SensorEvent> {
    let token = msg.process().audit_token();
    Some(process_stop_event(
        token.pid() as u32,
        token.ruid().to_string(),
        msg.time(),
    ))
}

/// Assemble a process-stop [`SensorEvent`] from FFI-free fields.
fn process_stop_event(pid: u32, user: String, event_time: SystemTime) -> SensorEvent {
    SensorEvent {
        platform: Platform::MacOS,
        provider: "esf",
        action: SensorAction::Stop,
        normalization: SensorNormalization {
            event_id: EVENT_ID_PROCESS_TERMINATE,
            action_code: 2,
        },
        pid: Some(pid),
        timestamp: event_time,
        process_start_key: None,
        payload: SensorPayload::Process(ProcessCreationFields {
            image: None,
            original_file_name: None,
            product: None,
            description: None,
            target_image: None,
            command_line: None,
            process_id: Some(pid.to_string()),
            process_start_time: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: Some(user),
            logon_id: None,
            logon_guid: None,
        }),
    }
}

/// File event class, mapped to Sysmon-compatible action metadata.
#[derive(Clone, Copy)]
enum FileAction {
    Create,
    Delete,
    Rename,
    Modify,
}

impl FileAction {
    /// Return the (action, event id, action code) triple for this class,
    /// matching the Linux sensor's Sysmon-compatible numbering.
    fn normalization(self) -> (SensorAction, u16, u8) {
        match self {
            FileAction::Create => (SensorAction::Create, EVENT_ID_FILE_CREATE, 64),
            FileAction::Delete => (SensorAction::Delete, EVENT_ID_FILE_DELETE, 70),
            FileAction::Rename => (SensorAction::Rename, EVENT_ID_FILE_RENAME, 71),
            // Sysmon has no file-modify event, so report modify under
            // FileCreate (11) like the Linux sensor; the action code stays 65.
            FileAction::Modify => (SensorAction::Modify, EVENT_ID_FILE_CREATE, 65),
        }
    }
}

/// Plain, FFI-free description of a file event, extracted from an ESF event.
struct RawFile {
    action: FileAction,
    pid: u32,
    image: Option<String>,
    user: String,
    target: String,
    source: Option<String>,
    event_time: SystemTime,
}

/// Acting process context shared by all file events: pid, executable, and the
/// raw uid as a string. Username resolution is deferred to the normalizer
/// (like the Linux sensor) to avoid a directory-services lookup per event on
/// the high-volume file path.
fn actor(msg: &Message) -> (u32, Option<String>, String) {
    let process = msg.process();
    let token = process.audit_token();
    let image = osstr_to_string(process.executable().path());
    (
        token.pid() as u32,
        (!image.is_empty()).then_some(image),
        token.ruid().to_string(),
    )
}

fn build_create_event(msg: &Message, create: &EventCreate) -> Option<SensorEvent> {
    let target = create_destination_path(create.destination()?)?;
    let (pid, image, user) = actor(msg);
    file_event(RawFile {
        action: FileAction::Create,
        pid,
        image,
        user,
        target,
        source: None,
        event_time: msg.time(),
    })
}

fn build_unlink_event(msg: &Message, unlink: &EventUnlink) -> Option<SensorEvent> {
    let target = osstr_to_string(unlink.target().path());
    let (pid, image, user) = actor(msg);
    file_event(RawFile {
        action: FileAction::Delete,
        pid,
        image,
        user,
        target,
        source: None,
        event_time: msg.time(),
    })
}

fn build_rename_event(msg: &Message, rename: &EventRename) -> Option<SensorEvent> {
    let target = rename_destination_path(rename.destination()?)?;
    let source = osstr_to_string(rename.source().path());
    let (pid, image, user) = actor(msg);
    file_event(RawFile {
        action: FileAction::Rename,
        pid,
        image,
        user,
        target,
        source: (!source.is_empty()).then_some(source),
        event_time: msg.time(),
    })
}

/// Emit a modify event when a writable file is closed after being changed.
///
/// Filtering on `modified` keeps the high-volume close stream down to actual
/// content changes, the closest ESF analog to Sysmon's file-change event.
fn build_close_event(msg: &Message, close: &EventClose) -> Option<SensorEvent> {
    if !close.modified() {
        return None;
    }
    let target = osstr_to_string(close.target().path());
    let (pid, image, user) = actor(msg);
    file_event(RawFile {
        action: FileAction::Modify,
        pid,
        image,
        user,
        target,
        source: None,
        event_time: msg.time(),
    })
}

/// Resolve the absolute path of a create destination.
fn create_destination_path(dest: EventCreateDestinationFile) -> Option<String> {
    let path = match dest {
        EventCreateDestinationFile::ExistingFile(file) => osstr_to_string(file.path()),
        EventCreateDestinationFile::NewPath {
            directory,
            filename,
            ..
        } => join_path(directory.path(), filename),
    };
    (!path.is_empty()).then_some(path)
}

/// Resolve the absolute path of a rename destination.
fn rename_destination_path(dest: EventRenameDestinationFile) -> Option<String> {
    let path = match dest {
        EventRenameDestinationFile::ExistingFile(file) => osstr_to_string(file.path()),
        EventRenameDestinationFile::NewPath {
            directory,
            filename,
        } => join_path(directory.path(), filename),
    };
    (!path.is_empty()).then_some(path)
}

/// Assemble a file [`SensorEvent`] from FFI-free fields.
fn file_event(raw: RawFile) -> Option<SensorEvent> {
    if raw.target.is_empty() {
        return None;
    }
    let (action, event_id, action_code) = raw.action.normalization();

    Some(SensorEvent {
        platform: Platform::MacOS,
        provider: "esf",
        action,
        normalization: SensorNormalization {
            event_id,
            action_code,
        },
        pid: Some(raw.pid),
        timestamp: raw.event_time,
        process_start_key: None,
        payload: SensorPayload::File(FileEventFields {
            source_filename: raw.source,
            target_filename: Some(raw.target),
            process_id: Some(raw.pid.to_string()),
            image: raw.image,
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: Some(raw.user),
        }),
    })
}

fn join_path(directory: &OsStr, filename: &OsStr) -> String {
    let mut path = PathBuf::from(directory);
    path.push(filename);
    path.to_string_lossy().into_owned()
}

fn osstr_to_string(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn system_time_nanos(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

fn try_send(tx: &Sender<SensorEvent>, event: SensorEvent) {
    match tx.try_send(event) {
        Ok(_) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            warn!("ESF sensor: event channel full, dropping event");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            // Pipeline has shut down; stop logging.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_start_event_maps_exec_fields() {
        let event = process_start_event(RawExec {
            pid: 4242,
            image: "/usr/bin/curl".to_string(),
            command_line: Some("/usr/bin/curl https://example.test".to_string()),
            parent_pid: 501,
            parent_image: Some("/bin/zsh".to_string()),
            current_directory: Some("/Users/alice".to_string()),
            user: "alice".to_string(),
            start_time: 1_700_000_000_000_000_000,
            event_time: SystemTime::UNIX_EPOCH,
        });

        assert_eq!(event.platform, Platform::MacOS);
        assert_eq!(event.provider, "esf");
        assert_eq!(event.action, SensorAction::Start);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_CREATE);
        assert_eq!(event.pid, Some(4242));
        assert_eq!(
            event.process_start_key,
            Some(ProcessStartKey {
                pid: 4242,
                start_time: 1_700_000_000_000_000_000,
            })
        );

        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/curl"));
                assert_eq!(
                    fields.command_line.as_deref(),
                    Some("/usr/bin/curl https://example.test")
                );
                assert_eq!(fields.process_id.as_deref(), Some("4242"));
                assert_eq!(fields.parent_process_id.as_deref(), Some("501"));
                assert_eq!(fields.current_directory.as_deref(), Some("/Users/alice"));
                assert_eq!(fields.user.as_deref(), Some("alice"));
                assert_eq!(fields.parent_image.as_deref(), Some("/bin/zsh"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    fn raw_file(action: FileAction, target: &str, source: Option<&str>) -> RawFile {
        RawFile {
            action,
            pid: 55,
            image: Some("/usr/bin/touch".to_string()),
            user: "alice".to_string(),
            target: target.to_string(),
            source: source.map(str::to_string),
            event_time: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn file_event_maps_create() {
        let event = file_event(raw_file(FileAction::Create, "/tmp/new.txt", None))
            .expect("create event should build");
        assert_eq!(event.action, SensorAction::Create);
        assert_eq!(event.normalization.event_id, EVENT_ID_FILE_CREATE);
        assert_eq!(event.pid, Some(55));
        assert!(event.process_start_key.is_none());

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/new.txt"));
                assert!(fields.source_filename.is_none());
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/touch"));
                assert_eq!(fields.user.as_deref(), Some("alice"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn file_event_maps_delete() {
        let event = file_event(raw_file(FileAction::Delete, "/tmp/old.txt", None))
            .expect("delete event should build");
        assert_eq!(event.action, SensorAction::Delete);
        assert_eq!(event.normalization.event_id, EVENT_ID_FILE_DELETE);
    }

    #[test]
    fn file_event_maps_rename_with_source() {
        let event = file_event(raw_file(
            FileAction::Rename,
            "/tmp/new.txt",
            Some("/tmp/old.txt"),
        ))
        .expect("rename event should build");
        assert_eq!(event.action, SensorAction::Rename);
        assert_eq!(event.normalization.event_id, EVENT_ID_FILE_RENAME);

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.source_filename.as_deref(), Some("/tmp/old.txt"));
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/new.txt"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn file_event_maps_modify() {
        let event = file_event(raw_file(FileAction::Modify, "/tmp/changed.txt", None))
            .expect("modify event should build");
        assert_eq!(event.action, SensorAction::Modify);
        // Matches the Linux sensor: modify reports under FileCreate (11).
        assert_eq!(event.normalization.event_id, EVENT_ID_FILE_CREATE);
        assert_eq!(event.normalization.event_id, 11);
    }

    #[test]
    fn file_event_rejects_empty_target() {
        assert!(file_event(raw_file(FileAction::Create, "", None)).is_none());
    }

    #[test]
    fn join_path_combines_directory_and_filename() {
        assert_eq!(
            join_path(OsStr::new("/tmp/dir"), OsStr::new("file.txt")),
            "/tmp/dir/file.txt"
        );
    }

    #[test]
    fn process_stop_event_maps_exit() {
        let event = process_stop_event(4242, "alice".to_string(), SystemTime::UNIX_EPOCH);

        assert_eq!(event.action, SensorAction::Stop);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_TERMINATE);
        assert_eq!(event.pid, Some(4242));
        assert!(event.process_start_key.is_none());

        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.process_id.as_deref(), Some("4242"));
                assert_eq!(fields.user.as_deref(), Some("alice"));
                assert!(fields.image.is_none());
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn process_start_event_omits_nonpositive_parent_pid() {
        let event = process_start_event(RawExec {
            pid: 7,
            image: "/sbin/launchd".to_string(),
            command_line: None,
            parent_pid: 0,
            parent_image: None,
            current_directory: None,
            user: "root".to_string(),
            start_time: 0,
            event_time: SystemTime::UNIX_EPOCH,
        });

        match event.payload {
            SensorPayload::Process(fields) => {
                assert!(fields.parent_process_id.is_none());
                assert!(fields.command_line.is_none());
                assert!(fields.current_directory.is_none());
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}
