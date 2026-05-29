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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use endpoint_sec::{Client, Event, EventExec, Message};
use endpoint_sec_sys::es_event_type_t;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::models::ProcessCreationFields;
use crate::sensor::{
    Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorNormalization,
    SensorPayload,
};
use crate::utils::lookup_username_by_uid;

/// Poll interval for the keepalive thread to observe the shutdown flag.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// Sysmon-compatible event ID emitted for process-create events.
const EVENT_ID_PROCESS_CREATE: u16 = 1;
/// Sysmon-compatible event ID emitted for process-terminate events.
const EVENT_ID_PROCESS_TERMINATE: u16 = 5;

/// Endpoint Security event subscriptions for the macOS sensor.
const SUBSCRIPTIONS: &[es_event_type_t] = &[
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
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

    Some(process_start_event(RawExec {
        pid: token.pid() as u32,
        image,
        command_line,
        parent_pid: target.ppid(),
        current_directory,
        user: resolved_user(token.ruid()),
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
            parent_process_id,
            // Enriched later via libproc; ESF exec events do not carry it.
            parent_image: None,
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
        resolved_user(token.ruid()),
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

fn osstr_to_string(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn system_time_nanos(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

fn resolved_user(uid: u32) -> String {
    lookup_username_by_uid(uid).unwrap_or_else(|| uid.to_string())
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
                assert!(fields.parent_image.is_none());
            }
            other => panic!("unexpected payload: {other:?}"),
        }
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
