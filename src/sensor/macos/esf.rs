//! macOS Endpoint Security sensor.
//!
//! [`EsfSensor`] implements [`Sensor`] for macOS using Apple's Endpoint
//! Security framework via the `endpoint-sec` crate. On `start()` it spawns a
//! dedicated thread that owns the ES client, the client must be created and
//! released on the same thread, subscribes to process events, and translates
//! each message into a [`RawEvent`] for the shared pipeline.
//!
//! Endpoint Security delivers messages on its own dispatch queue, so the
//! keepalive thread simply holds the client alive until shutdown; the actual
//! work happens in the message handler.
//!
//! Requirements: root, the `com.apple.developer.endpoint-security.client`
//! entitlement, and user approval (TCC). Dev builds can run with SIP/AMFI
//! relaxed.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use endpoint_sec::{Client, Message};
use endpoint_sec_sys::{es_event_type_t, NewClientError};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

#[cfg(test)]
mod fixture_tests;
mod recorder;
mod view;

use view::{EsDestination, EsEvent, EsExec, EsFile, EsMessage, EsTime};

use crate::models::{FileEventFields, FileObjectIdentity};
use crate::sensor::{
    Platform, ProcessStartKey, RawEvent, RawMacOsExec, RawMacOsProcess, RawPayload,
    RawProcessEvent, RawProcessPlatform, RawUserId, Sensor, SensorAction, SensorNormalization,
};

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
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CLOSE,
];

/// macOS Endpoint Security sensor. Implements [`Sensor`].
pub struct EsfSensor {
    shutdown: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    collectors: crate::telemetry::MacosCollectors,
    processes: Option<Arc<crate::state::ProcessCache>>,
}

impl EsfSensor {
    /// Report collector health to `host`, so the runtime's telemetry sees it.
    pub fn with_host_state(host: &crate::state::HostState) -> Self {
        Self {
            collectors: Arc::clone(&host.macos_collectors),
            processes: Some(Arc::clone(&host.processes)),
            ..Self::new()
        }
    }

    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
            collectors: Default::default(),
            processes: None,
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
    fn start(&self, tx: Sender<RawEvent>) -> Result<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

        let collectors = Arc::clone(&self.collectors);
        let processes = self.processes.clone();
        let handle = std::thread::Builder::new()
            .name("rustinel-esf".to_string())
            .spawn(move || run_client(tx, shutdown, ready_tx, collectors, processes))
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

/// Translate an `es_new_client` failure into an actionable message.
///
/// These failures are almost always environmental, missing TCC approval, not
/// root, or an unsigned binary, rather than bugs, so we point at the concrete
/// step that unblocks each one instead of surfacing a bare result code.
fn new_client_error_hint(err: &NewClientError) -> String {
    let remedy = match err {
        NewClientError::NotPermitted => {
            "macOS has not granted Endpoint Security access. Grant Rustinel.app Full Disk \
             Access in System Settings > Privacy & Security > Full Disk Access, then re-run. \
             If you launched it from a terminal, that terminal app may also need Full Disk \
             Access."
        }
        NewClientError::NotPrivileged => "Endpoint Security requires root. Re-run with sudo.",
        NewClientError::NotEntitled => {
            "The binary lacks the com.apple.developer.endpoint-security.client entitlement. \
             Run a signed Rustinel.app from a release, or repackage it with \
             scripts/macos/package-app.sh."
        }
        NewClientError::TooManyClients => {
            "The system reached its Endpoint Security client limit. Stop another Endpoint \
             Security agent and retry."
        }
        _ => "Could not create the Endpoint Security client.",
    };
    format!("es_new_client failed: {err:?}: {remedy}")
}

/// Best-effort deep-link to the Full Disk Access settings pane.
///
/// `NotPermitted` means the user still has to grant Full Disk Access by hand, so
/// for an interactive `sudo ./rustinel run` we open the right pane for them.
/// Started with sudo the process is root, which has no GUI session, so we reopen
/// in the invoking user's session via `launchctl asuser`. A LaunchDaemon has no
/// controlling terminal and is skipped; any failure is ignored, this is a
/// convenience, not a step the pipeline depends on.
fn try_open_full_disk_access_settings() {
    if !std::io::stderr().is_terminal() {
        return;
    }
    const PANE: &str = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";
    info!("Opening System Settings → Privacy & Security → Full Disk Access");
    let status = match std::env::var("SUDO_UID") {
        Ok(uid) => std::process::Command::new("launchctl")
            .args(["asuser", &uid, "open", PANE])
            .status(),
        Err(_) => std::process::Command::new("open").arg(PANE).status(),
    };
    let _ = status;
}

/// Body of the Endpoint Security client thread.
///
/// Creates the client, subscribes, signals readiness, then keeps the client
/// alive until shutdown. The client is dropped (released) on this thread, as
/// Endpoint Security requires.
fn run_client(
    tx: Sender<RawEvent>,
    shutdown: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::Sender<Result<(), String>>,
    collectors: crate::telemetry::MacosCollectors,
    processes: Option<Arc<crate::state::ProcessCache>>,
) {
    // These derived caches remain valid after unwinding. Recover poisoned
    // locks so a dropped event does not disable every later delivery.
    let identities = Mutex::new(ExecIdentities::default());
    if let Some(processes) = &processes {
        seed_exec_identities(
            &mut identities.lock().unwrap_or_else(|e| e.into_inner()),
            processes,
        );
    }
    let sequences = Mutex::new(crate::telemetry::macos::EsfSequences::default());
    let handler_collectors = Arc::clone(&collectors);
    // Development and tests unwind: catch conversion panics before the native
    // callback boundary and drop this event. Release uses panic = "abort", so
    // the process terminates and the service manager must restart it.
    let handler =
        move |_client: &mut Client<'_>, msg: Message| match catch_unwind(AssertUnwindSafe(|| {
            sequences.lock().unwrap_or_else(|e| e.into_inner()).observe(
                handler_collectors
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .esf
                    .get_or_insert_with(Default::default),
                format!("{:?}", msg.event_type()),
                msg.seq_num(),
                msg.global_seq_num(),
            );
            recorder::record(&msg);
            build_sensor_event(
                &msg,
                &mut identities.lock().unwrap_or_else(|e| e.into_inner()),
            )
        })) {
            Ok(Some(event)) => try_send(&tx, event),
            Ok(None) => {}
            Err(_) => {
                warn!(
                    event_type = ?msg.event_type(),
                    "Endpoint Security event conversion panicked; dropping event"
                );
            }
        };

    let mut client = match Client::new(handler) {
        Ok(client) => client,
        Err(e) => {
            if matches!(e, NewClientError::NotPermitted) {
                try_open_full_disk_access_settings();
            }
            let _ = ready_tx.send(Err(new_client_error_hint(&e)));
            return;
        }
    };

    collectors.lock().unwrap_or_else(|e| e.into_inner()).esf = Some(Default::default());

    if let Err(e) = client.subscribe(SUBSCRIPTIONS) {
        collectors.lock().unwrap_or_else(|e| e.into_inner()).esf = None;
        let _ = ready_tx.send(Err(format!("es_subscribe failed: {e:?}")));
        return;
    }

    let _ = ready_tx.send(Ok(()));

    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SHUTDOWN_POLL);
    }

    info!("Endpoint Security sensor shutting down");
}

/// Record the startup inventory's processes so a child of a process that
/// predates the sensor can still find its parent. Only processes the inventory
/// put in the shared cache are seeded, so a seeded key always resolves.
fn seed_exec_identities(identities: &mut ExecIdentities, processes: &crate::state::ProcessCache) {
    let Ok(pids) = libproc::processes::pids_by_type(libproc::processes::ProcFilter::All) else {
        return;
    };
    for pid in pids.into_iter().filter(|pid| *pid != 0) {
        let Some(start_time) = crate::utils::query_process_identity(pid).and_then(|i| i.start_time)
        else {
            continue;
        };
        if processes.get_metadata_by_key(pid, start_time).is_some() {
            identities.seed(ProcessStartKey { pid, start_time });
        }
    }
}

/// Translate an Endpoint Security message into a shared [`RawEvent`].
///
/// Returns `None` for messages that carry no detection signal or are not yet
/// mapped. Per-event-class translation is filled in incrementally.
fn build_sensor_event(msg: &impl EsMessage, identities: &mut ExecIdentities) -> Option<RawEvent> {
    match msg.event()? {
        EsEvent::Exec(exec) => build_exec_event(msg, &exec, identities),
        EsEvent::Exit => build_exit_event(msg, identities),
        EsEvent::Create { destination } => build_create_event(msg, destination?),
        EsEvent::Unlink { target } => build_unlink_event(msg, &target),
        EsEvent::Rename {
            source,
            destination,
        } => build_rename_event(msg, &source, destination?),
        EsEvent::Close { modified, target } => build_close_event(msg, modified, &target),
    }
}

/// Most audit generations kept before the oldest is evicted.
const EXEC_IDENTITY_CAP: usize = 65_536;

/// Bounded bridge from ES audit generations to the shared cache's start keys.
/// Retain old generations so a reused PID cannot satisfy an older parent token.
/// An exit retires its entry, and a full map evicts the oldest insertion, so a
/// long-lived daemon with a low PID keeps its children's parent link.
#[derive(Default)]
struct ExecIdentities {
    keys: BTreeMap<(u32, i32), (u64, ProcessStartKey)>,
    /// Insertion order, oldest first, for eviction.
    order: BTreeMap<u64, (u32, i32)>,
    next_seq: u64,
    /// Processes already running when the sensor started, by PID. Their audit
    /// generation is unknown, so they answer only a parent token that missed
    /// `keys`. An exec or exit of the PID retires the entry, so a reused PID
    /// never resolves to the process it replaced.
    seeded: HashMap<u32, ProcessStartKey>,
}

impl ExecIdentities {
    fn observe(&mut self, generation: i32, key: ProcessStartKey) {
        // A re-exec keeps its fork time, but replaces the image in ProcessCache.
        // Retire the prior audit generation so it cannot resolve to that new image.
        let replaced: Vec<_> = self
            .keys
            .range((key.pid, i32::MIN)..=(key.pid, i32::MAX))
            .filter(|(_, (_, existing))| *existing == key)
            .map(|(token, _)| *token)
            .collect();
        for token in replaced {
            self.remove(token);
        }
        // The PID is now an observed lifetime, not the one seen at startup.
        self.seeded.remove(&key.pid);
        self.remove((key.pid, generation));
        self.next_seq += 1;
        self.keys
            .insert((key.pid, generation), (self.next_seq, key));
        self.order.insert(self.next_seq, (key.pid, generation));
        while self.keys.len() > EXEC_IDENTITY_CAP {
            let Some((_, token)) = self.order.pop_first() else {
                break;
            };
            self.keys.remove(&token);
        }
    }

    /// Forget a process that exited.
    fn retire(&mut self, pid: u32, generation: i32) {
        self.remove((pid, generation));
        // The PID is free to be reused, so its startup entry is stale too.
        self.seeded.remove(&pid);
    }

    fn remove(&mut self, token: (u32, i32)) {
        if let Some((seq, _)) = self.keys.remove(&token) {
            self.order.remove(&seq);
        }
    }

    /// Record a process that predates the sensor.
    fn seed(&mut self, key: ProcessStartKey) {
        self.seeded.insert(key.pid, key);
    }

    fn parent(&self, pid: u32, generation: Option<i32>) -> Option<ProcessStartKey> {
        if let Some(generation) = generation {
            // Never fall back to a bare PID when an authoritative token misses,
            // except to a process seen at startup, which no exec or exit has
            // touched since.
            return self
                .keys
                .get(&(pid, generation))
                .map(|(_, key)| *key)
                .or_else(|| self.seeded.get(&pid).copied());
        }
        let mut candidates = self.keys.range((pid, i32::MIN)..=(pid, i32::MAX));
        let Some((_, (_, key))) = candidates.next() else {
            return self.seeded.get(&pid).copied();
        };
        // PID-only fallback is conservative when more than one lifetime was seen.
        candidates
            .all(|(_, (_, other))| other == key)
            .then_some(*key)
    }
}

fn parent_identity(
    ppid: i32,
    original_ppid: i32,
    token: Option<(i32, i32)>,
) -> (i32, Option<i32>, bool) {
    if ppid == 1 && original_ppid > 1 {
        let generation = token
            .filter(|(pid, _)| *pid == original_ppid)
            .map(|(_, generation)| generation);
        return (original_ppid, generation, true);
    }
    match token.filter(|(pid, _)| *pid > 0) {
        Some((pid, generation)) => (pid, Some(generation), false),
        None => (ppid, None, true),
    }
}

// XNU osfmk/kern/cs_blobs.h: CS_SIGNED and CS_VALID are independent bits.
fn signature_status(flags: u32) -> &'static str {
    if flags & 0x2000_0000 == 0 {
        "unsigned"
    } else if flags & 1 != 0 {
        "valid"
    } else {
        "invalid"
    }
}

/// Plain, FFI-free description of an exec, extracted from an ESF event.
///
/// Keeping this separate from the Endpoint Security types lets the
/// `RawEvent` assembly be unit-tested without a live ES client.
struct RawExec {
    pid: u32,
    image: String,
    command_line: Option<String>,
    parent_pid: i32,
    parent_process_start_key: Option<ProcessStartKey>,
    parent_derived: bool,
    metadata: RawMacOsExec,
    current_directory: Option<String>,
    user: u32,
    /// Process start time, as nanoseconds since the Unix epoch.
    start_time: u64,
    event_time: SystemTime,
    source_seq: Option<u64>,
}

/// Extract the fields we care about from an ESF exec event.
fn build_exec_event(
    msg: &impl EsMessage,
    exec: &EsExec,
    identities: &mut ExecIdentities,
) -> Option<RawEvent> {
    let target = &exec.target;

    let image = target.executable.path.clone();
    if image.is_empty() {
        return None;
    }

    let command_line = (!exec.args.is_empty()).then(|| exec.args.join(" "));

    let current_directory = exec.cwd.clone().filter(|value| !value.is_empty());

    let event_time = event_time(msg.raw_time())?;
    let start_time = target
        .start_time_ns
        .unwrap_or_else(|| system_time_nanos(event_time));

    // The binding probes message version >= 4 before reading parent_audit_token.
    // Older messages use ppid (or original_ppid after reparenting), marked Derived.
    let (parent_pid, parent_generation, parent_derived) =
        parent_identity(target.ppid, target.original_ppid, target.parent_token);
    let parent_process_start_key = identities
        .parent(parent_pid as u32, parent_generation)
        // A PID-only or startup-seeded parent must have existed when the child
        // was forked.
        .filter(|key| key.start_time <= start_time);
    if let Some(start_time) = target.start_time_ns {
        identities.observe(
            target.pidversion,
            ProcessStartKey {
                pid: target.pid as u32,
                start_time,
            },
        );
    }
    let flags = target.codesigning_flags;
    let nonempty = |value: &str| (!value.is_empty()).then(|| value.to_string());
    let metadata = RawMacOsExec {
        signed: Some(flags & 0x2000_0000 != 0),
        pre_exec_image: nonempty(&msg.actor().executable),
        real_user_id: Some(target.ruid),
        script: exec.script.as_deref().and_then(nonempty),
        signature_status: Some(signature_status(flags).to_string()),
        signing_id: nonempty(&target.signing_id),
        team_id: nonempty(&target.team_id),
        cdhash: (flags & 0x2000_0000 != 0).then(|| target.cdhash.clone()),
        codesigning_flags: Some(flags),
        is_platform_binary: Some(target.is_platform_binary),
        file_identity: Some(crate::utils::file_identity::from_stat(
            &target.executable.stat.to_libc(),
        )),
    };

    Some(process_start_event(RawExec {
        pid: target.pid as u32,
        image,
        command_line,
        parent_pid,
        parent_process_start_key,
        parent_derived,
        metadata,
        current_directory,
        user: target.euid,
        start_time,
        event_time,
        source_seq: msg.global_seq_num(),
    }))
}

/// Assemble a process-start [`RawEvent`] from FFI-free exec fields.
fn process_start_event(raw: RawExec) -> RawEvent {
    let parent_process_id = (raw.parent_pid > 0).then_some(raw.parent_pid as u32);

    RawEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::MacOS,
        provider: "esf",
        action: SensorAction::Start,
        normalization: SensorNormalization {
            event_id: EVENT_ID_PROCESS_CREATE,
            action_code: 1,
        },
        pid: Some(raw.pid),
        timestamp: raw.event_time,
        source_seq: raw.source_seq,
        process_start_key: Some(ProcessStartKey {
            pid: raw.pid,
            start_time: raw.start_time,
        }),
        parent_process_start_key: raw.parent_process_start_key,
        payload: RawPayload::Process(RawProcessEvent {
            process_id: raw.pid,
            parent_process_id,
            process_start_time: Some(raw.start_time),
            image: Some(raw.image),
            command_line: raw.command_line,
            parent_image: None,
            // ESF exec events do not carry the parent's command line.
            parent_command_line: None,
            current_directory: raw.current_directory,
            integrity_level: None,
            logon_id: None,
            user: Some(RawUserId::Unix(raw.user)),
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            platform: Box::new(RawProcessPlatform::MacOS(RawMacOsProcess {
                parent_process_id_derived: raw.parent_derived,
                exec: Some(Box::new(raw.metadata)),
            })),
        }),
    }
}

/// Extract the exiting process from an ESF exit event.
///
/// ESF reports the exiting process as the message's acting process; the exit
/// status is not carried in the shared payload (matching the Linux sensor).
fn build_exit_event(msg: &impl EsMessage, identities: &mut ExecIdentities) -> Option<RawEvent> {
    let actor = msg.actor();
    identities.retire(actor.pid as u32, actor.pidversion);
    Some(process_stop_event(
        actor.pid as u32,
        actor.euid,
        actor.start_time_ns,
        event_time(msg.raw_time())?,
        msg.global_seq_num(),
    ))
}

/// Assemble a process-stop [`RawEvent`] from FFI-free fields.
fn process_stop_event(
    pid: u32,
    user: u32,
    start_time: Option<u64>,
    event_time: SystemTime,
    source_seq: Option<u64>,
) -> RawEvent {
    RawEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::MacOS,
        provider: "esf",
        action: SensorAction::Stop,
        normalization: SensorNormalization {
            event_id: EVENT_ID_PROCESS_TERMINATE,
            action_code: 2,
        },
        pid: Some(pid),
        timestamp: event_time,
        source_seq,
        process_start_key: start_time.map(|start_time| ProcessStartKey { pid, start_time }),
        parent_process_start_key: None,
        payload: RawPayload::Process(RawProcessEvent {
            process_id: pid,
            parent_process_id: None,
            process_start_time: None,
            image: None,
            command_line: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            logon_id: None,
            user: Some(RawUserId::Unix(user)),
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            platform: Box::new(RawProcessPlatform::MacOS(RawMacOsProcess::default())),
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
    /// Return the (action, event id, action code) triple for this class, taken
    /// from the shared [`event_actions::EVENT_ACTIONS`] table so macOS lands in the
    /// same Sigma category as Linux and Windows for the same operation.
    fn normalization(self) -> (SensorAction, u16, u8) {
        let action = match self {
            FileAction::Create => SensorAction::Create,
            FileAction::Delete => SensorAction::Delete,
            FileAction::Rename => SensorAction::Rename,
            FileAction::Modify => SensorAction::Modify,
        };
        let normalization = SensorNormalization::for_file_action(action)
            .expect("file actions are covered by the shared file normalization table");
        (action, normalization.event_id, normalization.action_code)
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
    source_seq: Option<u64>,
    process_start_key: Option<ProcessStartKey>,
    /// The object ESF measured for the file whose content this event names.
    identity: Option<FileObjectIdentity>,
}

/// Acting process context shared by all file events: pid, executable, and the
/// raw uid as a string. Username resolution is deferred to the normalizer
/// (like the Linux sensor) to avoid a directory-services lookup per event on
/// the high-volume file path.
fn actor(msg: &impl EsMessage) -> (u32, Option<String>, String, Option<ProcessStartKey>) {
    let actor = msg.actor();
    let pid = actor.pid as u32;
    (
        pid,
        (!actor.executable.is_empty()).then_some(actor.executable),
        actor.euid.to_string(),
        actor
            .start_time_ns
            .map(|start_time| ProcessStartKey { pid, start_time }),
    )
}

/// The object a file names, from the `stat` ESF captured with the event.
fn identity(file: &EsFile) -> Option<FileObjectIdentity> {
    crate::utils::file_identity::object_from_stat(&file.stat.to_libc())
}

fn build_create_event(msg: &impl EsMessage, destination: EsDestination) -> Option<RawEvent> {
    let (target, identity) = create_destination(destination)?;
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Create,
        pid,
        image,
        user,
        target,
        source: None,
        event_time: event_time(msg.raw_time())?,
        source_seq: msg.global_seq_num(),
        process_start_key,
        identity,
    })
}

fn build_unlink_event(msg: &impl EsMessage, unlink: &EsFile) -> Option<RawEvent> {
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Delete,
        pid,
        image,
        user,
        target: unlink.path.clone(),
        source: None,
        event_time: event_time(msg.raw_time())?,
        source_seq: msg.global_seq_num(),
        process_start_key,
        identity: None,
    })
}

fn build_rename_event(
    msg: &impl EsMessage,
    source: &EsFile,
    destination: EsDestination,
) -> Option<RawEvent> {
    let target = destination_path(destination)?;
    // A rename moves the source object, so its identity is the one that now
    // sits at the destination path.
    let identity = identity(source);
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Rename,
        pid,
        image,
        user,
        target,
        source: (!source.path.is_empty()).then(|| source.path.clone()),
        event_time: event_time(msg.raw_time())?,
        source_seq: msg.global_seq_num(),
        process_start_key,
        identity,
    })
}

/// Emit a modify event when a writable file is closed after being changed.
///
/// Filtering on `modified` keeps the high-volume close stream down to actual
/// content changes, the closest ESF analog to Sysmon's file-change event.
fn build_close_event(msg: &impl EsMessage, modified: bool, close: &EsFile) -> Option<RawEvent> {
    if !modified {
        return None;
    }
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Modify,
        pid,
        image,
        user,
        target: close.path.clone(),
        source: None,
        event_time: event_time(msg.raw_time())?,
        source_seq: msg.global_seq_num(),
        process_start_key,
        identity: identity(close),
    })
}

/// Resolve the absolute path of a create destination, and the created
/// object's identity when ESF reports it as an existing file.
fn create_destination(dest: EsDestination) -> Option<(String, Option<FileObjectIdentity>)> {
    let identity = match &dest {
        EsDestination::ExistingFile(file) => identity(file),
        EsDestination::NewPath { .. } => None,
    };
    let path = destination_path(dest)?;
    Some((path, identity))
}

/// Resolve the absolute path of a create or rename destination.
fn destination_path(dest: EsDestination) -> Option<String> {
    let path = match dest {
        EsDestination::ExistingFile(file) => file.path,
        EsDestination::NewPath {
            directory,
            filename,
        } => join_path(OsStr::new(&directory), OsStr::new(&filename)),
    };
    (!path.is_empty()).then_some(path)
}

/// Assemble a file [`RawEvent`] from FFI-free fields.
fn file_event(raw: RawFile) -> Option<RawEvent> {
    if raw.target.is_empty() {
        return None;
    }
    let (action, event_id, action_code) = raw.action.normalization();

    Some(RawEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::MacOS,
        provider: "esf",
        action,
        normalization: SensorNormalization {
            event_id,
            action_code,
        },
        pid: Some(raw.pid),
        timestamp: raw.event_time,
        source_seq: raw.source_seq,
        process_start_key: raw.process_start_key,
        parent_process_start_key: None,
        payload: RawPayload::File(FileEventFields {
            source_filename: raw.source,
            target_filename: Some(raw.target),
            process_id: Some(raw.pid.to_string()),
            image: raw.image,
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: Some(raw.user),
            file_identity: raw.identity,
            path_truncated: None,
        }),
    })
}

fn join_path(directory: &OsStr, filename: &OsStr) -> String {
    let mut path = PathBuf::from(directory);
    path.push(filename);
    path.to_string_lossy().into_owned()
}

// Read the raw timestamp because Message::time uses unchecked SystemTime addition.
fn event_time(time: EsTime) -> Option<SystemTime> {
    let seconds = u64::try_from(time.sec).ok()?;
    let nanos = u32::try_from(time.nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
}

fn system_time_nanos(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

/// Queue a decoded event, accounting for a drop rather than blocking.
///
/// The ESF message handler runs on the client's own queue and must return
/// promptly, so overflow is shed and counted, see [`crate::telemetry`].
fn try_send(tx: &Sender<RawEvent>, event: RawEvent) {
    let _ = crate::telemetry::try_send_sensor_event(tx, event);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The expected numbering for `action`, read from the shared table rather
    /// than from a macOS-local constant, asserting against a sensor's own
    /// constant is what let the platforms drift apart in the first place.
    fn shared(action: SensorAction) -> SensorNormalization {
        SensorNormalization::for_file_action(action).expect("file action is in the shared table")
    }

    #[test]
    fn event_timestamp_checks_components_and_extreme_values() {
        let raw = |seconds, nanos| EsTime {
            sec: seconds,
            nsec: nanos,
        };
        assert_eq!(event_time(raw(0, 0)), Some(SystemTime::UNIX_EPOCH));
        assert_eq!(
            event_time(raw(i64::MAX, 0)),
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(i64::MAX as u64))
        );
        assert_eq!(
            event_time(raw(1, 999_999_999)),
            SystemTime::UNIX_EPOCH.checked_add(Duration::new(1, 999_999_999))
        );
        for time in [raw(-1, 0), raw(0, -1), raw(0, 1_000_000_000)] {
            assert!(event_time(time).is_none());
        }
    }

    #[test]
    fn parent_token_is_probed_at_message_version_four() {
        // SAFETY: es_process_t is a plain C struct whose fields admit zero values,
        // including null raw pointers. This test only reads the audit token and
        // never dereferences executable or tty.
        let mut raw: endpoint_sec_sys::es_process_t = unsafe { std::mem::zeroed() };
        raw.parent_audit_token.val[5] = 42;
        raw.parent_audit_token.val[7] = 9;
        assert!(endpoint_sec::Process::new(&raw, 3)
            .parent_audit_token()
            .is_none());
        let token = endpoint_sec::Process::new(&raw, 4)
            .parent_audit_token()
            .unwrap();
        assert_eq!((token.pid(), token.pidversion()), (42, 9));
    }

    fn key(pid: u32, start_time: u64) -> ProcessStartKey {
        ProcessStartKey { pid, start_time }
    }

    #[test]
    fn long_lived_low_pid_survives_churn_past_the_cap() {
        let mut identities = ExecIdentities::default();
        identities.observe(1, key(1, 10));
        for pid in 100..(100 + 2 * EXEC_IDENTITY_CAP as u32) {
            identities.observe(1, key(pid, 20));
            identities.retire(pid, 1);
        }
        assert_eq!(identities.parent(1, Some(1)), Some(key(1, 10)));
        assert_eq!(identities.keys.len(), 1);
        assert_eq!(identities.order.len(), 1);
    }

    #[test]
    fn full_map_evicts_the_oldest_insertion_not_the_lowest_pid() {
        let mut identities = ExecIdentities::default();
        for pid in 100..(100 + EXEC_IDENTITY_CAP as u32 - 1) {
            identities.observe(1, key(pid, 20));
        }
        identities.observe(1, key(1, 10));
        for pid in 0..10 {
            identities.observe(1, key(1_000_000 + pid, 30));
        }
        assert_eq!(identities.parent(1, Some(1)), Some(key(1, 10)));
        assert_eq!(identities.parent(100, Some(1)), None);
        assert_eq!(identities.keys.len(), EXEC_IDENTITY_CAP);
        assert_eq!(identities.order.len(), EXEC_IDENTITY_CAP);
    }

    #[test]
    fn exit_retires_the_identity() {
        let mut identities = ExecIdentities::default();
        identities.observe(5, key(42, 100));
        identities.seed(key(43, 100));
        identities.retire(42, 5);
        identities.retire(43, 9);
        assert_eq!(identities.parent(42, Some(5)), None);
        assert_eq!(identities.parent(43, Some(9)), None);
        assert!(identities.keys.is_empty() && identities.order.is_empty());
    }

    #[test]
    fn seeded_parent_answers_only_until_the_pid_is_observed() {
        let mut identities = ExecIdentities::default();
        identities.seed(key(7, 50));
        assert_eq!(identities.parent(7, Some(3)), Some(key(7, 50)));
        assert_eq!(identities.parent(7, None), Some(key(7, 50)));
        identities.observe(4, key(7, 90));
        assert_eq!(identities.parent(7, Some(3)), None);
        assert_eq!(identities.parent(7, Some(4)), Some(key(7, 90)));
    }

    #[test]
    fn parent_resolution_preserves_generations_and_reparenting() {
        let mut identities = ExecIdentities::default();
        let old = ProcessStartKey {
            pid: 42,
            start_time: 100,
        };
        let new = ProcessStartKey {
            pid: 42,
            start_time: 200,
        };
        identities.observe(1, old);
        assert_eq!(identities.parent(42, None), Some(old));
        identities.observe(2, new);
        assert_eq!(identities.parent(42, Some(1)), Some(old));
        assert_eq!(identities.parent(42, Some(3)), None);
        assert_eq!(identities.parent(42, None), None);
        identities.observe(3, new);
        assert_eq!(identities.parent(42, Some(2)), None);
        assert_eq!(identities.parent(42, Some(3)), Some(new));
        assert_eq!(parent_identity(1, 42, Some((1, 9))), (42, None, true));
        assert_eq!(parent_identity(1, 42, Some((42, 1))), (42, Some(1), true));
        assert_eq!(parent_identity(42, 42, None), (42, None, true));
        assert_eq!(parent_identity(42, 42, Some((42, 1))), (42, Some(1), false));
    }

    #[test]
    fn signature_absence_is_unknown_and_invalid_is_still_signed() {
        assert!(RawMacOsExec::default().signature_status.is_none());
        assert_eq!(signature_status(0), "unsigned");
        assert_eq!(signature_status(0x2000_0000), "invalid");
        assert_eq!(signature_status(0x2000_0001), "valid");
    }

    #[test]
    fn reexec_keeps_actor_separate_from_cached_parent() {
        use crate::normalizer::Normalizer;
        use crate::state::HostState;
        let normalizer = Normalizer::new(Arc::new(HostState::default()));
        let unsigned_metadata = || RawMacOsExec {
            real_user_id: Some(0),
            signed: Some(false),
            signature_status: Some("unsigned".to_string()),
            codesigning_flags: Some(0),
            is_platform_binary: Some(false),
            ..Default::default()
        };
        let make = |pid, image: &str, parent: Option<ProcessStartKey>, metadata| {
            process_start_event(RawExec {
                pid,
                image: image.to_string(),
                command_line: Some(image.to_string()),
                parent_pid: parent.map_or(0, |key: ProcessStartKey| key.pid as i32),
                parent_process_start_key: parent,
                parent_derived: false,
                metadata,
                current_directory: None,
                user: 0,
                start_time: u64::from(pid),
                event_time: SystemTime::UNIX_EPOCH,
                source_seq: None,
            })
        };
        normalizer
            .normalize(&make(40, "/sbin/launchd", None, unsigned_metadata()))
            .unwrap();
        let parent = Some(ProcessStartKey {
            pid: 40,
            start_time: 40,
        });
        normalizer
            .normalize(&make(42, "/bin/bash", parent, unsigned_metadata()))
            .unwrap();
        let metadata = RawMacOsExec {
            signed: Some(true),
            pre_exec_image: Some("/bin/bash".to_string()),
            real_user_id: Some(501),
            script: Some("/tmp/payload.sh".to_string()),
            signature_status: Some("valid".to_string()),
            signing_id: Some("com.apple.sh".to_string()),
            team_id: Some("TEAM".to_string()),
            cdhash: Some("abcd".to_string()),
            codesigning_flags: Some(536_870_913),
            is_platform_binary: Some(true),
            ..Default::default()
        };
        let normalized = normalizer
            .normalize(&make(42, "/bin/sh", parent, metadata))
            .unwrap();
        assert_eq!(normalized.get_field("ParentImage"), Some("/sbin/launchd"));
        assert_eq!(normalized.get_field("PreExecImage"), Some("/bin/bash"));
        assert_eq!(normalized.get_field("Image"), Some("/bin/sh"));
        assert_eq!(normalized.get_field("User"), Some("root"));
        assert!(normalized.provenance.entries().iter().any(
            |entry| entry.field == "User" && entry.fidelity == crate::models::Fidelity::Derived
        ));
        assert_eq!(normalized.get_field("RealUserId"), Some("501"));
        assert_eq!(normalized.get_field("Script"), Some("/tmp/payload.sh"));
        assert_eq!(normalized.get_field("SignatureStatus"), Some("valid"));
        assert_eq!(normalized.get_field("Signed"), Some("true"));
        assert_eq!(normalized.get_field("IsPlatformBinary"), Some("true"));
        assert!(normalized
            .provenance
            .entries()
            .iter()
            .any(|entry| entry.field == "ParentImage"));
        normalizer.normalize(&process_stop_event(
            40,
            0,
            Some(40),
            SystemTime::UNIX_EPOCH,
            None,
        ));
        let mut orphan = make(43, "/bin/sh", parent, unsigned_metadata());
        if let RawPayload::Process(fields) = &mut orphan.payload {
            let RawProcessPlatform::MacOS(RawMacOsProcess {
                parent_process_id_derived,
                ..
            }) = fields.platform.as_mut()
            else {
                panic!("expected macOS process payload")
            };
            *parent_process_id_derived = true;
        }
        let orphan = normalizer.normalize(&orphan).unwrap();
        assert_eq!(orphan.get_field("ParentImage"), Some("/sbin/launchd"));
        assert!(orphan
            .provenance
            .entries()
            .iter()
            .any(|entry| entry.field == "ParentProcessId"));
        let json = serde_json::to_string(&normalized).unwrap();
        let replay: crate::models::NormalizedEvent = serde_json::from_str(&json).unwrap();
        for key in [
            "ParentImage",
            "PreExecImage",
            "RealUserId",
            "Script",
            "SignatureStatus",
            "Signed",
            "SigningId",
            "TeamId",
            "CdHash",
            "CodeSigningFlags",
            "IsPlatformBinary",
        ] {
            assert_eq!(replay.get_field(key), normalized.get_field(key), "{key}");
        }
    }

    #[test]
    fn not_permitted_hint_points_at_full_disk_access() {
        let msg = new_client_error_hint(&NewClientError::NotPermitted);
        assert!(msg.contains("NotPermitted"));
        assert!(msg.contains("Full Disk Access"));
    }

    #[test]
    fn not_privileged_hint_points_at_sudo() {
        let msg = new_client_error_hint(&NewClientError::NotPrivileged);
        assert!(msg.contains("sudo"));
    }

    #[test]
    fn process_start_event_maps_exec_fields() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let identity = crate::utils::file_identity::from_file(file.as_file());
        let event = process_start_event(RawExec {
            pid: 4242,
            image: "/usr/bin/curl".to_string(),
            command_line: Some("/usr/bin/curl https://example.test".to_string()),
            parent_pid: 501,
            parent_process_start_key: Some(ProcessStartKey {
                pid: 501,
                start_time: 100,
            }),
            parent_derived: false,
            metadata: RawMacOsExec {
                pre_exec_image: Some("/bin/zsh".to_string()),
                file_identity: identity.clone(),
                real_user_id: Some(501),
                signed: Some(false),
                signature_status: Some("unsigned".to_string()),
                codesigning_flags: Some(0),
                is_platform_binary: Some(false),
                ..Default::default()
            },
            current_directory: Some("/Users/alice".to_string()),
            user: 501,
            start_time: 1_700_000_000_000_000_000,
            event_time: SystemTime::UNIX_EPOCH,
            source_seq: Some(77),
        });

        assert_eq!(event.platform, Platform::MacOS);
        assert_eq!(event.provider, "esf");
        assert_eq!(event.action, SensorAction::Start);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_CREATE);
        assert_eq!(event.pid, Some(4242));
        assert_eq!(event.source_seq, Some(77));
        let canonical = Arc::new(crate::state::HostState::default())
            .canonicalize(event.clone())
            .unwrap();
        let target = crate::artifact::ArtifactTarget::select_event(&canonical, None)
            .expect("process start is an artifact target");
        assert_eq!(
            target.expected,
            identity.map(crate::artifact::ExpectedIdentity::Exact)
        );

        assert_eq!(
            event.process_start_key,
            Some(ProcessStartKey {
                pid: 4242,
                start_time: 1_700_000_000_000_000_000,
            })
        );

        match event.payload {
            RawPayload::Process(fields) => {
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/curl"));
                assert_eq!(
                    fields.command_line.as_deref(),
                    Some("/usr/bin/curl https://example.test")
                );
                assert_eq!(fields.process_id, 4242);
                assert_eq!(fields.parent_process_id, Some(501));
                assert_eq!(fields.current_directory.as_deref(), Some("/Users/alice"));
                assert_eq!(fields.user, Some(RawUserId::Unix(501)));
                assert!(fields.parent_image.is_none());
                let RawProcessPlatform::MacOS(source) = *fields.platform else {
                    panic!("expected macOS process payload")
                };
                assert_eq!(
                    source.exec.unwrap().pre_exec_image.as_deref(),
                    Some("/bin/zsh")
                );
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
            source_seq: None,
            process_start_key: Some(ProcessStartKey {
                pid: 55,
                start_time: 123_456,
            }),
            identity: None,
        }
    }

    #[test]
    fn file_event_maps_create() {
        let event = file_event(raw_file(FileAction::Create, "/tmp/new.txt", None))
            .expect("create event should build");
        assert_eq!(event.action, SensorAction::Create);
        assert_eq!(event.normalization, shared(SensorAction::Create));
        assert_eq!(event.pid, Some(55));
        assert_eq!(
            event.process_start_key,
            Some(ProcessStartKey {
                pid: 55,
                start_time: 123_456,
            })
        );

        match event.payload {
            RawPayload::File(fields) => {
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
        assert_eq!(event.normalization, shared(SensorAction::Delete));
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
        assert_eq!(event.normalization, shared(SensorAction::Rename));

        match event.payload {
            RawPayload::File(fields) => {
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
        // Modify must not report under FileCreate (11): that would route macOS
        // writes into `file_create` instead of `file_change` (issue #239).
        assert_eq!(event.normalization, shared(SensorAction::Modify));
        assert_eq!(event.normalization.event_id, 65);
    }

    #[test]
    fn file_event_carries_the_esf_measured_identity() {
        // Written-file YARA refuses a target without this identity, so a
        // file event that drops it silently disables content inspection.
        let identity = FileObjectIdentity {
            device: 16_777_231,
            inode: 4_242,
        };
        let mut raw = raw_file(FileAction::Modify, "/tmp/payload.py", None);
        raw.identity = Some(identity);
        let event = file_event(raw).expect("modify event should build");
        match event.payload {
            RawPayload::File(fields) => assert_eq!(fields.file_identity, Some(identity)),
            other => panic!("unexpected payload: {other:?}"),
        }
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
        let event = process_stop_event(4242, 501, Some(123_456), SystemTime::UNIX_EPOCH, None);

        assert_eq!(event.action, SensorAction::Stop);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_TERMINATE);
        assert_eq!(event.pid, Some(4242));
        assert_eq!(
            event.process_start_key,
            Some(ProcessStartKey {
                pid: 4242,
                start_time: 123_456,
            })
        );

        match event.payload {
            RawPayload::Process(fields) => {
                assert_eq!(fields.process_id, 4242);
                assert_eq!(fields.user, Some(RawUserId::Unix(501)));
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
            parent_process_start_key: None,
            parent_derived: false,
            metadata: Default::default(),
            current_directory: None,
            user: 0,
            start_time: 0,
            event_time: SystemTime::UNIX_EPOCH,
            source_seq: None,
        });

        match event.payload {
            RawPayload::Process(fields) => {
                assert!(fields.parent_process_id.is_none());
                assert!(fields.command_line.is_none());
                assert!(fields.current_directory.is_none());
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}
