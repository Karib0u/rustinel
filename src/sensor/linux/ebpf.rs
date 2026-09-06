//! Linux eBPF sensor — userspace loader and ring-buffer dispatcher.
//!
//! [`EbpfSensor`] implements [`Sensor`] for Linux. On `start()` it:
//!
//! 1. Loads the eBPF object embedded at compile time (or from the path given
//!    by `RUSTINEL_EBPF_OBJECT` for development overrides).
//! 2. Loads and attaches the Linux telemetry eBPF programs.
//! 3. Takes ownership of the ring-buffer maps.
//! 4. Spawns a tokio task that polls all ring buffers and converts raw events
//!    into [`SensorEvent`] values for the shared pipeline.
//!
//! Requirements: Linux 5.8+ with BTF, `CAP_BPF` (or `CAP_SYS_ADMIN`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

use crate::models::{
    DnsQueryFields, FileEventFields, NetworkConnectionFields, ProcessCreationFields,
};
use crate::sensor::{
    Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorNormalization,
    SensorPayload,
};
use crate::utils::{
    lookup_username_by_uid, query_process_details, query_socket_metadata, SocketMetadata,
};

use super::events::{
    bytes_to_string, connect_result_is_connection, parse_event, DnsEvent, FileEvent,
    FileEventHeader, FileIndexEvent, NetworkEvent, ProcessEvent,
};
use super::paths::{resolve_at_path, resolve_indexable_dir_path, truncation_marker, DirFdIndex};

/// Sysmon-compatible event IDs emitted for Linux events.
const EVENT_ID_PROCESS_CREATE: u16 = 1;
const EVENT_ID_PROCESS_TERMINATE: u16 = 5;
const EVENT_ID_NETWORK_CONNECT: u16 = 3;
const EVENT_ID_DNS_QUERY: u16 = 22;
// File event IDs come from `SensorNormalization::for_file_action`, the shared
// table in `crate::sensor`, so they cannot drift from the other platforms.

const PROCESS_EVENT_EXEC: u32 = 1;
const PROCESS_EVENT_EXIT: u32 = 2;

const FILE_EVENT_CREATE: u32 = 1;
const FILE_EVENT_DELETE: u32 = 2;
const FILE_EVENT_RENAME: u32 = 3;
const FILE_EVENT_CHANGE: u32 = 4;
/// Not a file event: a directory descriptor being opened. Consumed by the
/// drain loop to name the `dfd` of later `*at` calls, never forwarded.
const FILE_EVENT_DIR_OPEN: u32 = 5;
const FILE_EVENT_INDEX_RESET: u32 = 6;

/// Linux eBPF sensor. Implements [`Sensor`]; call `start()` from within a
/// tokio runtime context.
pub struct EbpfSensor {
    shutdown: Arc<AtomicBool>,
}

impl EbpfSensor {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for EbpfSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for EbpfSensor {
    /// Load eBPF programs, attach tracepoints, and spawn the ring-buffer
    /// polling task. Returns immediately; the task runs in the background.
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        // Use the embedded object by default; accept an env-var override so
        // developers can hot-swap a freshly compiled eBPF binary without
        // rebuilding the whole userspace crate.
        let override_bytes: Option<Vec<u8>> = match std::env::var_os(super::EBPF_OBJECT_ENV) {
            Some(path) => {
                info!("loading eBPF object from override path {:?}", path);
                Some(std::fs::read(&path).with_context(|| {
                    format!("failed to read eBPF override object from {:?}", path)
                })?)
            }
            None => {
                info!("loading embedded eBPF object");
                None
            }
        };
        let bytes: &[u8] = override_bytes.as_deref().unwrap_or(super::EBPF_BYTES);

        let mut bpf = Ebpf::load(bytes)
            .context("eBPF object load failed — ensure BTF is available and kernel is 5.8+")?;

        // ── Attach programs ──────────────────────────────────────────────────

        attach_tracepoint(&mut bpf, "handle_exec", "sched", "sched_process_exec")?;
        attach_tracepoint(&mut bpf, "handle_exit", "sched", "sched_process_exit")?;
        attach_tracepoint(&mut bpf, "handle_file_exec", "sched", "sched_process_exec")?;
        attach_tracepoint(&mut bpf, "handle_file_exit", "sched", "sched_process_exit")?;
        // argv is only reachable while `execve` is still running, so it is
        // snapshotted at syscall entry and joined to the exec event above.
        attach_tracepoint(&mut bpf, "handle_execve", "syscalls", "sys_enter_execve")?;
        attach_tracepoint(
            &mut bpf,
            "handle_execveat",
            "syscalls",
            "sys_enter_execveat",
        )?;
        // Entry captures the destination while the sockaddr is still readable;
        // exit is what decides whether the attempt became a connection.
        attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect")?;
        attach_tracepoint(
            &mut bpf,
            "handle_connect_exit",
            "syscalls",
            "sys_exit_connect",
        )?;
        // `connect()` does not name its transport; the socket type is only
        // visible while `socket()` runs, and its descriptor only on return.
        attach_tracepoint(&mut bpf, "handle_socket", "syscalls", "sys_enter_socket")?;
        attach_tracepoint(
            &mut bpf,
            "handle_socket_exit",
            "syscalls",
            "sys_exit_socket",
        )?;
        attach_tracepoint(&mut bpf, "handle_openat", "syscalls", "sys_enter_openat")?;
        attach_kprobe(&mut bpf, "handle_vfs_create", "vfs_create")?;
        attach_tracepoint(
            &mut bpf,
            "handle_openat_exit",
            "syscalls",
            "sys_exit_openat",
        )?;
        attach_tracepoint(
            &mut bpf,
            "handle_unlinkat",
            "syscalls",
            "sys_enter_unlinkat",
        )?;
        attach_tracepoint(
            &mut bpf,
            "handle_unlinkat_exit",
            "syscalls",
            "sys_exit_unlinkat",
        )?;
        attach_tracepoint(
            &mut bpf,
            "handle_renameat",
            "syscalls",
            "sys_enter_renameat",
        )?;
        attach_tracepoint(
            &mut bpf,
            "handle_renameat_exit",
            "syscalls",
            "sys_exit_renameat",
        )?;
        attach_tracepoint(
            &mut bpf,
            "handle_renameat2",
            "syscalls",
            "sys_enter_renameat2",
        )?;
        attach_tracepoint(
            &mut bpf,
            "handle_renameat2_exit",
            "syscalls",
            "sys_exit_renameat2",
        )?;
        attach_tracepoint(&mut bpf, "handle_file_close", "syscalls", "sys_enter_close")?;
        attach_optional_tracepoint(&mut bpf, "handle_file_dup2", "syscalls", "sys_enter_dup2")?;
        attach_tracepoint(&mut bpf, "handle_file_dup3", "syscalls", "sys_enter_dup3")?;
        attach_optional_tracepoint(
            &mut bpf,
            "handle_file_close_range",
            "syscalls",
            "sys_enter_close_range",
        )?;
        attach_tracepoint(&mut bpf, "handle_sendto", "syscalls", "sys_enter_sendto")?;
        attach_tracepoint(&mut bpf, "handle_sendmsg", "syscalls", "sys_enter_sendmsg")?;
        attach_tracepoint(
            &mut bpf,
            "handle_sendmmsg",
            "syscalls",
            "sys_enter_sendmmsg",
        )?;

        info!("eBPF tracepoints attached");

        // ── Take ring-buffer maps ────────────────────────────────────────────

        let process_ring: RingBuf<MapData> = RingBuf::try_from(
            bpf.take_map("PROCESS_RING")
                .context("PROCESS_RING map not found in eBPF object")?,
        )?;
        let network_ring: RingBuf<MapData> = RingBuf::try_from(
            bpf.take_map("NETWORK_RING")
                .context("NETWORK_RING map not found in eBPF object")?,
        )?;
        let file_ring: RingBuf<MapData> = RingBuf::try_from(
            bpf.take_map("FILE_RING")
                .context("FILE_RING map not found in eBPF object")?,
        )?;
        let dns_ring: RingBuf<MapData> = RingBuf::try_from(
            bpf.take_map("DNS_RING")
                .context("DNS_RING map not found in eBPF object")?,
        )?;

        // ── Spawn polling task ───────────────────────────────────────────────

        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            // Keep `bpf` alive here — dropping it detaches the programs.
            let _bpf = bpf;

            if let Err(e) = run_ring_poll(
                process_ring,
                network_ring,
                file_ring,
                dns_ring,
                tx,
                shutdown,
            )
            .await
            {
                error!("eBPF ring-buffer poller exited with error: {:#}", e);
            }
        });

        Ok(())
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

// ── Ring-buffer polling ──────────────────────────────────────────────────────

async fn run_ring_poll(
    process_ring: RingBuf<MapData>,
    network_ring: RingBuf<MapData>,
    file_ring: RingBuf<MapData>,
    dns_ring: RingBuf<MapData>,
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let mut process_fd: AsyncFd<RingBuf<MapData>> = AsyncFd::new(process_ring)?;
    let mut network_fd: AsyncFd<RingBuf<MapData>> = AsyncFd::new(network_ring)?;
    let mut file_fd: AsyncFd<RingBuf<MapData>> = AsyncFd::new(file_ring)?;
    let mut dns_fd: AsyncFd<RingBuf<MapData>> = AsyncFd::new(dns_ring)?;
    let mut unresolved_file_events: u64 = 0;
    let mut dir_fds = DirFdIndex::new();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!("eBPF sensor shutting down");
            break;
        }

        tokio::select! {
            biased;

            Ok(mut guard) = process_fd.readable_mut() => {
                let rb: &mut RingBuf<MapData> = guard.get_inner_mut();
                drain_process_ring(rb, &tx);
                guard.clear_ready();
            }

            Ok(mut guard) = network_fd.readable_mut() => {
                let rb: &mut RingBuf<MapData> = guard.get_inner_mut();
                drain_network_ring(rb, &tx);
                guard.clear_ready();
            }

            Ok(mut guard) = file_fd.readable_mut() => {
                let rb: &mut RingBuf<MapData> = guard.get_inner_mut();
                drain_file_ring(rb, &tx, &mut dir_fds, &mut unresolved_file_events);
                guard.clear_ready();
            }

            Ok(mut guard) = dns_fd.readable_mut() => {
                let rb: &mut RingBuf<MapData> = guard.get_inner_mut();
                drain_dns_ring(rb, &tx);
                guard.clear_ready();
            }

            // Wake up periodically to check the shutdown flag even when
            // the ring buffers are idle.
            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
        }
    }

    Ok(())
}

// ── Ring-buffer drain helpers ────────────────────────────────────────────────

fn drain_process_ring(rb: &mut RingBuf<MapData>, tx: &Sender<SensorEvent>) {
    while let Some(item) = rb.next() {
        let bytes: &[u8] = &item;
        let Some(ev) = parse_event::<ProcessEvent>(bytes) else {
            warn!("process ring: short read ({} bytes)", bytes.len());
            continue;
        };
        if let Some(sensor_event) = build_process_event(&ev) {
            try_send(tx, sensor_event);
        }
    }
}

fn drain_network_ring(rb: &mut RingBuf<MapData>, tx: &Sender<SensorEvent>) {
    while let Some(item) = rb.next() {
        let bytes: &[u8] = &item;
        let Some(ev) = parse_event::<NetworkEvent>(bytes) else {
            warn!("network ring: short read ({} bytes)", bytes.len());
            continue;
        };
        if let Some(sensor_event) = build_network_event(&ev) {
            try_send(tx, sensor_event);
        }
    }
}

/// Drain the file ring.
///
/// `unresolved` counts events dropped because their path could not be rebuilt.
/// It lives with the poll loop rather than being recomputed per call, so the
/// size of that blind spot stays visible in the log. See
/// [`super::paths`] for when resolution fails.
fn drain_file_ring(
    rb: &mut RingBuf<MapData>,
    tx: &Sender<SensorEvent>,
    dir_fds: &mut DirFdIndex,
    unresolved: &mut u64,
) {
    while let Some(item) = rb.next() {
        let bytes: &[u8] = &item;
        let Some(header) = parse_event::<FileEventHeader>(bytes) else {
            warn!("file ring: short read ({} bytes)", bytes.len());
            continue;
        };
        if header.kind == FILE_EVENT_INDEX_RESET {
            let Some(ev) = parse_event::<FileIndexEvent>(bytes) else {
                warn!("file index ring: short read ({} bytes)", bytes.len());
                continue;
            };
            dir_fds.forget_process(ev.pid);
            continue;
        }
        let Some(ev) = parse_event::<FileEvent>(bytes) else {
            warn!("file ring: short read ({} bytes)", bytes.len());
            continue;
        };
        if ev.kind == FILE_EVENT_DIR_OPEN {
            index_dir_open(&ev, dir_fds);
            continue;
        }
        if let Some(sensor_event) = build_file_event(&ev, dir_fds, unresolved) {
            try_send(tx, sensor_event);
        }
    }
}

/// Record what a freshly opened directory descriptor points at.
///
/// `dfd` holds the descriptor the open produced and `aux_dfd` the one its own
/// name was relative to, since `openat(dirfd, "sub", O_DIRECTORY)` is ordinary.
/// A directory whose own path cannot be resolved is skipped rather than indexed
/// under a guess — the next `*at` call against it then falls back to `/proc`.
fn index_dir_open(ev: &FileEvent, dir_fds: &mut DirFdIndex) {
    let raw = bytes_to_string(&ev.path);
    if raw.is_empty() || ev.flags & super::events::FILE_FLAG_PATH_TRUNCATED != 0 {
        return;
    }
    if let Some(path) =
        resolve_indexable_dir_path(dir_fds, ev.pid, ev.aux_dfd, ev.aux_dfd_token, &raw)
    {
        dir_fds.insert(ev.pid, ev.dfd, ev.dfd_token, path);
    }
}

fn drain_dns_ring(rb: &mut RingBuf<MapData>, tx: &Sender<SensorEvent>) {
    while let Some(item) = rb.next() {
        let bytes: &[u8] = &item;
        let Some(ev) = parse_event::<DnsEvent>(bytes) else {
            warn!("dns ring: short read ({} bytes)", bytes.len());
            continue;
        };
        if let Some(sensor_event) = build_dns_event(&ev) {
            try_send(tx, sensor_event);
        }
    }
}

// ── Event builders ───────────────────────────────────────────────────────────

/// Pick the image path for an exec event.
///
/// The tracepoint carries `bprm->filename`, i.e. the literal string userspace
/// passed to `execve()` — `./malware` stays `./malware`. Downstream consumers
/// (YARA queueing, the allowlist, Sigma `Image` rules, IOC path regexes) all
/// need a real path, so prefer `/proc/<pid>/exe`, which is absolute,
/// symlink-resolved, and immune to the caller's `chdir`. The raw kernel string
/// stays as a fallback for short-lived processes that exit before the userspace
/// ring drain gets to `/proc`.
fn resolve_exec_image(
    proc_exe: Option<&str>,
    raw_filename: &str,
) -> Option<(String, &'static str)> {
    if let Some(image) = proc_exe.filter(|value| !value.is_empty()) {
        return Some((image.to_string(), "proc"));
    }

    Some((raw_filename.to_string(), "execve")).filter(|(value, _)| !value.is_empty())
}

/// Pick the command line for an exec event.
///
/// The kernel capture is authoritative when it is complete: it is the argv
/// this exec was called with, taken before the process could exit or exec
/// again. `/proc/<pid>/cmdline` is only consulted when the kernel capture is
/// missing or hit its bounds — and the truncated kernel value is still better
/// than nothing when `/proc` has already gone away.
fn resolve_command_line(
    kernel: Option<String>,
    truncated: bool,
    proc_cmdline: Option<String>,
) -> Option<String> {
    match kernel {
        Some(value) if !truncated => Some(value),
        Some(value) => proc_cmdline.or(Some(value)),
        None => proc_cmdline,
    }
}

fn build_process_event(ev: &ProcessEvent) -> Option<SensorEvent> {
    let user = resolved_linux_user(ev.uid);
    match ev.kind {
        PROCESS_EVENT_EXEC => {
            let details = query_process_details(ev.pid);
            let (image, image_source) = resolve_exec_image(
                details.as_ref().and_then(|value| value.image.as_deref()),
                &bytes_to_string(&ev.image),
            )?;

            let now = SystemTime::now();
            Some(SensorEvent {
                platform: Platform::Linux,
                provider: "ebpf",
                action: SensorAction::Start,
                normalization: SensorNormalization {
                    event_id: EVENT_ID_PROCESS_CREATE,
                    action_code: 1,
                },
                pid: Some(ev.pid),
                timestamp: now,
                process_start_key: Some(ProcessStartKey {
                    pid: ev.pid,
                    start_time: details
                        .as_ref()
                        .and_then(|value| value.start_time)
                        .unwrap_or_else(|| unix_epoch_nanos(now)),
                }),
                payload: SensorPayload::Process(ProcessCreationFields {
                    image: Some(image),
                    image_source: Some(image_source.to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    company: None,
                    file_version: None,
                    target_image: None,
                    command_line: resolve_command_line(
                        ev.kernel_command_line(),
                        ev.args_truncated != 0,
                        details
                            .as_ref()
                            .and_then(|value| value.command_line.clone()),
                    ),
                    process_id: Some(ev.pid.to_string()),
                    process_start_time: None,
                    parent_process_id: details
                        .as_ref()
                        .and_then(|value| value.parent_process_id.map(|pid| pid.to_string())),
                    parent_image: details
                        .as_ref()
                        .and_then(|value| value.parent_image.clone()),
                    parent_command_line: details
                        .as_ref()
                        .and_then(|value| value.parent_command_line.clone()),
                    current_directory: details
                        .as_ref()
                        .and_then(|value| value.current_directory.clone()),
                    // Windows-specific; absent on Linux.
                    integrity_level: None,
                    user: Some(user),
                }),
            })
        }
        PROCESS_EVENT_EXIT => Some(SensorEvent {
            platform: Platform::Linux,
            provider: "ebpf",
            action: SensorAction::Stop,
            normalization: SensorNormalization {
                event_id: EVENT_ID_PROCESS_TERMINATE,
                action_code: 2,
            },
            pid: Some(ev.pid),
            timestamp: SystemTime::now(),
            process_start_key: None,
            payload: SensorPayload::Process(ProcessCreationFields {
                image: None,
                image_source: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                command_line: None,
                process_id: Some(ev.pid.to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some(user),
            }),
        }),
        _ => None,
    }
}

fn build_network_event(ev: &NetworkEvent) -> Option<SensorEvent> {
    // The kernel emits only attempts that connected, so this rejects nothing
    // in practice. It is the decode-side half of that contract: a refused or
    // unreachable destination is an attempt, not a connection, and a rule
    // matching "connection to suspicious IP" must not fire on one.
    if !connect_result_is_connection(ev.ret) {
        return None;
    }
    if ev.dport == 0 {
        return None;
    }

    let (destination_ip, source_ip) = match ev.af {
        2 => {
            // AF_INET
            let dst = Ipv4Addr::new(ev.daddr[0], ev.daddr[1], ev.daddr[2], ev.daddr[3]);
            let src = Ipv4Addr::new(ev.saddr[0], ev.saddr[1], ev.saddr[2], ev.saddr[3]);
            if dst.is_unspecified() {
                return None;
            }
            let source_ip = if src.is_unspecified() {
                None
            } else {
                Some(src.to_string())
            };
            (dst.to_string(), source_ip)
        }
        10 => {
            // AF_INET6
            let dst = Ipv6Addr::from(ev.daddr);
            let src = Ipv6Addr::from(ev.saddr);
            if dst.is_unspecified() {
                return None;
            }
            let source_ip = if src.is_unspecified() {
                None
            } else {
                Some(src.to_string())
            };
            (dst.to_string(), source_ip)
        }
        _ => return None,
    };

    // `/proc` is read after the fact, so it may describe a different socket
    // than the one this event captured; see `socket_matches_connection`.
    let socket_metadata = query_socket_metadata(ev.pid, ev.fd)
        .filter(|value| socket_matches_connection(value, &destination_ip, ev.dport));
    let user = resolved_linux_user(ev.uid);
    let source_ip = source_ip.or_else(|| {
        socket_metadata
            .as_ref()
            .and_then(|value| filter_unspecified_ip(value.source_ip.clone()))
            // A v4-mapped local address belongs to an IPv4 connection; keeping
            // the `::ffff:` form would make `network.type` disagree with the
            // destination it is paired with.
            .map(|value| match value.parse::<IpAddr>() {
                Ok(address) => unmap_ipv4(address).to_string(),
                Err(_) => value,
            })
    });
    let source_port = if ev.sport > 0 {
        Some(ev.sport.to_string())
    } else {
        // An unbound socket can still be listed with a local port of 0. That
        // is a placeholder, not a measurement, so it is dropped like the
        // unspecified source address above.
        socket_metadata
            .as_ref()
            .and_then(|value| value.source_port)
            .filter(|port| *port > 0)
            .map(|port| port.to_string())
    };

    Some(SensorEvent {
        platform: Platform::Linux,
        provider: "ebpf",
        action: SensorAction::Connect,
        normalization: SensorNormalization {
            event_id: EVENT_ID_NETWORK_CONNECT,
            action_code: 0,
        },
        pid: Some(ev.pid),
        timestamp: SystemTime::now(),
        process_start_key: None,
        payload: SensorPayload::Network(NetworkConnectionFields {
            destination_ip: Some(destination_ip),
            source_ip,
            destination_port: Some(ev.dport.to_string()),
            source_port,
            process_id: Some(ev.pid.to_string()),
            // Enriched by the normalizer from ProcessCache if PID is known.
            image: None,
            user: Some(user),
            destination_hostname: None,
            // The kernel-side socket type is authoritative: it is recorded when
            // the socket is created, while `/proc/net` is read after the event
            // is drained and answers for whatever the descriptor points at then.
            protocol: ev
                .transport()
                .map(str::to_string)
                .or_else(|| socket_metadata.and_then(|value| value.protocol)),
            // The probe hooks `connect()` only, so every captured connection
            // is one this host opened. `accept()` is not hooked, so no inbound
            // connection can reach here and be mislabelled.
            initiated: Some(true),
        }),
    })
}

fn build_file_event(
    ev: &FileEvent,
    dir_fds: &DirFdIndex,
    unresolved: &mut u64,
) -> Option<SensorEvent> {
    let raw_path = bytes_to_string(&ev.path);
    if raw_path.is_empty() {
        return None;
    }

    let action = match ev.kind {
        FILE_EVENT_CREATE => SensorAction::Create,
        FILE_EVENT_DELETE => SensorAction::Delete,
        FILE_EVENT_RENAME => SensorAction::Rename,
        FILE_EVENT_CHANGE => SensorAction::Modify,
        _ => return None,
    };
    let normalization = SensorNormalization::for_file_action(action)
        .expect("file actions are covered by the shared file normalization table");

    // A relative name that cannot be tied back to its directory is worse than
    // no event: `TargetFilename|endswith: '/passwd'` would fire on any
    // `openat(dirfd, "passwd")` anywhere on the disk. Dropping is the same
    // policy the Windows sensor applies to events it cannot name.
    let Some(target_filename) = resolve_at_path(dir_fds, ev.pid, ev.dfd, ev.dfd_token, &raw_path)
    else {
        *unresolved += 1;
        if *unresolved == 1 || unresolved.is_multiple_of(1000) {
            debug!(
                unresolved_file_events = *unresolved,
                raw_path = %raw_path,
                "Dropping file event whose path could not be resolved"
            );
        }
        return None;
    };

    // Rename resolves its two names independently: they carry separate
    // descriptors and `renameat(olddfd, .., newdfd, ..)` may cross directories.
    // A source that cannot be resolved is omitted rather than guessed, which
    // keeps the event's target usable.
    let source_filename = (ev.kind == FILE_EVENT_RENAME)
        .then(|| bytes_to_string(&ev.aux_path))
        .filter(|value| !value.is_empty())
        .and_then(|value| resolve_at_path(dir_fds, ev.pid, ev.aux_dfd, ev.aux_dfd_token, &value));

    let user = resolved_linux_user(ev.uid);
    let comm = bytes_to_string(&ev.comm);
    let path_truncated = truncation_marker(ev.flags, source_filename.is_some()).map(str::to_string);

    Some(SensorEvent {
        platform: Platform::Linux,
        provider: "ebpf",
        action,
        normalization,
        pid: Some(ev.pid),
        timestamp: SystemTime::now(),
        process_start_key: None,
        payload: SensorPayload::File(FileEventFields {
            source_filename,
            target_filename: Some(target_filename),
            process_id: Some(ev.pid.to_string()),
            image: if comm.is_empty() { None } else { Some(comm) },
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: Some(user),
            path_truncated,
        }),
    })
}

fn build_dns_event(ev: &DnsEvent) -> Option<SensorEvent> {
    let record_type = bytes_to_string(&ev.record_type);
    // Drop events with no record type — they carry no detection signal.
    if record_type.is_empty() {
        return None;
    }

    let query_name = parse_dns_query_name(ev).or_else(|| {
        let value = bytes_to_string(&ev.query_name);
        (!value.is_empty()).then_some(value)
    });
    let query_results = {
        let value = bytes_to_string(&ev.query_results);
        (!value.is_empty()).then_some(value)
    };

    Some(SensorEvent {
        platform: Platform::Linux,
        provider: "ebpf",
        action: SensorAction::Query,
        normalization: SensorNormalization {
            event_id: EVENT_ID_DNS_QUERY,
            action_code: 0,
        },
        pid: Some(ev.pid),
        timestamp: SystemTime::now(),
        process_start_key: None,
        payload: SensorPayload::Dns(DnsQueryFields {
            query_name,
            query_results,
            record_type: Some(record_type),
            query_status: None,
            process_id: Some(ev.pid.to_string()),
            image: None,
        }),
    })
}

fn parse_dns_query_name(ev: &DnsEvent) -> Option<String> {
    let payload_len = usize::from(ev.payload_len).min(ev.payload.len());
    let payload = ev.payload.get(..payload_len)?;
    crate::sensor::dns::parse_question(payload).map(|(name, _qtype)| name)
}

// ── Utilities ────────────────────────────────────────────────────────────────

/// Queue a decoded event, accounting for a drop rather than blocking.
///
/// Blocking here would stall the perf-buffer poll loop and lose the events
/// behind it in the kernel instead, so overflow is shed. The count is what
/// makes that trade auditable — see [`crate::telemetry`].
fn try_send(tx: &Sender<SensorEvent>, event: SensorEvent) {
    // Both the full and closed cases are already counted; the reason is in the
    // rate-limited warning the telemetry module emits.
    let _ = crate::telemetry::try_send_sensor_event(tx, event);
}

fn resolved_linux_user(uid: u32) -> String {
    lookup_username_by_uid(uid).unwrap_or_else(|| uid.to_string())
}

fn unix_epoch_nanos(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

/// Does this `/proc/net` entry describe the connection the probe reported?
///
/// The metadata is resolved from `/proc/<pid>/fd/<fd>` well after the
/// `connect()` entry that produced the event. A process that closes and reuses
/// the descriptor in between — what happy-eyeballs does on every dual-stack
/// name — hands back a different socket, whose local address and protocol
/// would then be attributed to this connection. That is the same failure as
/// reporting an unassigned address: a value nothing downstream can tell apart
/// from a measured one. Accept the entry only when its remote end is the one
/// the probe saw.
fn socket_matches_connection(
    metadata: &SocketMetadata,
    destination_ip: &str,
    destination_port: u16,
) -> bool {
    let ip_matches = metadata
        .destination_ip
        .as_deref()
        .is_none_or(|value| same_ip(value, destination_ip));
    let port_matches = metadata
        .destination_port
        .is_none_or(|value| value == destination_port);
    ip_matches && port_matches
}

/// Compare two addresses, treating an IPv4-mapped form as its IPv4 address.
///
/// A dual-stack socket reaching an IPv4 peer is listed in `/proc/net/tcp6` as
/// `::ffff:a.b.c.d`, while the probe read `a.b.c.d` out of the `sockaddr`.
/// They are the same peer.
fn same_ip(left: &str, right: &str) -> bool {
    match (left.parse::<IpAddr>(), right.parse::<IpAddr>()) {
        (Ok(left), Ok(right)) => unmap_ipv4(left) == unmap_ipv4(right),
        _ => left == right,
    }
}

fn unmap_ipv4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn filter_unspecified_ip(value: Option<String>) -> Option<String> {
    let ip = value?;
    let is_unspecified = ip
        .parse::<std::net::IpAddr>()
        .map(|value| value.is_unspecified())
        .unwrap_or(false);
    (!is_unspecified).then_some(ip)
}

fn attach_optional_tracepoint(
    bpf: &mut Ebpf,
    program: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let available = [
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ]
    .into_iter()
    .map(|root| {
        std::path::Path::new(root)
            .join(category)
            .join(name)
            .join("id")
    })
    .any(|path| path.exists());
    if available {
        attach_tracepoint(bpf, program, category, name)
    } else {
        warn!(
            program,
            category, name, "optional tracepoint is unavailable"
        );
        Ok(())
    }
}

fn attach_tracepoint(bpf: &mut Ebpf, program: &str, category: &str, name: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(program)
        .with_context(|| format!("program '{}' not found in eBPF object", program))?
        .try_into()
        .with_context(|| format!("program '{}' is not a TracePoint", program))?;

    prog.load()
        .with_context(|| format!("failed to load tracepoint '{}'", program))?;

    prog.attach(category, name)
        .with_context(|| format!("failed to attach '{}' to {}/{}", program, category, name))?;

    Ok(())
}

fn attach_kprobe(bpf: &mut Ebpf, program: &str, function: &str) -> Result<()> {
    let prog: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program '{}' not found in eBPF object", program))?
        .try_into()
        .with_context(|| format!("program '{}' is not a KProbe", program))?;

    prog.load()
        .with_context(|| format!("failed to load kprobe '{}'", program))?;

    prog.attach(function, 0)
        .with_context(|| format!("failed to attach '{}' to {}", program, function))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IocConfig;
    use crate::engine::Engine;
    use crate::ioc::{IocEngine, IocKind};
    use crate::models::EventFields;
    use crate::normalizer::Normalizer;
    use crate::sensor::linux::events::{
        ARGV_CAPACITY, FILE_FLAG_AUX_PATH_TRUNCATED, FILE_FLAG_PATH_TRUNCATED, FILE_PATH_LEN,
    };
    use crate::sensor::linux::paths::AT_FDCWD;
    use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
    use std::sync::Arc;

    /// Build a `ProcessEvent` the way the kernel would, with no argv capture.
    /// Tests that exercise argv override `args*` explicitly.
    fn raw_process_event(kind: u32, pid: u32, image: &str) -> ProcessEvent {
        ProcessEvent {
            kind,
            pid,
            uid: 1000,
            _pad: 0,
            comm: fixed("bash"),
            image: fixed(image),
            args_len: 0,
            args_count: 0,
            args_truncated: 0,
            _pad1: [0u8; 3],
            args: [0u8; ARGV_CAPACITY],
        }
    }

    /// Pack argv the way `read_argv` does: NUL-separated, `args_len` bytes.
    fn packed_argv(args: &[&str]) -> ([u8; ARGV_CAPACITY], u16, u16) {
        let mut buf = [0u8; ARGV_CAPACITY];
        let mut offset = 0usize;
        for arg in args {
            let bytes = arg.as_bytes();
            buf[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len() + 1;
        }
        (buf, offset as u16, args.len() as u16)
    }

    fn fixed<const N: usize>(value: &str) -> [u8; N] {
        let mut buf = [0u8; N];
        let bytes = value.as_bytes();
        let len = bytes.len().min(N.saturating_sub(1));
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }

    /// Build a file event whose paths are absolute, i.e. one that needs no
    /// `/proc` lookup to resolve.
    fn file_event(kind: u32, pid: u32, path: &str, comm: &str) -> FileEvent {
        FileEvent {
            kind,
            pid,
            uid: 1000,
            flags: 0,
            dfd: AT_FDCWD,
            aux_dfd: AT_FDCWD,
            dfd_token: 0,
            aux_dfd_token: 0,
            path: fixed(path),
            aux_path: [0u8; FILE_PATH_LEN],
            comm: fixed(comm),
        }
    }

    fn dns_query_payload(name: &str, qtype: u16) -> ([u8; 256], u16) {
        let mut payload = [0u8; 256];
        payload[4] = 0;
        payload[5] = 1;

        let mut pos = crate::sensor::dns::HEADER_LEN;
        for label in name.split('.') {
            let bytes = label.as_bytes();
            payload[pos] = bytes.len() as u8;
            pos += 1;
            payload[pos..pos + bytes.len()].copy_from_slice(bytes);
            pos += bytes.len();
        }
        payload[pos] = 0;
        pos += 1;
        payload[pos..pos + 2].copy_from_slice(&qtype.to_be_bytes());
        pos += 2;
        payload[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
        pos += 2;

        (payload, pos as u16)
    }

    fn raw_dns_query(name: &str, record_type: &str) -> DnsEvent {
        let qtype = match record_type {
            "AAAA" => 28,
            "CNAME" => 5,
            "PTR" => 12,
            "TXT" => 16,
            _ => 1,
        };
        let (payload, payload_len) = dns_query_payload(name, qtype);
        DnsEvent {
            kind: 1,
            pid: 4242,
            uid: 1000,
            fd: 5,
            payload_len,
            _pad0: 0,
            query_name: [0u8; 96],
            query_results: [0u8; 96],
            record_type: fixed(record_type),
            payload,
        }
    }

    fn test_normalizer() -> Normalizer {
        Normalizer::new(
            Arc::new(ProcessCache::new()),
            Arc::new(SidCache::new()),
            Arc::new(DnsCache::new()),
            Arc::new(ConnectionAggregator::new()),
            false,
        )
    }

    fn normalized_raw_dns_query(name: &str) -> crate::models::NormalizedEvent {
        let raw = raw_dns_query(name, "A");
        let event = build_dns_event(&raw).expect("raw dns event should build");
        test_normalizer()
            .normalize(&event)
            .expect("raw dns event should normalize")
    }

    /// Never a live pid: above every possible `/proc/sys/kernel/pid_max`, so
    /// `query_process_details` is guaranteed to come back empty and the builder
    /// falls back to the raw tracepoint filename.
    const DEAD_PID: u32 = u32::MAX;

    #[test]
    fn build_process_exec_event_emits_start() {
        let raw = raw_process_event(PROCESS_EVENT_EXEC, DEAD_PID, "/usr/bin/bash");

        let event = build_process_event(&raw).expect("process exec should build");
        assert_eq!(event.action, SensorAction::Start);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_CREATE);
        assert!(event.process_start_key.is_some());

        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/bash"));
                assert_eq!(fields.image_source.as_deref(), Some("execve"));
                assert_eq!(
                    fields.process_id.as_deref(),
                    Some(DEAD_PID.to_string().as_str())
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_process_exec_event_resolves_relative_image_from_proc() {
        let expected = std::fs::read_link("/proc/self/exe")
            .expect("current process should expose /proc/self/exe");
        // `./rustinel` is what the kernel records when a binary is run
        // relatively.
        let raw = raw_process_event(PROCESS_EVENT_EXEC, std::process::id(), "./rustinel");

        let event = build_process_event(&raw).expect("process exec should build");
        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.image.as_deref(), expected.to_str());
                assert_eq!(fields.image_source.as_deref(), Some("proc"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_process_exec_event_uses_kernel_argv_for_a_dead_process() {
        // DEAD_PID has no `/proc` entry — exactly the short-lived case where
        // userspace enrichment loses the command line.
        let mut raw = raw_process_event(PROCESS_EVENT_EXEC, DEAD_PID, "/bin/true");
        let (args, args_len, args_count) = packed_argv(&["/bin/true", "--quiet"]);
        raw.args = args;
        raw.args_len = args_len;
        raw.args_count = args_count;

        let event = build_process_event(&raw).expect("process exec should build");
        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.command_line.as_deref(), Some("/bin/true --quiet"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn kernel_command_line_ignores_bytes_past_args_len() {
        let (mut args, args_len, args_count) = packed_argv(&["/bin/ls", "-la"]);
        // Stale bytes from a previous capture must never leak into the event.
        args[args_len as usize..args_len as usize + 5].copy_from_slice(b"stale");

        let event = ProcessEvent {
            args,
            args_len,
            args_count,
            ..raw_process_event(PROCESS_EVENT_EXEC, 42, "/bin/ls")
        };
        assert_eq!(event.kernel_command_line().as_deref(), Some("/bin/ls -la"));
    }

    #[test]
    fn kernel_command_line_is_none_without_a_capture() {
        let event = raw_process_event(PROCESS_EVENT_EXEC, 42, "/bin/ls");
        assert!(event.kernel_command_line().is_none());
    }

    #[test]
    fn resolve_command_line_prefers_a_complete_kernel_capture() {
        assert_eq!(
            resolve_command_line(
                Some("/bin/true --quiet".to_string()),
                false,
                Some("/bin/true".to_string()),
            )
            .as_deref(),
            Some("/bin/true --quiet")
        );
    }

    #[test]
    fn resolve_command_line_prefers_proc_when_the_kernel_capture_is_truncated() {
        assert_eq!(
            resolve_command_line(
                Some("/bin/sh -c long".to_string()),
                true,
                Some("/bin/sh -c long and complete".to_string()),
            )
            .as_deref(),
            Some("/bin/sh -c long and complete")
        );
    }

    #[test]
    fn resolve_command_line_keeps_a_truncated_capture_when_proc_is_gone() {
        assert_eq!(
            resolve_command_line(Some("/bin/sh -c long".to_string()), true, None).as_deref(),
            Some("/bin/sh -c long")
        );
        assert_eq!(
            resolve_command_line(None, false, Some("/bin/sh".to_string())).as_deref(),
            Some("/bin/sh")
        );
        assert_eq!(resolve_command_line(None, false, None), None);
    }

    #[test]
    fn resolve_exec_image_prefers_proc_exe_over_raw_filename() {
        assert_eq!(
            resolve_exec_image(Some("/tmp/malware"), "./malware"),
            Some(("/tmp/malware".to_string(), "proc"))
        );
    }

    #[test]
    fn resolve_exec_image_falls_back_to_raw_filename() {
        assert_eq!(
            resolve_exec_image(None, "./malware"),
            Some(("./malware".to_string(), "execve"))
        );
        assert_eq!(
            resolve_exec_image(Some(""), "/usr/bin/bash"),
            Some(("/usr/bin/bash".to_string(), "execve"))
        );
        assert_eq!(resolve_exec_image(None, ""), None);
    }

    #[test]
    fn build_process_exit_event_emits_stop() {
        let raw = raw_process_event(PROCESS_EVENT_EXIT, 42, "");

        let event = build_process_event(&raw).expect("process exit should build");
        assert_eq!(event.action, SensorAction::Stop);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_TERMINATE);
        assert!(event.process_start_key.is_none());

        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.process_id.as_deref(), Some("42"));
                assert!(fields.image.is_none());
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_network_event_omits_zero_source_and_protocol_guessing() {
        let mut daddr = [0u8; 16];
        daddr[..4].copy_from_slice(&[198, 51, 100, 10]);

        let raw = NetworkEvent {
            pid: 77,
            uid: 1000,
            fd: -1,
            ret: 0,
            dport: 443,
            sport: 0,
            af: 2,
            sock_type: 0,
            _pad1: 0,
            daddr,
            saddr: [0u8; 16],
        };

        let event = build_network_event(&raw).expect("network event should build");
        match event.payload {
            SensorPayload::Network(fields) => {
                assert_eq!(fields.destination_ip.as_deref(), Some("198.51.100.10"));
                assert!(fields.source_ip.is_none());
                assert!(fields.source_port.is_none());
                assert!(fields.protocol.is_none());
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_network_event_reports_the_kernel_socket_type() {
        let mut daddr = [0u8; 16];
        daddr[..4].copy_from_slice(&[198, 51, 100, 10]);

        let mut raw = NetworkEvent {
            pid: 77,
            uid: 1000,
            // A closed descriptor, so `/proc/net` cannot supply a protocol and
            // only the kernel-side socket type can answer.
            fd: -1,
            ret: 0,
            dport: 53,
            sport: 0,
            af: 2,
            sock_type: 2, // SOCK_DGRAM
            _pad1: 0,
            daddr,
            saddr: [0u8; 16],
        };

        let event = build_network_event(&raw).expect("udp connect should build");
        match event.payload {
            SensorPayload::Network(fields) => assert_eq!(fields.protocol.as_deref(), Some("udp")),
            other => panic!("unexpected payload: {:?}", other),
        }

        raw.sock_type = 1; // SOCK_STREAM
        let event = build_network_event(&raw).expect("tcp connect should build");
        match event.payload {
            SensorPayload::Network(fields) => assert_eq!(fields.protocol.as_deref(), Some("tcp")),
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_network_event_supports_ipv6() {
        let raw = NetworkEvent {
            pid: 88,
            uid: 1000,
            fd: -1,
            ret: 0,
            dport: 8443,
            sport: 5353,
            af: 10,
            sock_type: 0,
            _pad1: 0,
            daddr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10).octets(),
            saddr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x20).octets(),
        };

        let event = build_network_event(&raw).expect("ipv6 network event should build");
        match event.payload {
            SensorPayload::Network(fields) => {
                assert_eq!(fields.destination_ip.as_deref(), Some("2001:db8::10"));
                assert_eq!(fields.source_ip.as_deref(), Some("fe80::20"));
                assert_eq!(fields.destination_port.as_deref(), Some("8443"));
                assert_eq!(fields.source_port.as_deref(), Some("5353"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn socket_metadata_from_a_reused_descriptor_is_rejected() {
        // Happy-eyeballs closes the losing socket and the descriptor comes
        // back for the next attempt, so a late `/proc` read can describe a
        // connection to a different peer entirely.
        let reused = SocketMetadata {
            source_ip: Some("2001:db8::20".to_string()),
            source_port: Some(41406),
            destination_ip: Some("2606:4700:10::6814:179a".to_string()),
            destination_port: Some(443),
            protocol: Some("tcp".to_string()),
        };
        assert!(!socket_matches_connection(&reused, "198.51.100.10", 443));

        let same_peer = SocketMetadata {
            destination_ip: Some("198.51.100.10".to_string()),
            ..reused.clone()
        };
        assert!(socket_matches_connection(&same_peer, "198.51.100.10", 443));

        // The same host on another port is another connection.
        assert!(!socket_matches_connection(&same_peer, "198.51.100.10", 80));

        // A dual-stack socket lists an IPv4 peer in v4-mapped form. It is the
        // same connection, and rejecting it would throw away good data.
        let dual_stack = SocketMetadata {
            source_ip: Some("::ffff:192.168.1.27".to_string()),
            destination_ip: Some("::ffff:198.51.100.10".to_string()),
            ..reused
        };
        assert!(socket_matches_connection(&dual_stack, "198.51.100.10", 443));
    }

    #[test]
    fn build_network_event_drops_failed_connect_attempts() {
        let mut daddr = [0u8; 16];
        daddr[..4].copy_from_slice(&[198, 51, 100, 10]);

        // -ECONNREFUSED, -EHOSTUNREACH, -ETIMEDOUT: an attempt was made, no
        // connection was established.
        for result in [-111, -113, -110] {
            let raw = NetworkEvent {
                pid: 77,
                uid: 1000,
                fd: -1,
                ret: result,
                dport: 443,
                sport: 0,
                af: 2,
                sock_type: 0,
                _pad1: 0,
                daddr,
                saddr: [0u8; 16],
            };

            assert!(
                build_network_event(&raw).is_none(),
                "connect() returning {result} is not a connection"
            );
        }
    }

    #[test]
    fn build_network_event_keeps_connects_still_in_progress() {
        let mut daddr = [0u8; 16];
        daddr[..4].copy_from_slice(&[198, 51, 100, 10]);

        // -EINPROGRESS is how every non-blocking client starts a connection,
        // and -EINTR leaves the kernel completing one in the background.
        for result in [0, -115, -4] {
            let raw = NetworkEvent {
                pid: 77,
                uid: 1000,
                fd: -1,
                ret: result,
                dport: 443,
                sport: 0,
                af: 2,
                sock_type: 0,
                _pad1: 0,
                daddr,
                saddr: [0u8; 16],
            };

            let event = build_network_event(&raw)
                .unwrap_or_else(|| panic!("connect() returning {result} is a connection"));
            match event.payload {
                SensorPayload::Network(fields) => {
                    assert_eq!(fields.destination_ip.as_deref(), Some("198.51.100.10"));
                    assert_eq!(fields.initiated, Some(true));
                }
                other => panic!("unexpected payload: {:?}", other),
            }
        }
    }

    #[test]
    fn build_network_event_rejects_unspecified_destination() {
        let raw = NetworkEvent {
            pid: 77,
            uid: 1000,
            fd: -1,
            ret: 0,
            dport: 443,
            sport: 0,
            af: 2,
            sock_type: 0,
            _pad1: 0,
            daddr: [0u8; 16],
            saddr: [0u8; 16],
        };

        assert!(build_network_event(&raw).is_none());
    }

    #[test]
    fn build_file_event_preserves_fallback_comm_until_normalization() {
        let raw = file_event(1, 55, "/tmp/test.txt", "touch");

        let event =
            build_file_event(&raw, &DirFdIndex::new(), &mut 0).expect("file event should build");
        match event.payload {
            SensorPayload::File(fields) => {
                assert!(fields.source_filename.is_none());
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/test.txt"));
                assert_eq!(fields.image.as_deref(), Some("touch"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_delete_event_emits_delete_action() {
        let raw = file_event(2, 55, "/tmp/deleted.txt", "rm");

        let event = build_file_event(&raw, &DirFdIndex::new(), &mut 0)
            .expect("delete file event should build");
        assert_eq!(event.action, SensorAction::Delete);
        assert_eq!(
            event.normalization,
            SensorNormalization::for_file_action(SensorAction::Delete).unwrap()
        );

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/deleted.txt"));
                assert_eq!(fields.image.as_deref(), Some("rm"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn parse_event_struct_layout_matches_userspace_decoder() {
        let raw = file_event(2, 7, "/tmp/delete-me", "rm");

        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw as *const FileEvent).cast::<u8>(),
                std::mem::size_of::<FileEvent>(),
            )
        };
        let decoded =
            parse_event::<FileEvent>(bytes).expect("parse_event should decode file event");
        let built = build_file_event(&decoded, &DirFdIndex::new(), &mut 0)
            .expect("decoded file event should build");

        match built.payload {
            SensorPayload::File(fields) => {
                let normalized = fields.clone();
                assert_eq!(
                    normalized.target_filename.as_deref(),
                    Some("/tmp/delete-me")
                );
                let event_fields = SensorPayload::File(fields).into_event_fields();
                assert!(matches!(event_fields, EventFields::FileEvent(_)));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_rename_event_preserves_old_and_new_paths() {
        let mut raw = file_event(3, 99, "/tmp/new.txt", "mv");
        raw.aux_path = fixed("/tmp/old.txt");

        let event = build_file_event(&raw, &DirFdIndex::new(), &mut 0)
            .expect("rename file event should build");
        assert_eq!(event.action, SensorAction::Rename);
        assert_eq!(
            event.normalization,
            SensorNormalization::for_file_action(SensorAction::Rename).unwrap()
        );

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.source_filename.as_deref(), Some("/tmp/old.txt"));
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/new.txt"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_event_resolves_cwd_relative_paths() {
        let cwd = std::env::current_dir().expect("cwd should be readable");
        let mut raw = file_event(1, std::process::id(), "payload.sh", "sh");
        raw.dfd = AT_FDCWD;

        let event = build_file_event(&raw, &DirFdIndex::new(), &mut 0)
            .expect("cwd-relative event should build");
        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(
                    fields.target_filename.as_deref(),
                    Some(format!("{}/payload.sh", cwd.display()).as_str())
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_event_resolves_descriptor_relative_paths() {
        use std::os::fd::AsRawFd;

        let dir = std::fs::File::open("/etc").expect("/etc should be openable");
        let mut raw = file_event(2, std::process::id(), "passwd", "rm");
        raw.dfd = dir.as_raw_fd();

        let event = build_file_event(&raw, &DirFdIndex::new(), &mut 0)
            .expect("dirfd-relative event should build");
        match event.payload {
            SensorPayload::File(fields) => {
                // Without the descriptor this is the bare string "passwd",
                // which names a different file under every directory on the
                // disk.
                assert_eq!(fields.target_filename.as_deref(), Some("/etc/passwd"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn a_directory_open_names_the_descriptor_for_later_events() {
        // What the sensor actually receives: the open of the directory, then a
        // delete against the descriptor it produced. /proc cannot answer for
        // either here - pid 4242 does not exist - so only the index can.
        let mut dir_fds = DirFdIndex::new();

        let mut dir_open = file_event(FILE_EVENT_DIR_OPEN, 4242, "/tmp/watched", "find");
        dir_open.dfd = 9;
        dir_open.aux_dfd = AT_FDCWD;
        dir_open.dfd_token = 101;
        index_dir_open(&dir_open, &mut dir_fds);

        let mut delete = file_event(FILE_EVENT_DELETE, 4242, "victim.txt", "find");
        delete.dfd = 9;
        delete.dfd_token = 101;

        let event =
            build_file_event(&delete, &dir_fds, &mut 0).expect("indexed dfd should resolve");
        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(
                    fields.target_filename.as_deref(),
                    Some("/tmp/watched/victim.txt")
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn a_recycled_descriptor_resolves_to_the_directory_it_now_names() {
        // The bug the index exists for: fd 9 is reopened onto another directory,
        // and every later event must follow the new one, not the old.
        let mut dir_fds = DirFdIndex::new();

        let mut first = file_event(FILE_EVENT_DIR_OPEN, 4242, "/tmp/first", "rm");
        first.dfd = 9;
        first.dfd_token = 101;
        index_dir_open(&first, &mut dir_fds);

        let mut second = file_event(FILE_EVENT_DIR_OPEN, 4242, "/tmp/second", "rm");
        second.dfd = 9;
        second.dfd_token = 102;
        index_dir_open(&second, &mut dir_fds);

        let mut delete = file_event(FILE_EVENT_DELETE, 4242, "victim.txt", "rm");
        delete.dfd = 9;
        delete.dfd_token = 102;

        let event =
            build_file_event(&delete, &dir_fds, &mut 0).expect("indexed dfd should resolve");
        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(
                    fields.target_filename.as_deref(),
                    Some("/tmp/second/victim.txt")
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn an_old_index_token_is_never_used_after_untracked_fd_reuse() {
        let mut dir_fds = DirFdIndex::new();

        let mut old_dir = file_event(FILE_EVENT_DIR_OPEN, 4242, "/tmp/old", "rm");
        old_dir.dfd = 9;
        old_dir.dfd_token = 101;
        index_dir_open(&old_dir, &mut dir_fds);

        // Kernel close tracking removed token 101 before a bare O_RDONLY open
        // reused fd 9. The later event therefore carries token zero. PID 4242
        // does not exist, so `/proc` cannot hide an accidental cache hit.
        let mut delete = file_event(FILE_EVENT_DELETE, 4242, "victim.txt", "rm");
        delete.dfd = 9;
        delete.dfd_token = 0;

        let mut unresolved = 0;
        assert!(build_file_event(&delete, &dir_fds, &mut unresolved).is_none());
        assert_eq!(unresolved, 1);
    }

    #[test]
    fn a_truncated_directory_path_is_not_promoted_into_the_index() {
        let mut dir_fds = DirFdIndex::new();

        let mut dir_open = file_event(FILE_EVENT_DIR_OPEN, 4242, "/tmp/cut", "find");
        dir_open.dfd = 9;
        dir_open.dfd_token = 101;
        dir_open.flags = FILE_FLAG_PATH_TRUNCATED;
        index_dir_open(&dir_open, &mut dir_fds);

        let mut delete = file_event(FILE_EVENT_DELETE, 4242, "victim.txt", "find");
        delete.dfd = 9;
        delete.dfd_token = 101;

        assert!(build_file_event(&delete, &dir_fds, &mut 0).is_none());
    }

    #[test]
    fn a_directory_opened_under_another_descriptor_is_indexed_absolutely() {
        // `openat(dirfd, "sub", O_DIRECTORY)` is ordinary, so the directory's
        // own name is resolved before it becomes a base for anything else.
        let mut dir_fds = DirFdIndex::new();

        let mut parent = file_event(FILE_EVENT_DIR_OPEN, 4242, "/srv/data", "tar");
        parent.dfd = 4;
        parent.dfd_token = 101;
        index_dir_open(&parent, &mut dir_fds);

        let mut child = file_event(FILE_EVENT_DIR_OPEN, 4242, "nested", "tar");
        child.dfd = 5;
        child.aux_dfd = 4;
        child.dfd_token = 102;
        child.aux_dfd_token = 101;
        index_dir_open(&child, &mut dir_fds);

        let mut create = file_event(FILE_EVENT_CREATE, 4242, "payload.sh", "tar");
        create.dfd = 5;
        create.dfd_token = 102;

        let event = build_file_event(&create, &dir_fds, &mut 0).expect("nested dfd should resolve");
        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(
                    fields.target_filename.as_deref(),
                    Some("/srv/data/nested/payload.sh")
                );
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_event_drops_and_counts_unresolvable_relative_paths() {
        // PID 0 is never a real process, so /proc/0/cwd cannot be read.
        let raw = file_event(1, 0, "payload.sh", "sh");

        let mut unresolved = 0;
        assert!(build_file_event(&raw, &DirFdIndex::new(), &mut unresolved).is_none());
        assert_eq!(unresolved, 1);
    }

    #[test]
    fn build_file_event_keeps_absolute_paths_without_touching_proc() {
        // A dead PID must not matter when the name is already absolute.
        let raw = file_event(1, 0, "/tmp/absolute.txt", "sh");

        let mut unresolved = 0;
        let event = build_file_event(&raw, &DirFdIndex::new(), &mut unresolved)
            .expect("absolute event should build");
        assert_eq!(unresolved, 0);
        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/absolute.txt"));
                assert!(fields.path_truncated.is_none());
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_event_marks_truncated_paths() {
        let long_path = format!("/tmp/{}", "a".repeat(FILE_PATH_LEN));
        let mut raw = file_event(1, 55, &long_path, "dd");
        raw.flags = FILE_FLAG_PATH_TRUNCATED;

        let event = build_file_event(&raw, &DirFdIndex::new(), &mut 0)
            .expect("truncated event should build");
        match event.payload {
            SensorPayload::File(fields) => {
                let target = fields.target_filename.expect("target should be present");
                assert_eq!(target.len(), FILE_PATH_LEN - 1);
                assert_eq!(fields.path_truncated.as_deref(), Some("target"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_rename_event_resolves_each_side_against_its_own_descriptor() {
        use std::os::fd::AsRawFd;

        let etc = std::fs::File::open("/etc").expect("/etc should be openable");
        let tmp = std::fs::File::open("/tmp").expect("/tmp should be openable");

        let mut raw = file_event(3, std::process::id(), "shadow.bak", "mv");
        raw.dfd = tmp.as_raw_fd();
        raw.aux_path = fixed("shadow");
        raw.aux_dfd = etc.as_raw_fd();
        raw.flags = FILE_FLAG_AUX_PATH_TRUNCATED;

        let event =
            build_file_event(&raw, &DirFdIndex::new(), &mut 0).expect("rename event should build");
        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.source_filename.as_deref(), Some("/etc/shadow"));
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/shadow.bak"));
                assert_eq!(fields.path_truncated.as_deref(), Some("source"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_file_rename_event_keeps_the_target_when_the_source_is_unresolvable() {
        let mut raw = file_event(3, 0, "/tmp/new.txt", "mv");
        raw.aux_path = fixed("old.txt");

        let mut unresolved = 0;
        let event = build_file_event(&raw, &DirFdIndex::new(), &mut unresolved)
            .expect("rename event should build");
        assert_eq!(unresolved, 0);
        match event.payload {
            SensorPayload::File(fields) => {
                // Omitted rather than emitted as the bare name "old.txt".
                assert!(fields.source_filename.is_none());
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/new.txt"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_dns_event_maps_linux_dns_payload() {
        let (payload, payload_len) = dns_query_payload("example.test", 1);
        let raw = DnsEvent {
            kind: 1,
            pid: 4242,
            uid: 1000,
            fd: 5,
            payload_len,
            _pad0: 0,
            query_name: [0u8; 96],
            query_results: [0u8; 96],
            record_type: fixed("A"),
            payload,
        };

        let event = build_dns_event(&raw).expect("dns event should build");
        assert_eq!(event.action, SensorAction::Query);
        assert_eq!(event.normalization.event_id, EVENT_ID_DNS_QUERY);

        match event.payload {
            SensorPayload::Dns(fields) => {
                assert_eq!(fields.query_name.as_deref(), Some("example.test"));
                assert_eq!(fields.query_results, None);
                assert_eq!(fields.record_type.as_deref(), Some("A"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_dns_event_falls_back_to_query_name_field() {
        let raw = DnsEvent {
            kind: 1,
            pid: 4242,
            uid: 1000,
            fd: 5,
            payload_len: 0,
            _pad0: 0,
            query_name: fixed("fallback.test"),
            query_results: [0u8; 96],
            record_type: fixed("AAAA"),
            payload: [0u8; 256],
        };

        let event = build_dns_event(&raw).expect("dns event should build");

        match event.payload {
            SensorPayload::Dns(fields) => {
                assert_eq!(fields.query_name.as_deref(), Some("fallback.test"));
                assert_eq!(fields.record_type.as_deref(), Some("AAAA"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn parse_dns_query_name_rejects_truncated_payload() {
        let (payload, payload_len) = dns_query_payload("example.test", 1);
        let raw = DnsEvent {
            kind: 1,
            pid: 4242,
            uid: 1000,
            fd: 5,
            payload_len: payload_len.min((crate::sensor::dns::HEADER_LEN + 4) as u16),
            _pad0: 0,
            query_name: [0u8; 96],
            query_results: [0u8; 96],
            record_type: fixed("A"),
            payload,
        };

        assert_eq!(parse_dns_query_name(&raw), None);
    }

    #[test]
    fn raw_dns_payload_query_name_matches_real_sigma_dns_rule() {
        let tempdir = tempfile::tempdir().expect("create sigma tempdir");
        let rules_dir = tempdir.path().join("sigma");
        std::fs::create_dir_all(&rules_dir).expect("create sigma rules dir");
        std::fs::write(
            rules_dir.join("dns.yml"),
            r#"title: Raw Linux DNS QueryName
logsource:
  product: linux
  category: dns_query
detection:
  selection:
    QueryName|endswith: ".example.test"
    RecordType: "A"
  condition: selection
level: high
"#,
        )
        .expect("write sigma rule");

        let mut engine = Engine::new_for_platform(Platform::Linux);
        engine.load_rules(&rules_dir).expect("load sigma rule");
        assert_eq!(engine.stats().failed_rules, Vec::<(String, String)>::new());

        let event = normalized_raw_dns_query("sub.example.test");
        assert_eq!(event.get_field("QueryName"), Some("sub.example.test"));
        assert_eq!(event.get_field("query"), Some("sub.example.test"));
        assert_eq!(event.get_field("RecordType"), Some("A"));

        let alert = engine
            .check_event(&event)
            .into_iter()
            .next()
            .expect("dns Sigma rule should match raw eBPF QueryName");
        assert_eq!(alert.rule_name, "Raw Linux DNS QueryName");
    }

    #[test]
    fn descriptor_relative_file_event_matches_a_path_sigma_rule() {
        use std::os::fd::AsRawFd;

        let tempdir = tempfile::tempdir().expect("create sigma tempdir");
        let rules_dir = tempdir.path().join("sigma");
        std::fs::create_dir_all(&rules_dir).expect("create sigma rules dir");
        std::fs::write(
            rules_dir.join("file.yml"),
            r#"title: Raw Linux Sensitive File Write
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|endswith: "/etc/passwd"
  condition: selection
level: high
"#,
        )
        .expect("write sigma rule");

        let mut engine = Engine::new_for_platform(Platform::Linux);
        engine.load_rules(&rules_dir).expect("load sigma rule");
        assert_eq!(engine.stats().failed_rules, Vec::<(String, String)>::new());

        // The kernel hands the sensor the bare name "passwd" plus a descriptor.
        // Before resolution that string matched no path rule at all.
        let dir = std::fs::File::open("/etc").expect("/etc should be openable");
        let mut raw = file_event(FILE_EVENT_CREATE, std::process::id(), "passwd", "sh");
        raw.dfd = dir.as_raw_fd();

        let sensor_event =
            build_file_event(&raw, &DirFdIndex::new(), &mut 0).expect("file event should build");
        let event = test_normalizer()
            .normalize(&sensor_event)
            .expect("file event should normalize");
        assert_eq!(event.get_field("TargetFilename"), Some("/etc/passwd"));

        let alert = engine
            .check_event(&event)
            .into_iter()
            .next()
            .expect("file Sigma rule should match the resolved path");
        assert_eq!(alert.rule_name, "Raw Linux Sensitive File Write");
    }

    #[test]
    fn descriptor_relative_file_event_matches_a_path_regex_ioc() {
        use std::os::fd::AsRawFd;

        let tempdir = tempfile::tempdir().expect("create ioc tempdir");
        let root = tempdir.path().join("ioc");
        std::fs::create_dir_all(&root).expect("create ioc dir");
        let hashes_path = root.join("hashes.txt");
        let ips_path = root.join("ips.txt");
        let domains_path = root.join("domains.txt");
        let paths_regex_path = root.join("paths_regex.txt");
        std::fs::write(&hashes_path, "").expect("write hashes");
        std::fs::write(&ips_path, "").expect("write ips");
        std::fs::write(&domains_path, "").expect("write domains");
        std::fs::write(&paths_regex_path, "^/etc/passwd$; sensitive file")
            .expect("write path regexes");

        let engine = IocEngine::load(&IocConfig {
            enabled: true,
            hashes_path,
            ips_path,
            domains_path,
            paths_regex_path,
            default_severity: "high".to_string(),
            max_file_size_mb: 16,
            hash_allowlist_paths: Vec::new(),
        });

        let dir = std::fs::File::open("/etc").expect("/etc should be openable");
        let mut raw = file_event(FILE_EVENT_CREATE, std::process::id(), "passwd", "sh");
        raw.dfd = dir.as_raw_fd();

        let sensor_event =
            build_file_event(&raw, &DirFdIndex::new(), &mut 0).expect("file event should build");
        let event = test_normalizer()
            .normalize(&sensor_event)
            .expect("file event should normalize");

        let matches = engine.check_event(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].observed, "/etc/passwd");
    }

    #[test]
    fn raw_dns_payload_query_name_matches_domain_ioc() {
        let tempdir = tempfile::tempdir().expect("create ioc tempdir");
        let root = tempdir.path().join("ioc");
        std::fs::create_dir_all(&root).expect("create ioc dir");
        let hashes_path = root.join("hashes.txt");
        let ips_path = root.join("ips.txt");
        let domains_path = root.join("domains.txt");
        let paths_regex_path = root.join("paths_regex.txt");
        std::fs::write(&hashes_path, "").expect("write hashes");
        std::fs::write(&ips_path, "").expect("write ips");
        std::fs::write(&domains_path, ".example.test; raw dns suffix").expect("write domains");
        std::fs::write(&paths_regex_path, "").expect("write path regexes");

        let engine = IocEngine::load(&IocConfig {
            enabled: true,
            hashes_path,
            ips_path,
            domains_path,
            paths_regex_path,
            default_severity: "high".to_string(),
            max_file_size_mb: 16,
            hash_allowlist_paths: Vec::new(),
        });
        let event = normalized_raw_dns_query("sub.example.test");

        let matches = engine.check_event(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, IocKind::Domain);
        assert_eq!(matches[0].observed, "sub.example.test");

        let alert = engine.build_alert_for_match(&matches[0], &event);
        assert_eq!(alert.rule_name, "ioc:domain:.example.test");
    }

    #[test]
    fn build_dns_event_drops_empty_record_type() {
        let raw = DnsEvent {
            kind: 1,
            pid: 1,
            uid: 0,
            fd: 3,
            payload_len: 0,
            _pad0: 0,
            query_name: [0u8; 96],
            query_results: [0u8; 96],
            record_type: [0u8; 16],
            payload: [0u8; 256],
        };
        assert!(build_dns_event(&raw).is_none());
    }
}
