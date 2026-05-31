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

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use crate::models::{
    DnsQueryFields, FileEventFields, NetworkConnectionFields, ProcessCreationFields,
};
use crate::sensor::{
    Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorNormalization,
    SensorPayload,
};
use crate::utils::{lookup_username_by_uid, query_process_details, query_socket_metadata};

use super::events::{
    bytes_to_string, parse_event, DnsEvent, FileEvent, NetworkEvent, ProcessEvent,
};

/// Sysmon-compatible event IDs emitted for Linux events.
const EVENT_ID_PROCESS_CREATE: u16 = 1;
const EVENT_ID_PROCESS_TERMINATE: u16 = 5;
const EVENT_ID_NETWORK_CONNECT: u16 = 3;
const EVENT_ID_FILE_CREATE: u16 = 11;
const EVENT_ID_FILE_DELETE: u16 = 23;
const EVENT_ID_FILE_CHANGE: u16 = 65;
const EVENT_ID_FILE_RENAME: u16 = 71;
const EVENT_ID_DNS_QUERY: u16 = 22;

const PROCESS_EVENT_EXEC: u32 = 1;
const PROCESS_EVENT_EXIT: u32 = 2;
const DNS_HEADER_LEN: usize = 12;
const DNS_LABEL_POINTER_MASK: u8 = 0xc0;
const DNS_LABEL_MAX_LEN: usize = 63;

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
        attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect")?;
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
        attach_tracepoint(&mut bpf, "handle_sendto", "syscalls", "sys_enter_sendto")?;

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
                drain_file_ring(rb, &tx);
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

fn drain_file_ring(rb: &mut RingBuf<MapData>, tx: &Sender<SensorEvent>) {
    while let Some(item) = rb.next() {
        let bytes: &[u8] = &item;
        let Some(ev) = parse_event::<FileEvent>(bytes) else {
            warn!("file ring: short read ({} bytes)", bytes.len());
            continue;
        };
        if let Some(sensor_event) = build_file_event(&ev) {
            try_send(tx, sensor_event);
        }
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

fn build_process_event(ev: &ProcessEvent) -> Option<SensorEvent> {
    let user = resolved_linux_user(ev.uid);
    match ev.kind {
        PROCESS_EVENT_EXEC => {
            let details = query_process_details(ev.pid);
            let image = match bytes_to_string(&ev.image) {
                value if !value.is_empty() => Some(value),
                _ => details.as_ref().and_then(|value| value.image.clone()),
            };
            let image = image?;

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
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
                    command_line: details
                        .as_ref()
                        .and_then(|value| value.command_line.clone()),
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
                    logon_id: None,
                    logon_guid: None,
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
                original_file_name: None,
                product: None,
                description: None,
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
                logon_id: None,
                logon_guid: None,
            }),
        }),
        _ => None,
    }
}

fn build_network_event(ev: &NetworkEvent) -> Option<SensorEvent> {
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

    let socket_metadata = query_socket_metadata(ev.pid, ev.fd);
    let user = resolved_linux_user(ev.uid);
    let source_ip = source_ip.or_else(|| {
        socket_metadata
            .as_ref()
            .and_then(|value| filter_unspecified_ip(value.source_ip.clone()))
    });
    let source_port = if ev.sport > 0 {
        Some(ev.sport.to_string())
    } else {
        socket_metadata
            .as_ref()
            .and_then(|value| value.source_port.map(|port| port.to_string()))
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
            protocol: socket_metadata.and_then(|value| value.protocol),
        }),
    })
}

fn build_file_event(ev: &FileEvent) -> Option<SensorEvent> {
    let path = bytes_to_string(&ev.path);
    if path.is_empty() {
        return None;
    }

    let (action, event_id, action_code) = match ev.kind {
        1 => (SensorAction::Create, EVENT_ID_FILE_CREATE, 64u8),
        2 => (SensorAction::Delete, EVENT_ID_FILE_DELETE, 70u8),
        3 => (SensorAction::Rename, EVENT_ID_FILE_RENAME, 71u8),
        4 => (SensorAction::Modify, EVENT_ID_FILE_CHANGE, 65u8),
        _ => return None,
    };

    let user = resolved_linux_user(ev.uid);
    let comm = bytes_to_string(&ev.comm);
    let source_filename = if ev.kind == 3 {
        let value = bytes_to_string(&ev.aux_path);
        (!value.is_empty()).then_some(value)
    } else {
        None
    };

    Some(SensorEvent {
        platform: Platform::Linux,
        provider: "ebpf",
        action,
        normalization: SensorNormalization {
            event_id,
            action_code,
        },
        pid: Some(ev.pid),
        timestamp: SystemTime::now(),
        process_start_key: None,
        payload: SensorPayload::File(FileEventFields {
            source_filename,
            target_filename: Some(path),
            process_id: Some(ev.pid.to_string()),
            image: if comm.is_empty() { None } else { Some(comm) },
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: Some(user),
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
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if flags & 0x8000 != 0 || qdcount == 0 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let mut labels: Vec<String> = Vec::new();
    while pos < payload.len() {
        let label_len = payload[pos];
        pos += 1;

        if label_len == 0 {
            return if labels.is_empty() {
                Some(".".to_string())
            } else {
                Some(labels.join("."))
            };
        }

        if label_len & DNS_LABEL_POINTER_MASK != 0 {
            return None;
        }

        let label_len = usize::from(label_len);
        if label_len > DNS_LABEL_MAX_LEN || pos + label_len > payload.len() {
            return None;
        }

        labels.push(String::from_utf8_lossy(&payload[pos..pos + label_len]).into_owned());
        pos += label_len;
    }

    None
}

// ── Utilities ────────────────────────────────────────────────────────────────

fn try_send(tx: &Sender<SensorEvent>, event: SensorEvent) {
    match tx.try_send(event) {
        Ok(_) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            warn!("eBPF sensor: event channel full, dropping event");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            // Pipeline has shut down; stop logging.
        }
    }
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

fn filter_unspecified_ip(value: Option<String>) -> Option<String> {
    let ip = value?;
    let is_unspecified = ip
        .parse::<std::net::IpAddr>()
        .map(|value| value.is_unspecified())
        .unwrap_or(false);
    (!is_unspecified).then_some(ip)
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
    use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
    use std::sync::Arc;

    fn fixed<const N: usize>(value: &str) -> [u8; N] {
        let mut buf = [0u8; N];
        let bytes = value.as_bytes();
        let len = bytes.len().min(N.saturating_sub(1));
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }

    fn dns_query_payload(name: &str, qtype: u16) -> ([u8; 256], u16) {
        let mut payload = [0u8; 256];
        payload[4] = 0;
        payload[5] = 1;

        let mut pos = DNS_HEADER_LEN;
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

    #[test]
    fn build_process_exec_event_emits_start() {
        let raw = ProcessEvent {
            kind: PROCESS_EVENT_EXEC,
            pid: 42,
            uid: 1000,
            _pad: 0,
            comm: fixed("bash"),
            image: fixed("/usr/bin/bash"),
        };

        let event = build_process_event(&raw).expect("process exec should build");
        assert_eq!(event.action, SensorAction::Start);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_CREATE);
        assert!(event.process_start_key.is_some());

        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/bash"));
                assert_eq!(fields.process_id.as_deref(), Some("42"));
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_process_exit_event_emits_stop() {
        let raw = ProcessEvent {
            kind: PROCESS_EVENT_EXIT,
            pid: 42,
            uid: 1000,
            _pad: 0,
            comm: fixed("bash"),
            image: [0u8; 128],
        };

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
            _pad0: 0,
            dport: 443,
            sport: 0,
            af: 2,
            _pad1: 0,
            daddr,
            saddr: [0u8; 16],
        };

        let event = build_network_event(&raw).expect("network event should build");
        match event.payload {
            SensorPayload::Network(fields) => {
                assert_eq!(fields.destination_ip.as_deref(), Some("198.51.100.10"));
                assert!(fields.source_ip.is_none());
                assert!(fields.protocol.is_none());
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[test]
    fn build_network_event_supports_ipv6() {
        let raw = NetworkEvent {
            pid: 88,
            uid: 1000,
            fd: -1,
            _pad0: 0,
            dport: 8443,
            sport: 5353,
            af: 10,
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
    fn build_network_event_rejects_unspecified_destination() {
        let raw = NetworkEvent {
            pid: 77,
            uid: 1000,
            fd: -1,
            _pad0: 0,
            dport: 443,
            sport: 0,
            af: 2,
            _pad1: 0,
            daddr: [0u8; 16],
            saddr: [0u8; 16],
        };

        assert!(build_network_event(&raw).is_none());
    }

    #[test]
    fn build_file_event_preserves_fallback_comm_until_normalization() {
        let raw = FileEvent {
            kind: 1,
            pid: 55,
            uid: 1000,
            _pad0: 0,
            path: fixed("/tmp/test.txt"),
            aux_path: [0u8; 96],
            comm: fixed("touch"),
        };

        let event = build_file_event(&raw).expect("file event should build");
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
        let raw = FileEvent {
            kind: 2,
            pid: 55,
            uid: 1000,
            _pad0: 0,
            path: fixed("/tmp/deleted.txt"),
            aux_path: [0u8; 96],
            comm: fixed("rm"),
        };

        let event = build_file_event(&raw).expect("delete file event should build");
        assert_eq!(event.action, SensorAction::Delete);
        assert_eq!(event.normalization.event_id, EVENT_ID_FILE_DELETE);

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
        let raw = FileEvent {
            kind: 2,
            pid: 7,
            uid: 1000,
            _pad0: 0,
            path: fixed("/tmp/delete-me"),
            aux_path: [0u8; 96],
            comm: fixed("rm"),
        };

        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw as *const FileEvent).cast::<u8>(),
                std::mem::size_of::<FileEvent>(),
            )
        };
        let decoded =
            parse_event::<FileEvent>(bytes).expect("parse_event should decode file event");
        let built = build_file_event(&decoded).expect("decoded file event should build");

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
        let raw = FileEvent {
            kind: 3,
            pid: 99,
            uid: 1000,
            _pad0: 0,
            path: fixed("/tmp/new.txt"),
            aux_path: fixed("/tmp/old.txt"),
            comm: fixed("mv"),
        };

        let event = build_file_event(&raw).expect("rename file event should build");
        assert_eq!(event.action, SensorAction::Rename);
        assert_eq!(event.normalization.event_id, EVENT_ID_FILE_RENAME);

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.source_filename.as_deref(), Some("/tmp/old.txt"));
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
            payload_len: payload_len.min((DNS_HEADER_LEN + 4) as u16),
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
            .expect("dns Sigma rule should match raw eBPF QueryName");
        assert_eq!(alert.rule_name, "Raw Linux DNS QueryName");
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
