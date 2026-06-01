//! macOS network and DNS sensor backed by `/dev/bpf` packet capture.
//!
//! Endpoint Security does not surface network connections or DNS, so the macOS
//! sensor pairs ESF with a BPF capture device. [`BpfSensor`] opens a `/dev/bpf`
//! device, binds it to an interface, and reads link-layer frames on a
//! dedicated thread. Captured frames are parsed into [`SensorEvent`] values
//! (network connections and DNS queries) for the shared pipeline.
//!
//! Requirements: root (or access to the bpf device nodes). PID attribution for
//! captured flows is best-effort via libproc; see the socket helper.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use super::packet::{self, ParsedPacket, Transport, DLT_EN10MB, TCP_FLAG_ACK, TCP_FLAG_SYN};
use super::socket;
use crate::models::{DnsQueryFields, NetworkConnectionFields};
use crate::sensor::{
    Platform, Sensor, SensorAction, SensorEvent, SensorNormalization, SensorPayload,
};

/// Sysmon-compatible event ID emitted for network-connect events.
const EVENT_ID_NETWORK_CONNECT: u16 = 3;
/// Sysmon-compatible event ID emitted for DNS-query events.
const EVENT_ID_DNS_QUERY: u16 = 22;
/// Destination port that identifies DNS query traffic.
const DNS_PORT: u16 = 53;

/// Environment variable overriding the capture interface (default `en0`).
const INTERFACE_ENV: &str = "RUSTINEL_BPF_INTERFACE";
const DEFAULT_INTERFACE: &str = "en0";

/// Requested BPF read-buffer size, set via `BIOCSBLEN` before binding. The
/// kernel may cap this; the effective size is read back and used for reads.
const BPF_BUFFER_LEN: u32 = 1 << 18; // 256 KiB

/// Read timeout so the capture loop wakes periodically to observe shutdown.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// Bound on connection-attribution jobs queued for the worker thread. When the
/// worker falls behind (a burst of new connections), the capture thread emits
/// the event unattributed rather than blocking the read loop.
const ATTRIBUTION_QUEUE_CAP: usize = 1024;

// BPF ioctl request codes for 64-bit macOS, from <net/bpf.h>. Encoded with the
// _IOW/_IOR/_IOWR macros; verified against the SDK headers.
const BIOCSBLEN: libc::c_ulong = 0xc004_4266; // _IOWR('B', 102, u_int)
const BIOCSETF: libc::c_ulong = 0x8010_4267; // _IOW('B', 103, struct bpf_program)
const BIOCGDLT: libc::c_ulong = 0x4004_426a; // _IOR('B', 106, u_int)
const BIOCSETIF: libc::c_ulong = 0x8020_426c; // _IOW('B', 108, struct ifreq)
const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d; // _IOW('B', 109, struct timeval)
const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270; // _IOW('B', 112, u_int)

// struct bpf_hdr field offsets on 64-bit macOS (sizeof == 20; bh_tstamp is a
// 32-bit timeval, so caplen/hdrlen sit earlier than a 64-bit timeval suggests).
// The packet payload starts bh_hdrlen bytes into each record.
const BH_CAPLEN_OFFSET: usize = 8;
const BH_HDRLEN_OFFSET: usize = 16;
/// Smallest prefix needed to read bh_caplen and bh_hdrlen from a record.
const BPF_HDR_FIELDS_LEN: usize = 18;

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; 16],
    ifr_ifru: [u8; 16],
}

/// A classic-BPF instruction (`struct bpf_insn`): opcode, two jump offsets, and
/// a generic operand. Eight bytes, matching the kernel layout.
#[repr(C)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// A classic-BPF filter program (`struct bpf_program`) passed to `BIOCSETF`.
#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *const BpfInsn,
}

/// Coarse in-kernel pre-filter for Ethernet links: accept TCP connection
/// initiations (SYN set, ACK clear) over IPv4 and IPv6, plus any port-53
/// traffic, and drop the rest so the kernel never copies the ~99% of frames
/// userspace would discard. This is the macOS analogue of attaching the Linux
/// probe to `sys_enter_connect` rather than tapping every packet; [`packet`]
/// stays the precise tier, so over-matching here is harmless. It must not
/// *under*-match relative to the parser, which is why the IPv6 SYN term is
/// spelled out explicitly rather than relying on `tcp[tcpflags]`.
///
/// Generated with libpcap against a dead `DLT_EN10MB` handle, equivalent to:
///   `(tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn)`
///   `  or (ip6 and ip6[6] = 6 and (ip6[53] & 0x12) = 2)`
///   `  or port 53`
/// The `tcp[tcpflags]` primitive only compiles to IPv4 code, so the IPv6 SYN
/// term is written by hand: `ip6[6]` is the next header and `ip6[53]` the TCP
/// flags byte (the IPv6 header is a fixed 40 bytes plus the TCP flags at offset
/// 13). It assumes no IPv6 extension headers, matching `parse_ipv6`'s own
/// first-next-header-only behavior, so the two tiers stay consistent.
/// Regenerate if the expression changes; the offsets are Ethernet-specific, so
/// it is only installed when `BIOCGDLT` reports `DLT_EN10MB`.
#[rustfmt::skip]
const BPF_FILTER_EN10MB: [BpfInsn; 37] = [
    BpfInsn { code: 0x0028, jt: 0,  jf: 0,  k: 0x0000000c },
    BpfInsn { code: 0x0015, jt: 0,  jf: 19, k: 0x00000800 },
    BpfInsn { code: 0x0030, jt: 0,  jf: 0,  k: 0x00000017 },
    BpfInsn { code: 0x0015, jt: 0,  jf: 8,  k: 0x00000006 },
    BpfInsn { code: 0x0028, jt: 0,  jf: 0,  k: 0x00000014 },
    BpfInsn { code: 0x0045, jt: 30, jf: 0,  k: 0x00001fff },
    BpfInsn { code: 0x00b1, jt: 0,  jf: 0,  k: 0x0000000e },
    BpfInsn { code: 0x0050, jt: 0,  jf: 0,  k: 0x0000001b },
    BpfInsn { code: 0x0054, jt: 0,  jf: 0,  k: 0x00000012 },
    BpfInsn { code: 0x0015, jt: 25, jf: 0,  k: 0x00000002 },
    BpfInsn { code: 0x0048, jt: 0,  jf: 0,  k: 0x0000000e },
    BpfInsn { code: 0x0015, jt: 23, jf: 7,  k: 0x00000035 },
    BpfInsn { code: 0x0015, jt: 1,  jf: 0,  k: 0x00000084 },
    BpfInsn { code: 0x0015, jt: 0,  jf: 22, k: 0x00000011 },
    BpfInsn { code: 0x0028, jt: 0,  jf: 0,  k: 0x00000014 },
    BpfInsn { code: 0x0045, jt: 20, jf: 0,  k: 0x00001fff },
    BpfInsn { code: 0x00b1, jt: 0,  jf: 0,  k: 0x0000000e },
    BpfInsn { code: 0x0048, jt: 0,  jf: 0,  k: 0x0000000e },
    BpfInsn { code: 0x0015, jt: 16, jf: 0,  k: 0x00000035 },
    BpfInsn { code: 0x0048, jt: 0,  jf: 0,  k: 0x00000010 },
    BpfInsn { code: 0x0015, jt: 14, jf: 15, k: 0x00000035 },
    BpfInsn { code: 0x0015, jt: 0,  jf: 14, k: 0x000086dd },
    BpfInsn { code: 0x0030, jt: 0,  jf: 0,  k: 0x00000014 },
    BpfInsn { code: 0x0015, jt: 0,  jf: 3,  k: 0x00000006 },
    BpfInsn { code: 0x0030, jt: 0,  jf: 0,  k: 0x00000043 },
    BpfInsn { code: 0x0054, jt: 0,  jf: 0,  k: 0x00000012 },
    BpfInsn { code: 0x0015, jt: 8,  jf: 0,  k: 0x00000002 },
    BpfInsn { code: 0x0030, jt: 0,  jf: 0,  k: 0x00000014 },
    BpfInsn { code: 0x0015, jt: 2,  jf: 0,  k: 0x00000084 },
    BpfInsn { code: 0x0015, jt: 1,  jf: 0,  k: 0x00000006 },
    BpfInsn { code: 0x0015, jt: 0,  jf: 5,  k: 0x00000011 },
    BpfInsn { code: 0x0028, jt: 0,  jf: 0,  k: 0x00000036 },
    BpfInsn { code: 0x0015, jt: 2,  jf: 0,  k: 0x00000035 },
    BpfInsn { code: 0x0028, jt: 0,  jf: 0,  k: 0x00000038 },
    BpfInsn { code: 0x0015, jt: 0,  jf: 1,  k: 0x00000035 },
    BpfInsn { code: 0x0006, jt: 0,  jf: 0,  k: 0x00040000 },
    BpfInsn { code: 0x0006, jt: 0,  jf: 0,  k: 0x00000000 },
];

/// macOS `/dev/bpf` network/DNS sensor. Implements [`Sensor`].
pub struct BpfSensor {
    shutdown: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl BpfSensor {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        }
    }
}

impl Default for BpfSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for BpfSensor {
    /// Open and configure the bpf device synchronously so failures (no device
    /// nodes, no privileges, unknown interface) surface to the caller, then
    /// spawn the capture loop on a dedicated thread.
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        let interface =
            std::env::var(INTERFACE_ENV).unwrap_or_else(|_| DEFAULT_INTERFACE.to_string());
        let device = BpfDevice::open(&interface)?;
        let link_type = device.link_type;
        info!(
            interface = %interface,
            link_type,
            buffer_len = device.buffer_len,
            "bpf capture device ready"
        );

        let shutdown = Arc::clone(&self.shutdown);
        let handle = std::thread::Builder::new()
            .name("rustinel-bpf".to_string())
            .spawn(move || run_capture(device, tx, shutdown))
            .map_err(|e| anyhow!("failed to spawn bpf capture thread: {e}"))?;
        *self.thread.lock().expect("bpf thread mutex poisoned") = Some(handle);

        Ok(())
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self
            .thread
            .lock()
            .expect("bpf thread mutex poisoned")
            .take()
        {
            let _ = handle.join();
        }
    }
}

/// An open, configured bpf capture device. Closes its fd on drop.
struct BpfDevice {
    fd: RawFd,
    link_type: u32,
    buffer_len: u32,
}

impl BpfDevice {
    fn open(interface: &str) -> Result<Self> {
        let fd = open_bpf_device()?;
        // BIOCSBLEN must be set before binding the interface; the kernel may
        // adjust the requested size, so use the value it reports back.
        let buffer_len = match set_buffer_len(fd, BPF_BUFFER_LEN) {
            Ok(len) => len,
            Err(e) => {
                close_fd(fd);
                return Err(anyhow!("BIOCSBLEN failed: {e}"));
            }
        };
        let configure = || -> io::Result<u32> {
            bind_interface(fd, interface)?;
            let link_type = get_u32(fd, BIOCGDLT)?;
            // Install a coarse kernel filter right after binding so the kernel
            // drops everything but SYNs and port-53 traffic before it reaches
            // userspace. The program uses Ethernet offsets, so it is only
            // applied when the link type matches; other link types fall back to
            // capturing everything and filtering in userspace.
            if link_type == DLT_EN10MB {
                set_filter(fd, &BPF_FILTER_EN10MB)?;
            }
            set_u32(fd, BIOCIMMEDIATE, 1)?;
            set_read_timeout(fd, READ_TIMEOUT)?;
            Ok(link_type)
        };
        match configure() {
            Ok(link_type) => Ok(Self {
                fd,
                link_type,
                buffer_len,
            }),
            Err(e) => {
                close_fd(fd);
                Err(anyhow!(
                    "failed to configure bpf device for {interface}: {e}"
                ))
            }
        }
    }
}

impl Drop for BpfDevice {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

/// Open the first available `/dev/bpfN` cloning device.
fn open_bpf_device() -> Result<RawFd> {
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no /dev/bpf device available");
    for n in 0..256 {
        let path = CString::new(format!("/dev/bpf{n}")).expect("device path has no NUL");
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            return Ok(fd);
        }
        let err = io::Error::last_os_error();
        // EBUSY means the device is taken by another client; try the next one.
        // Anything else (e.g. EACCES, ENOENT) is recorded and we keep trying a
        // few more in case only some nodes are restricted.
        last_err = err;
    }
    Err(anyhow!("could not open any /dev/bpf device: {last_err}"))
}

fn bind_interface(fd: RawFd, interface: &str) -> io::Result<()> {
    let mut req: IfReq = unsafe { std::mem::zeroed() };
    let bytes = interface.as_bytes();
    if bytes.len() >= req.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    for (slot, byte) in req.ifr_name.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, BIOCSETIF, &req as *const IfReq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Install a classic-BPF filter program on the device via `BIOCSETF`.
fn set_filter(fd: RawFd, program: &[BpfInsn]) -> io::Result<()> {
    let prog = BpfProgram {
        bf_len: program.len() as u32,
        bf_insns: program.as_ptr(),
    };
    let rc = unsafe { libc::ioctl(fd, BIOCSETF, &prog as *const BpfProgram) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_buffer_len(fd: RawFd, len: u32) -> io::Result<u32> {
    let mut value: libc::c_uint = len;
    let rc = unsafe { libc::ioctl(fd, BIOCSBLEN, &mut value as *mut libc::c_uint) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value as u32)
}

fn set_u32(fd: RawFd, request: libc::c_ulong, value: u32) -> io::Result<()> {
    let value: libc::c_uint = value;
    let rc = unsafe { libc::ioctl(fd, request, &value as *const libc::c_uint) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_u32(fd: RawFd, request: libc::c_ulong) -> io::Result<u32> {
    let mut value: libc::c_uint = 0;
    let rc = unsafe { libc::ioctl(fd, request, &mut value as *mut libc::c_uint) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value as u32)
}

fn set_read_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let rc = unsafe { libc::ioctl(fd, BIOCSRTIMEOUT, &tv as *const libc::timeval) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

/// A network-connection event awaiting best-effort process attribution.
struct AttributionJob {
    event: SensorEvent,
    local_port: u16,
    remote_port: u16,
}

/// Capture loop: read batches of bpf records and dispatch each packet.
///
/// Socket-to-process attribution is offloaded to a dedicated worker so the
/// `O(processes x descriptors)` scan never blocks draining the bpf device,
/// which is exactly when the kernel would otherwise drop packets.
fn run_capture(device: BpfDevice, tx: Sender<SensorEvent>, shutdown: Arc<AtomicBool>) {
    let (attribution_tx, attribution_rx) = std::sync::mpsc::sync_channel(ATTRIBUTION_QUEUE_CAP);
    let worker_tx = tx.clone();
    let attribution_worker = std::thread::Builder::new()
        .name("rustinel-bpf-attr".to_string())
        .spawn(move || run_attribution_worker(attribution_rx, worker_tx))
        .map_err(|e| warn!("failed to spawn bpf attribution worker: {e}"))
        .ok();

    let mut buf = vec![0u8; device.buffer_len as usize];
    while !shutdown.load(Ordering::Relaxed) {
        let n = unsafe { libc::read(device.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // EINTR/EAGAIN: interrupted or read timeout elapsed with no
                // data. Loop back and re-check the shutdown flag.
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => {
                    if !shutdown.load(Ordering::Relaxed) {
                        warn!("bpf read error: {err}");
                        std::thread::sleep(READ_TIMEOUT);
                    }
                    continue;
                }
            }
        }
        if n == 0 {
            continue;
        }
        let data = &buf[..n as usize];
        for_each_packet(data, |packet| {
            handle_packet(device.link_type, packet, &tx, &attribution_tx)
        });
    }

    // Drop our sender so the worker observes the channel closing and exits,
    // then wait for it to finish any in-flight lookup.
    drop(attribution_tx);
    if let Some(handle) = attribution_worker {
        let _ = handle.join();
    }
    info!("bpf sensor shutting down");
}

/// Attribution worker: receive connection events that still need an owning
/// process, perform the libproc socket lookup off the capture thread, and
/// forward the (now best-effort attributed) event to the pipeline. Exits when
/// the capture thread drops its sender.
fn run_attribution_worker(rx: Receiver<AttributionJob>, tx: Sender<SensorEvent>) {
    while let Ok(mut job) = rx.recv() {
        apply_socket_owner(&mut job.event, job.local_port, job.remote_port);
        try_send(&tx, job.event);
    }
}

/// Iterate the packets in a bpf read buffer, calling `handle` with each
/// captured frame. Records are prefixed with a `struct bpf_hdr` and aligned to
/// `BPF_ALIGNMENT` (4 bytes) boundaries.
fn for_each_packet(buf: &[u8], mut handle: impl FnMut(&[u8])) {
    let mut offset = 0usize;
    while offset + BPF_HDR_FIELDS_LEN <= buf.len() {
        let caplen = read_u32(buf, offset + BH_CAPLEN_OFFSET) as usize;
        let hdrlen = read_u16(buf, offset + BH_HDRLEN_OFFSET) as usize;

        let start = offset + hdrlen;
        let end = match start.checked_add(caplen) {
            Some(end) if end <= buf.len() && start <= buf.len() => end,
            _ => break,
        };
        handle(&buf[start..end]);

        let advance = bpf_word_align(hdrlen + caplen);
        if advance == 0 {
            break;
        }
        offset += advance;
    }
}

/// Parse a captured frame and emit any resulting [`SensorEvent`].
///
/// Network-connection events are queued for off-thread attribution; DNS events
/// need no PID lookup and go straight to the pipeline.
fn handle_packet(
    link_type: u32,
    frame: &[u8],
    tx: &Sender<SensorEvent>,
    attribution_tx: &SyncSender<AttributionJob>,
) {
    let Some(parsed) = packet::parse(link_type, frame) else {
        return;
    };
    if let Some(event) = build_network_event(&parsed) {
        match connection_ports(&parsed) {
            Some((local_port, remote_port)) => {
                enqueue_attribution(attribution_tx, tx, event, local_port, remote_port)
            }
            None => try_send(tx, event),
        }
    }
    if let Some(event) = build_dns_event(&parsed) {
        try_send(tx, event);
    }
}

/// Hand a connection event to the attribution worker, falling back to emitting
/// it unattributed if the worker is saturated or gone. The capture thread never
/// blocks and the event is never lost; only its attribution is best-effort.
fn enqueue_attribution(
    attribution_tx: &SyncSender<AttributionJob>,
    tx: &Sender<SensorEvent>,
    event: SensorEvent,
    local_port: u16,
    remote_port: u16,
) {
    let job = AttributionJob {
        event,
        local_port,
        remote_port,
    };
    match attribution_tx.try_send(job) {
        Ok(()) => {}
        Err(TrySendError::Full(job)) | Err(TrySendError::Disconnected(job)) => {
            try_send(tx, job.event)
        }
    }
}

/// Best-effort: attribute a connection event to its owning process by matching
/// the connection's ports against open sockets. Failures leave the event
/// unattributed (the normalizer still enriches by destination). Runs on the
/// attribution worker, never on the capture thread.
fn apply_socket_owner(event: &mut SensorEvent, local_port: u16, remote_port: u16) {
    let Some(owner) = socket::find_tcp_socket_owner(local_port, remote_port) else {
        return;
    };
    event.pid = Some(owner.pid);
    if let SensorPayload::Network(fields) = &mut event.payload {
        fields.process_id = Some(owner.pid.to_string());
        fields.image = owner.image;
    }
}

/// The local and remote ports of a TCP packet, used to key socket attribution.
fn connection_ports(packet: &ParsedPacket) -> Option<(u16, u16)> {
    match &packet.transport {
        Transport::Tcp {
            src_port, dst_port, ..
        } => Some((*src_port, *dst_port)),
        Transport::Udp { .. } => None,
    }
}

/// Build a network-connection event from a TCP connection initiation.
///
/// Only SYN segments with ACK clear are treated as new connections. PID and
/// image attribution are filled in best-effort by the attribution worker; the
/// normalizer enriches the rest.
fn build_network_event(packet: &ParsedPacket) -> Option<SensorEvent> {
    let Transport::Tcp {
        src_port,
        dst_port,
        flags,
        ..
    } = &packet.transport
    else {
        return None;
    };
    if flags & TCP_FLAG_SYN == 0 || flags & TCP_FLAG_ACK != 0 {
        return None;
    }

    Some(SensorEvent {
        platform: Platform::MacOS,
        provider: "bpf",
        action: SensorAction::Connect,
        normalization: SensorNormalization {
            event_id: EVENT_ID_NETWORK_CONNECT,
            action_code: 0,
        },
        pid: None,
        timestamp: SystemTime::now(),
        process_start_key: None,
        payload: SensorPayload::Network(NetworkConnectionFields {
            destination_ip: Some(packet.dst_ip.to_string()),
            source_ip: Some(packet.src_ip.to_string()),
            destination_port: Some(dst_port.to_string()),
            source_port: Some(src_port.to_string()),
            process_id: None,
            image: None,
            user: None,
            destination_hostname: None,
            protocol: Some("tcp".to_string()),
        }),
    })
}

/// Build a DNS-query event from a packet destined to port 53.
///
/// Handles UDP queries directly and DNS-over-TCP by skipping the 2-byte length
/// prefix. Responses are rejected by the shared parser (QR bit).
fn build_dns_event(packet: &ParsedPacket) -> Option<SensorEvent> {
    let (dst_port, dns_payload) = match &packet.transport {
        Transport::Udp { dst_port, payload } => (*dst_port, *payload),
        Transport::Tcp {
            dst_port, payload, ..
        } => (*dst_port, payload.get(2..)?),
    };
    if dst_port != DNS_PORT {
        return None;
    }

    let (query_name, qtype) = crate::sensor::dns::parse_question(dns_payload)?;

    Some(SensorEvent {
        platform: Platform::MacOS,
        provider: "bpf",
        action: SensorAction::Query,
        normalization: SensorNormalization {
            event_id: EVENT_ID_DNS_QUERY,
            action_code: 0,
        },
        pid: None,
        timestamp: SystemTime::now(),
        process_start_key: None,
        payload: SensorPayload::Dns(DnsQueryFields {
            query_name: Some(query_name),
            query_results: None,
            record_type: record_type_name(qtype).map(str::to_string),
            query_status: None,
            process_id: None,
            image: None,
        }),
    })
}

/// Map a DNS QTYPE to its record-type name, for the common types.
fn record_type_name(qtype: u16) -> Option<&'static str> {
    let name = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => return None,
    };
    Some(name)
}

fn try_send(tx: &Sender<SensorEvent>, event: SensorEvent) {
    match tx.try_send(event) {
        Ok(_) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            warn!("bpf sensor: event channel full, dropping event");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            // Pipeline has shut down; stop logging.
        }
    }
}

fn read_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn read_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([buf[at], buf[at + 1]])
}

/// Round up to the next `BPF_ALIGNMENT` (4-byte) boundary.
fn bpf_word_align(value: usize) -> usize {
    (value + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a bpf record (20-byte header + payload) padded to word alignment.
    fn bpf_record(payload: &[u8]) -> Vec<u8> {
        let hdrlen: u16 = 18;
        let caplen = payload.len() as u32;
        let mut record = vec![0u8; hdrlen as usize];
        record[BH_CAPLEN_OFFSET..BH_CAPLEN_OFFSET + 4].copy_from_slice(&caplen.to_ne_bytes());
        record[BH_HDRLEN_OFFSET..BH_HDRLEN_OFFSET + 2].copy_from_slice(&hdrlen.to_ne_bytes());
        record.extend_from_slice(payload);
        record.resize(bpf_word_align(hdrlen as usize + payload.len()), 0);
        record
    }

    #[test]
    fn bpf_filter_accepts_and_ends_with_a_drop() {
        // BPF_RET | BPF_K: a terminating return with an immediate operand.
        const BPF_RET_K: u16 = 0x0006;
        let last = BPF_FILTER_EN10MB
            .last()
            .expect("filter program is not empty");
        // The program must end by dropping non-matching frames (return 0)...
        assert_eq!(last.code, BPF_RET_K);
        assert_eq!(last.k, 0);
        // ...and must contain at least one accepting return (non-zero length).
        assert!(BPF_FILTER_EN10MB
            .iter()
            .any(|insn| insn.code == BPF_RET_K && insn.k > 0));
    }

    #[test]
    fn for_each_packet_yields_each_record() {
        let mut buf = bpf_record(&[1, 2, 3]);
        buf.extend(bpf_record(&[9, 8, 7, 6, 5]));

        let mut packets: Vec<Vec<u8>> = Vec::new();
        for_each_packet(&buf, |packet| packets.push(packet.to_vec()));

        assert_eq!(packets, vec![vec![1, 2, 3], vec![9, 8, 7, 6, 5]]);
    }

    #[test]
    fn for_each_packet_ignores_trailing_partial_header() {
        let mut buf = bpf_record(&[1, 2, 3, 4]);
        buf.extend_from_slice(&[0u8; 5]); // shorter than a header

        let mut count = 0;
        for_each_packet(&buf, |_| count += 1);
        assert_eq!(count, 1);
    }

    #[test]
    fn for_each_packet_stops_on_truncated_capture() {
        let mut buf = vec![0u8; 18];
        // Claim a 100-byte capture that the buffer cannot satisfy.
        buf[BH_CAPLEN_OFFSET..BH_CAPLEN_OFFSET + 4].copy_from_slice(&100u32.to_ne_bytes());
        buf[BH_HDRLEN_OFFSET..BH_HDRLEN_OFFSET + 2].copy_from_slice(&18u16.to_ne_bytes());

        let mut count = 0;
        for_each_packet(&buf, |_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn bpf_word_align_rounds_up_to_four() {
        assert_eq!(bpf_word_align(0), 0);
        assert_eq!(bpf_word_align(1), 4);
        assert_eq!(bpf_word_align(18), 20);
        assert_eq!(bpf_word_align(20), 20);
    }

    fn tcp_packet(flags: u8) -> ParsedPacket<'static> {
        ParsedPacket {
            src_ip: "10.0.0.5".parse().unwrap(),
            dst_ip: "93.184.216.34".parse().unwrap(),
            transport: Transport::Tcp {
                src_port: 51324,
                dst_port: 443,
                flags,
                payload: &[],
            },
        }
    }

    #[test]
    fn build_network_event_emits_on_syn() {
        let event = build_network_event(&tcp_packet(TCP_FLAG_SYN)).expect("syn should emit");
        assert_eq!(event.provider, "bpf");
        assert_eq!(event.action, SensorAction::Connect);
        assert_eq!(event.normalization.event_id, EVENT_ID_NETWORK_CONNECT);
        match event.payload {
            SensorPayload::Network(fields) => {
                assert_eq!(fields.destination_ip.as_deref(), Some("93.184.216.34"));
                assert_eq!(fields.source_ip.as_deref(), Some("10.0.0.5"));
                assert_eq!(fields.destination_port.as_deref(), Some("443"));
                assert_eq!(fields.protocol.as_deref(), Some("tcp"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn build_network_event_ignores_syn_ack_and_established() {
        assert!(build_network_event(&tcp_packet(TCP_FLAG_SYN | TCP_FLAG_ACK)).is_none());
        assert!(build_network_event(&tcp_packet(TCP_FLAG_ACK)).is_none());
    }

    #[test]
    fn enqueue_attribution_emits_unattributed_when_worker_saturated() {
        // A rendezvous channel with no worker receiving: try_send always reports
        // the queue full, so the capture thread must emit the event itself
        // rather than block or drop it.
        let (attribution_tx, _attribution_rx) = std::sync::mpsc::sync_channel::<AttributionJob>(0);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SensorEvent>(8);

        let event = build_network_event(&tcp_packet(TCP_FLAG_SYN)).expect("syn should emit");
        enqueue_attribution(&attribution_tx, &tx, event, 51324, 443);

        let received = rx
            .try_recv()
            .expect("event should still reach the pipeline");
        assert!(received.pid.is_none(), "event should be unattributed");
        match received.payload {
            SensorPayload::Network(fields) => assert!(fields.process_id.is_none()),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn connection_ports_reads_tcp_only() {
        assert_eq!(
            connection_ports(&tcp_packet(TCP_FLAG_SYN)),
            Some((51324, 443))
        );
        assert_eq!(connection_ports(&udp_packet(DNS_PORT, vec![])), None);
    }

    /// Minimal single-question DNS query payload for `name` with the given qtype.
    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[5] = 1; // qdcount = 1
        for label in name.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.push(0);
        payload.extend_from_slice(&qtype.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes()); // qclass = IN
        payload
    }

    fn udp_packet(dst_port: u16, payload: Vec<u8>) -> ParsedPacket<'static> {
        ParsedPacket {
            src_ip: "10.0.0.5".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            transport: Transport::Udp {
                dst_port,
                payload: Box::leak(payload.into_boxed_slice()),
            },
        }
    }

    #[test]
    fn build_dns_event_maps_udp_query() {
        let event = build_dns_event(&udp_packet(DNS_PORT, dns_query("sub.example.test", 28)))
            .expect("dns query should emit");
        assert_eq!(event.provider, "bpf");
        assert_eq!(event.action, SensorAction::Query);
        assert_eq!(event.normalization.event_id, EVENT_ID_DNS_QUERY);
        match event.payload {
            SensorPayload::Dns(fields) => {
                assert_eq!(fields.query_name.as_deref(), Some("sub.example.test"));
                assert_eq!(fields.record_type.as_deref(), Some("AAAA"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn build_dns_event_ignores_non_dns_port() {
        assert!(build_dns_event(&udp_packet(123, dns_query("example.test", 1))).is_none());
    }

    #[test]
    fn record_type_name_maps_known_types() {
        assert_eq!(record_type_name(1), Some("A"));
        assert_eq!(record_type_name(28), Some("AAAA"));
        assert_eq!(record_type_name(64000), None);
    }

    fn test_normalizer() -> crate::normalizer::Normalizer {
        use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
        crate::normalizer::Normalizer::new(
            Arc::new(ProcessCache::new()),
            Arc::new(SidCache::new()),
            Arc::new(DnsCache::new()),
            Arc::new(ConnectionAggregator::new()),
            false,
        )
    }

    #[test]
    fn macos_dns_query_matches_product_macos_sigma_rule() {
        use crate::engine::Engine;
        use crate::sensor::Platform;

        let tempdir = tempfile::tempdir().expect("create sigma tempdir");
        let rules_dir = tempdir.path().join("sigma");
        std::fs::create_dir_all(&rules_dir).expect("create sigma rules dir");
        std::fs::write(
            rules_dir.join("dns.yml"),
            r#"title: macOS DNS QueryName
logsource:
  product: macos
  category: dns_query
detection:
  selection:
    QueryName|endswith: ".example.test"
  condition: selection
level: high
"#,
        )
        .expect("write sigma rule");

        let mut engine = Engine::new_for_platform(Platform::MacOS);
        engine.load_rules(&rules_dir).expect("load sigma rule");

        let event = build_dns_event(&udp_packet(DNS_PORT, dns_query("sub.example.test", 1)))
            .expect("dns event should build");
        let normalized = test_normalizer()
            .normalize(&event)
            .expect("dns event should normalize");
        assert_eq!(normalized.get_field("QueryName"), Some("sub.example.test"));

        let alert = engine
            .check_event(&normalized)
            .expect("macOS dns Sigma rule should match parsed QueryName");
        assert_eq!(alert.rule_name, "macOS DNS QueryName");
    }
}
