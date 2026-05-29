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
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::sensor::{Sensor, SensorEvent};

/// Environment variable overriding the capture interface (default `en0`).
const INTERFACE_ENV: &str = "RUSTINEL_BPF_INTERFACE";
const DEFAULT_INTERFACE: &str = "en0";

/// Requested BPF read-buffer size, set via `BIOCSBLEN` before binding. The
/// kernel may cap this; the effective size is read back and used for reads.
const BPF_BUFFER_LEN: u32 = 1 << 18; // 256 KiB

/// Read timeout so the capture loop wakes periodically to observe shutdown.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

// BPF ioctl request codes for 64-bit macOS, from <net/bpf.h>. Encoded with the
// _IOW/_IOR/_IOWR macros; verified against the SDK headers.
const BIOCSBLEN: libc::c_ulong = 0xc004_4266; // _IOWR('B', 102, u_int)
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
            set_u32(fd, BIOCIMMEDIATE, 1)?;
            set_read_timeout(fd, READ_TIMEOUT)?;
            get_u32(fd, BIOCGDLT)
        };
        match configure() {
            Ok(link_type) => Ok(Self {
                fd,
                link_type,
                buffer_len,
            }),
            Err(e) => {
                close_fd(fd);
                Err(anyhow!("failed to configure bpf device for {interface}: {e}"))
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

/// Capture loop: read batches of bpf records and dispatch each packet.
fn run_capture(device: BpfDevice, tx: Sender<SensorEvent>, shutdown: Arc<AtomicBool>) {
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
        for_each_packet(data, |packet| handle_packet(device.link_type, packet, &tx));
    }
    info!("bpf sensor shutting down");
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

/// Dispatch a captured link-layer frame. Network and DNS translation are added
/// in following commits; for now frames are consumed without emitting events.
fn handle_packet(_link_type: u32, _packet: &[u8], _tx: &Sender<SensorEvent>) {}

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
}
