//! DNS syscall telemetry eBPF programs.
//!
//! Copies raw DNS messages to userspace, which parses both directions:
//!
//! - Queries come from `sendto(2)`, `sendmsg(2)`, `sendmmsg(2)`, and
//!   `write(2)`. `send(2)` is `sendto` with no address.
//! - Responses come from `recvfrom(2)`, `recvmsg(2)`, and `read(2)`, captured
//!   at syscall exit once the kernel has filled the buffer.
//!
//! `read` and `write` are the busiest syscalls on any host, so they are hooked
//! with `fentry`/`fexit` on `ksys_write`/`ksys_read` rather than syscall
//! tracepoints. On kernel 7.0 an empty `sys_enter_write` program cost about
//! 200 ns per call because the tracepoint copies the write buffer for its
//! consumer; `fentry` cost about 35 ns and the `fexit` on `ksys_read` about
//! 65 ns, with no entry-to-exit map. Both need kernel BTF.
//!
//! A descriptor is a DNS socket once it is connected, or sends a query, to
//! port 53. [`DNS_SOCKETS`] records that per `(tgid, fd)`, so a connected
//! socket that sends with no destination address, and every receive, is
//! matched by a map lookup rather than by guessing from the payload. Close and
//! `dup2`/`dup3` retire the entry through [`forget_socket`] before the number
//! can be reused.
//!
//! Nothing here walks the DNS name: doing so in eBPF exceeded the verifier's
//! 1 M-instruction complexity limit. The kernel only checks the header's QR
//! bit and question count; userspace does all parsing.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_buf},
    macros::{fentry, fexit, map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext, TracePointContext},
};

use crate::events::{
    event_metadata, DnsEvent, DNS_EVENT_QUERY, DNS_EVENT_RESPONSE, DNS_PAYLOAD_CAPACITY,
};
use crate::process::current_process_start_time;
use crate::telemetry::{record_map_full, record_ring_full, record_submitted, DNS_FAMILY};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsTracepointOffsets {
    pub sendto_fd: u32,
    pub sendto_buf: u32,
    pub sendto_len: u32,
    pub sendto_addr: u32,
    pub sendmsg_fd: u32,
    pub sendmsg_msg: u32,
    pub sendmmsg_fd: u32,
    pub sendmmsg_msgvec: u32,
    pub sendmmsg_vlen: u32,
    pub connect_fd: u32,
    pub connect_addr: u32,
    pub recvfrom_fd: u32,
    pub recvfrom_buf: u32,
    pub recvfrom_size: u32,
    pub recvfrom_ret: u32,
    pub recvmsg_fd: u32,
    pub recvmsg_msg: u32,
    pub recvmsg_ret: u32,
}

#[no_mangle]
pub static DNS_TRACEPOINT_OFFSETS: DnsTracepointOffsets = DnsTracepointOffsets {
    sendto_fd: 0,
    sendto_buf: 0,
    sendto_len: 0,
    sendto_addr: 0,
    sendmsg_fd: 0,
    sendmsg_msg: 0,
    sendmmsg_fd: 0,
    sendmmsg_msgvec: 0,
    sendmmsg_vlen: 0,
    connect_fd: 0,
    connect_addr: 0,
    recvfrom_fd: 0,
    recvfrom_buf: 0,
    recvfrom_size: 0,
    recvfrom_ret: 0,
    recvmsg_fd: 0,
    recvmsg_msg: 0,
    recvmsg_ret: 0,
};

#[inline(always)]
unsafe fn tracepoint_offset(value: *const u32) -> usize {
    core::ptr::read_volatile(value) as usize
}

const DNS_HEADER_LEN: usize = 12;
const DNS_PORT: u16 = 53;

/// Maximum iovec segments copied from one sendmsg-style message.
///
/// DNS libraries normally pass one contiguous payload iovec. Keeping this at
/// one gives the verifier a statically bounded destination range.
const MAX_IOVEC_SEGMENTS: usize = 1;

/// Maximum messages inspected from one sendmmsg call.
const MAX_SENDMMSG_MESSAGES: usize = 4;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// [`DNS_SOCKETS`] value for a descriptor talking to port 53. Zero marks a
/// retired slot.
const DNS_SOCKET_ACTIVE: u8 = 1;

/// Pending receive whose buffer is the payload itself (`recvfrom`).
const RECV_BUFFER: u32 = 1;
/// Pending receive whose pointer is a `struct msghdr` (`recvmsg`).
const RECV_MSGHDR: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: u16,
    addr: [u8; 4],
    _pad: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

/// 64-bit Linux userspace `struct msghdr` layout.
///
/// The syscall tracepoints expose userspace pointers, so this layout is read
/// with `bpf_probe_read_user` instead of dereferenced directly.
#[repr(C)]
#[derive(Clone, Copy)]
struct UserMsghdr {
    msg_name: u64,
    msg_namelen: u32,
    _pad0: u32,
    msg_iov: u64,
    msg_iovlen: u64,
    msg_control: u64,
    msg_controllen: u64,
    msg_flags: u32,
    _pad1: u32,
}

/// 64-bit Linux userspace `struct iovec` layout.
#[repr(C)]
#[derive(Clone, Copy)]
struct UserIovec {
    iov_base: u64,
    iov_len: u64,
}

/// 64-bit Linux userspace `struct mmsghdr` layout.
#[repr(C)]
#[derive(Clone, Copy)]
struct UserMmsghdr {
    msg_hdr: UserMsghdr,
    msg_len: u32,
    _pad0: u32,
}

/// Receive a thread is inside on a DNS socket, carried from entry to exit.
#[repr(C)]
#[derive(Clone, Copy)]
struct PendingRecv {
    /// Payload buffer for [`RECV_BUFFER`], `struct msghdr` for [`RECV_MSGHDR`].
    ptr: u64,
    /// Buffer capacity for [`RECV_BUFFER`]; unused for [`RECV_MSGHDR`].
    len: u64,
    fd: i32,
    kind: u32,
    /// Tracepoint that queued the receive, so a mismatched exit ignores it.
    syscall: u32,
    _pad: u32,
}

/// Ring buffer shared with the userspace loader for DNS events.
#[map]
pub static DNS_RING: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU buffer: staging area for the outgoing `DnsEvent`.
#[map]
static DNS_SCRATCH: PerCpuArray<DnsEvent> = PerCpuArray::with_max_entries(1, 0);

/// Descriptors known to talk to port 53, keyed by `tgid << 32 | fd`.
///
/// LRU so that entries a process never closed (it exited, or the socket was
/// connected before the agent started) age out instead of filling the map.
#[map]
static DNS_SOCKETS: LruHashMap<u64, u8> = LruHashMap::with_max_entries(8_192, 0);

/// Receive in progress on a DNS socket, keyed by TID.
///
/// A thread is inside one syscall at a time. LRU so that a thread killed
/// mid-receive, whose exit never runs, cannot leak its slot.
#[map]
static DNS_RECV_PENDING: LruHashMap<u32, PendingRecv> = LruHashMap::with_max_entries(4_096, 0);

const SYSCALL_RECVFROM: u32 = 1;
const SYSCALL_RECVMSG: u32 = 2;

#[tracepoint]
pub fn handle_sendto(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_sendto(&ctx) }.unwrap_or(1)
}

#[tracepoint]
pub fn handle_sendmsg(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_sendmsg(&ctx) }.unwrap_or(1)
}

#[tracepoint]
pub fn handle_sendmmsg(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_sendmmsg(&ctx) }.unwrap_or(1)
}

/// `write(2)` on a DNS socket: `ksys_write(fd, buf, count)`.
#[fentry]
pub fn handle_dns_write(ctx: FEntryContext) -> u32 {
    unsafe {
        let fd = ctx.arg::<u32>(0) as i32;
        // Settle membership before touching anything else.
        let tgid = current_tgid();
        if is_dns_socket(tgid, fd) {
            capture_buffer(
                tgid,
                fd,
                ctx.arg::<u64>(1),
                ctx.arg::<u64>(2),
                DNS_EVENT_QUERY,
            );
        }
    }
    0
}

/// Mark or retire a descriptor as a DNS socket when it is connected.
#[tracepoint]
pub fn handle_dns_connect(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_connect(&ctx) }.unwrap_or(1)
}

#[tracepoint]
pub fn handle_dns_recvfrom(ctx: TracePointContext) -> u32 {
    unsafe {
        let off = &DNS_TRACEPOINT_OFFSETS;
        queue_recv(
            &ctx,
            tracepoint_offset(core::ptr::addr_of!(off.recvfrom_fd)),
            tracepoint_offset(core::ptr::addr_of!(off.recvfrom_buf)),
            Some(tracepoint_offset(core::ptr::addr_of!(off.recvfrom_size))),
            SYSCALL_RECVFROM,
        )
    }
    .unwrap_or(1)
}

#[tracepoint]
pub fn handle_dns_recvfrom_exit(ctx: TracePointContext) -> u32 {
    unsafe {
        complete_recv(
            &ctx,
            tracepoint_offset(core::ptr::addr_of!(DNS_TRACEPOINT_OFFSETS.recvfrom_ret)),
            SYSCALL_RECVFROM,
        )
    }
    .unwrap_or(1)
}

#[tracepoint]
pub fn handle_dns_recvmsg(ctx: TracePointContext) -> u32 {
    unsafe {
        let off = &DNS_TRACEPOINT_OFFSETS;
        queue_recv(
            &ctx,
            tracepoint_offset(core::ptr::addr_of!(off.recvmsg_fd)),
            tracepoint_offset(core::ptr::addr_of!(off.recvmsg_msg)),
            None,
            SYSCALL_RECVMSG,
        )
    }
    .unwrap_or(1)
}

#[tracepoint]
pub fn handle_dns_recvmsg_exit(ctx: TracePointContext) -> u32 {
    unsafe {
        complete_recv(
            &ctx,
            tracepoint_offset(core::ptr::addr_of!(DNS_TRACEPOINT_OFFSETS.recvmsg_ret)),
            SYSCALL_RECVMSG,
        )
    }
    .unwrap_or(1)
}

/// `read(2)` on a DNS socket: `ksys_read(fd, buf, count)` and its return.
#[fexit]
pub fn handle_dns_read(ctx: FExitContext) -> u32 {
    unsafe {
        let fd = ctx.arg::<u32>(0) as i32;
        let tgid = current_tgid();
        let ret = ctx.arg::<i64>(3);
        if ret >= DNS_HEADER_LEN as i64 && is_dns_socket(tgid, fd) {
            capture_buffer(
                tgid,
                fd,
                ctx.arg::<u64>(1),
                (ret as u64).min(ctx.arg::<u64>(2)),
                DNS_EVENT_RESPONSE,
            );
        }
    }
    0
}

#[inline(always)]
fn socket_key(tgid: u32, fd: i32) -> u64 {
    ((tgid as u64) << 32) | (fd as u32 as u64)
}

#[inline(always)]
fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[inline(always)]
unsafe fn is_dns_socket(tgid: u32, fd: i32) -> bool {
    if fd < 0 {
        return false;
    }
    matches!(
        DNS_SOCKETS.get(&socket_key(tgid, fd)),
        Some(&DNS_SOCKET_ACTIVE)
    )
}

#[inline(always)]
unsafe fn remember_socket(tgid: u32, fd: i32) {
    if fd < 0 {
        return;
    }
    if DNS_SOCKETS
        .insert(&socket_key(tgid, fd), &DNS_SOCKET_ACTIVE, 0)
        .is_err()
    {
        record_map_full(DNS_FAMILY);
    }
}

/// Retire `fd` as a DNS socket before its number can be reused.
///
/// Called from the file close and `dup2`/`dup3` hooks. The slot is zeroed
/// rather than deleted, following the directory index: the lookup on every
/// close is cheaper than LRU removal.
#[inline(always)]
pub unsafe fn forget_socket(tgid: u32, fd: i32) {
    if fd < 0 {
        return;
    }
    if let Some(state) = DNS_SOCKETS.get_ptr_mut(&socket_key(tgid, fd)) {
        *state = 0;
    }
}

#[inline(always)]
unsafe fn try_handle_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.connect_fd
    )))? as i32;
    let addr_ptr = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.connect_addr
    )))?;
    let tgid = current_tgid();
    // Reconnecting elsewhere, or dissolving with AF_UNSPEC, ends the socket's
    // time as a DNS socket just as closing it does.
    if addr_ptr != 0 && sockaddr_points_to_dns_port(addr_ptr)? {
        remember_socket(tgid, fd);
    } else {
        forget_socket(tgid, fd);
    }
    Ok(0)
}

/// Whether a send may carry a DNS query: it names port 53, or it names no
/// destination and the descriptor is already a DNS socket.
#[inline(always)]
unsafe fn send_targets_dns(tgid: u32, fd: i32, addr_ptr: u64) -> Result<bool, i64> {
    if addr_ptr == 0 {
        return Ok(is_dns_socket(tgid, fd));
    }
    if !sockaddr_points_to_dns_port(addr_ptr)? {
        return Ok(false);
    }
    // An unconnected socket that sends to port 53 receives the answer on the
    // same descriptor.
    if !is_dns_socket(tgid, fd) {
        remember_socket(tgid, fd);
    }
    Ok(true)
}

#[inline(always)]
unsafe fn try_handle_sendto(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendto_fd
    )))? as i32;
    let buf_ptr = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendto_buf
    )))?;
    let len = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendto_len
    )))?;
    let addr_ptr = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendto_addr
    )))?;

    if buf_ptr == 0 || len < DNS_HEADER_LEN as u64 {
        return Ok(0);
    }
    let tgid = current_tgid();
    if !send_targets_dns(tgid, fd, addr_ptr)? {
        return Ok(0);
    }
    capture_buffer(tgid, fd, buf_ptr, len, DNS_EVENT_QUERY);
    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_sendmsg(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendmsg_fd
    )))? as i32;
    let msg_ptr = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendmsg_msg
    )))?;

    if msg_ptr == 0 {
        return Ok(0);
    }

    let msg = match bpf_probe_read_user::<UserMsghdr>(msg_ptr as *const _) {
        Ok(value) => value,
        Err(_) => return Ok(0),
    };
    let tgid = current_tgid();
    if !send_targets_dns(tgid, fd, msg.msg_name)? {
        return Ok(0);
    }
    capture_msghdr(tgid, fd, &msg, u64::MAX, DNS_EVENT_QUERY);
    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_sendmmsg(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendmmsg_fd
    )))? as i32;
    let msgvec_ptr = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendmmsg_msgvec
    )))?;
    let message_count = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        DNS_TRACEPOINT_OFFSETS.sendmmsg_vlen
    )))? as usize;

    if msgvec_ptr == 0 || message_count == 0 {
        return Ok(0);
    }

    let tgid = current_tgid();
    let mut index = 0usize;
    while index < MAX_SENDMMSG_MESSAGES {
        if index >= message_count {
            break;
        }

        let offset = index * core::mem::size_of::<UserMmsghdr>();
        let msg_ptr = msgvec_ptr.wrapping_add(offset as u64);
        let msg = match bpf_probe_read_user::<UserMsghdr>(msg_ptr as *const _) {
            Ok(value) => value,
            Err(_) => break,
        };
        if send_targets_dns(tgid, fd, msg.msg_name)? {
            capture_msghdr(tgid, fd, &msg, u64::MAX, DNS_EVENT_QUERY);
        }
        index += 1;
    }

    Ok(0)
}

/// Remember a receive on a DNS socket so its exit can copy what arrived.
#[inline(always)]
unsafe fn queue_recv(
    ctx: &TracePointContext,
    fd_offset: usize,
    ptr_offset: usize,
    len_offset: Option<usize>,
    syscall: u32,
) -> Result<u32, i64> {
    let fd = ctx.read_at::<i64>(fd_offset)? as i32;
    let pid_tgid = bpf_get_current_pid_tgid();
    if !is_dns_socket((pid_tgid >> 32) as u32, fd) {
        return Ok(0);
    }
    let ptr = ctx.read_at::<u64>(ptr_offset)?;
    if ptr == 0 {
        return Ok(0);
    }
    let (kind, len) = match len_offset {
        Some(offset) => (RECV_BUFFER, ctx.read_at::<u64>(offset)?),
        None => (RECV_MSGHDR, 0),
    };
    let pending = PendingRecv {
        ptr,
        len,
        fd,
        kind,
        syscall,
        _pad: 0,
    };
    if DNS_RECV_PENDING
        .insert(&(pid_tgid as u32), &pending, 0)
        .is_err()
    {
        record_map_full(DNS_FAMILY);
    }
    Ok(0)
}

/// Copy a completed receive queued by [`queue_recv`].
#[inline(always)]
unsafe fn complete_recv(
    ctx: &TracePointContext,
    ret_offset: usize,
    syscall: u32,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    let Some(pending) = DNS_RECV_PENDING.get(&tid) else {
        return Ok(0);
    };
    let pending = *pending;
    let _ = DNS_RECV_PENDING.remove(&tid);
    if pending.syscall != syscall {
        return Ok(0);
    }

    let ret = ctx.read_at::<i64>(ret_offset)?;
    if ret < DNS_HEADER_LEN as i64 {
        return Ok(0);
    }
    let tgid = (pid_tgid >> 32) as u32;
    if pending.kind == RECV_BUFFER {
        capture_buffer(
            tgid,
            pending.fd,
            pending.ptr,
            (ret as u64).min(pending.len),
            DNS_EVENT_RESPONSE,
        );
    } else {
        let msg = match bpf_probe_read_user::<UserMsghdr>(pending.ptr as *const _) {
            Ok(value) => value,
            Err(_) => return Ok(0),
        };
        capture_msghdr(tgid, pending.fd, &msg, ret as u64, DNS_EVENT_RESPONSE);
    }
    Ok(0)
}

/// Copy up to `len` bytes of a contiguous user buffer and emit them.
#[inline(always)]
unsafe fn capture_buffer(tgid: u32, fd: i32, buf_ptr: u64, len: u64, kind: u32) {
    if len < DNS_HEADER_LEN as u64 {
        return;
    }
    let Some(scratch) = DNS_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    let read_len = (len as usize).min(DNS_PAYLOAD_CAPACITY);
    (*scratch).payload = [0u8; DNS_PAYLOAD_CAPACITY];
    if bpf_probe_read_user_buf(
        buf_ptr as *const u8,
        &mut (&mut (*scratch).payload)[..read_len],
    )
    .is_err()
    {
        return;
    }
    emit_dns_event(scratch, tgid, fd, read_len, kind);
}

/// Copy the first iovec of a message, at most `limit` bytes, and emit it.
#[inline(always)]
unsafe fn capture_msghdr(tgid: u32, fd: i32, msg: &UserMsghdr, limit: u64, kind: u32) {
    if msg.msg_iov == 0 || msg.msg_iovlen < MAX_IOVEC_SEGMENTS as u64 {
        return;
    }
    let iovec = match bpf_probe_read_user::<UserIovec>(msg.msg_iov as *const _) {
        Ok(value) => value,
        Err(_) => return,
    };
    if iovec.iov_base == 0 {
        return;
    }
    capture_buffer(tgid, fd, iovec.iov_base, iovec.iov_len.min(limit), kind);
}

#[inline(always)]
unsafe fn emit_dns_event(scratch: *mut DnsEvent, tgid: u32, fd: i32, read_len: usize, kind: u32) {
    if read_len < DNS_HEADER_LEN || read_len > DNS_PAYLOAD_CAPACITY {
        return;
    }

    // Only the direction and a non-empty question are checked here; the
    // message itself is parsed in userspace.
    let response = (*scratch).payload[2] & 0x80 != 0;
    let qdcount = (((*scratch).payload[4] as u16) << 8) | ((*scratch).payload[5] as u16);
    if response != (kind == DNS_EVENT_RESPONSE) || qdcount == 0 {
        return;
    }

    (*scratch).kind = kind;
    (*scratch).pid = tgid;
    (*scratch).uid = crate::task_identity::effective_uid().unwrap_or(u32::MAX);
    (*scratch).fd = fd;
    (*scratch).payload_len = read_len as u16;
    (*scratch)._pad0 = 0;
    (*scratch)._pad1 = 0;
    (*scratch).process_start_time = current_process_start_time(tgid);

    let Some(mut entry) = DNS_RING.reserve::<DnsEvent>(0) else {
        record_ring_full(DNS_FAMILY);
        return;
    };
    ((*scratch).event_time_ns, (*scratch).source_seq) = event_metadata();
    entry.write(*scratch);
    entry.submit(0);
    record_submitted(DNS_FAMILY);
}

#[inline(always)]
unsafe fn sockaddr_points_to_dns_port(addr_ptr: u64) -> Result<bool, i64> {
    let family: u16 = bpf_probe_read_user(addr_ptr as *const u16)?;
    let port = match family {
        AF_INET => {
            let sa = bpf_probe_read_user::<SockAddrIn>(addr_ptr as *const _)?;
            u16::from_be(sa.port)
        }
        AF_INET6 => {
            let sa = bpf_probe_read_user::<SockAddrIn6>(addr_ptr as *const _)?;
            u16::from_be(sa.port)
        }
        _ => return Ok(false),
    };
    Ok(port == DNS_PORT)
}
