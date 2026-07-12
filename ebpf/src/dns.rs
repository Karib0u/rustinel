//! DNS syscall telemetry eBPF programs.
//!
//! Emits outbound DNS query telemetry from `sendto(2)`, `sendmsg(2)`, and
//! `sendmmsg(2)` payloads, capturing PID/UID/FD and the DNS record type
//! (QTYPE). The domain name is not extracted in eBPF because doing so
//! exceeded the BPF verifier's 1 M-instruction complexity limit. Callers
//! should enrich the event with the domain in userspace via the raw payload.

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};

use crate::events::DnsEvent;

const DNS_EVENT_QUERY: u32 = 1;
const DNS_HEADER_LEN: usize = 12;
const DNS_PORT: u16 = 53;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_NS: u16 = 2;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;

/// Maximum bytes of DNS payload we copy in one probe read.
const MAX_DNS_PAYLOAD: usize = 256;

/// Maximum iovec segments copied from one sendmsg-style message.
///
/// DNS libraries normally pass one contiguous payload iovec. Keeping this at
/// one gives the verifier a statically bounded destination range.
const MAX_IOVEC_SEGMENTS: usize = 1;

/// Maximum messages inspected from one sendmmsg call.
const MAX_SENDMMSG_MESSAGES: usize = 4;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

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

/// Ring buffer shared with the userspace loader for DNS events.
#[map]
pub static DNS_RING: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU buffer: staging area for the outgoing `DnsEvent`.
#[map]
static DNS_SCRATCH: PerCpuArray<DnsEvent> = PerCpuArray::with_max_entries(1, 0);

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

#[inline(always)]
unsafe fn try_handle_sendto(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let fd = ctx.read_at::<i64>(16)? as i32;
    let buf_ptr = ctx.read_at::<u64>(24)?;
    let len = ctx.read_at::<u64>(32)? as usize;
    let addr_ptr = ctx.read_at::<u64>(48)?;

    if buf_ptr == 0
        || len < DNS_HEADER_LEN
        || (addr_ptr != 0 && !sockaddr_points_to_dns_port(addr_ptr)?)
    {
        return Ok(0);
    }

    let scratch = match DNS_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let read_len = len.min(MAX_DNS_PAYLOAD);
    (*scratch).payload = [0u8; MAX_DNS_PAYLOAD];
    if bpf_probe_read_user_buf(
        buf_ptr as *const u8,
        &mut (&mut (*scratch).payload)[..read_len],
    )
    .is_err()
    {
        return Ok(0);
    }

    emit_dns_query(scratch, pid, uid, fd, read_len);

    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_sendmsg(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let fd = ctx.read_at::<i64>(16)? as i32;
    let msg_ptr = ctx.read_at::<u64>(24)?;

    if msg_ptr == 0 {
        return Ok(0);
    }

    let msg = match bpf_probe_read_user::<UserMsghdr>(msg_ptr as *const _) {
        Ok(value) => value,
        Err(_) => return Ok(0),
    };
    if msg.msg_name != 0 && !sockaddr_points_to_dns_port(msg.msg_name)? {
        return Ok(0);
    }

    let scratch = match DNS_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let read_len = match read_iovec_payload(&msg, &mut (*scratch).payload) {
        Some(value) => value,
        None => return Ok(0),
    };

    emit_dns_query(scratch, pid, uid, fd, read_len);

    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_sendmmsg(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let fd = ctx.read_at::<i64>(16)? as i32;
    let msgvec_ptr = ctx.read_at::<u64>(24)?;
    let message_count = ctx.read_at::<u64>(32)? as usize;

    if msgvec_ptr == 0 || message_count == 0 {
        return Ok(0);
    }

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
        if msg.msg_name != 0 && !sockaddr_points_to_dns_port(msg.msg_name)? {
            index += 1;
            continue;
        }

        let scratch = match DNS_SCRATCH.get_ptr_mut(0) {
            Some(p) => p,
            None => return Ok(0),
        };
        let read_len = match read_iovec_payload(&msg, &mut (*scratch).payload) {
            Some(value) => value,
            None => {
                index += 1;
                continue;
            }
        };

        emit_dns_query(scratch, pid, uid, fd, read_len);
        index += 1;
    }

    Ok(0)
}

#[inline(always)]
unsafe fn read_iovec_payload(msg: &UserMsghdr, payload: &mut [u8; MAX_DNS_PAYLOAD]) -> Option<usize> {
    if msg.msg_iov == 0 || msg.msg_iovlen < MAX_IOVEC_SEGMENTS as u64 {
        return None;
    }

    *payload = [0u8; MAX_DNS_PAYLOAD];
    let iovec = match bpf_probe_read_user::<UserIovec>(msg.msg_iov as *const _) {
        Ok(value) => value,
        Err(_) => return None,
    };
    if iovec.iov_base == 0 || iovec.iov_len < DNS_HEADER_LEN as u64 {
        return None;
    }

    let read_len = (iovec.iov_len as usize).min(MAX_DNS_PAYLOAD);
    if bpf_probe_read_user_buf(iovec.iov_base as *const u8, &mut payload[..read_len]).is_err() {
        return None;
    }

    Some(read_len)
}

#[inline(always)]
unsafe fn emit_dns_query(scratch: *mut DnsEvent, pid: u32, uid: u32, fd: i32, read_len: usize) {
    if read_len < DNS_HEADER_LEN || read_len > MAX_DNS_PAYLOAD {
        return;
    }

    // Validate DNS header: must be a query (QR=0) with at least one question.
    let flags = (((*scratch).payload[2] as u16) << 8) | ((*scratch).payload[3] as u16);
    let qdcount = (((*scratch).payload[4] as u16) << 8) | ((*scratch).payload[5] as u16);
    if flags & 0x8000 != 0 || qdcount == 0 {
        return;
    }

    // Locate QTYPE: scan past the name (null-terminated labels) to the QTYPE
    // field.  We only scan forward for the null byte — no label structure
    // tracking.  Trip count is bounded by MAX_DNS_PAYLOAD so the verifier
    // sees a small, fixed upper bound with no nested state.
    let mut pos = DNS_HEADER_LEN;
    let mut i = 0usize;
    while i < MAX_DNS_PAYLOAD {
        if pos >= read_len {
            return;
        }
        let b = (*scratch).payload[pos & (MAX_DNS_PAYLOAD - 1)];
        if b == 0 {
            // Found end of name.
            break;
        }
        pos += 1;
        i += 1;
    }
    // pos points at the null byte; QTYPE is the two bytes that follow.
    if pos + 3 > read_len {
        return;
    }
    let qtype = (((*scratch).payload[(pos + 1) & (MAX_DNS_PAYLOAD - 1)] as u16) << 8)
        | ((*scratch).payload[(pos + 2) & (MAX_DNS_PAYLOAD - 1)] as u16);

    (*scratch).kind = DNS_EVENT_QUERY;
    (*scratch).pid = pid;
    (*scratch).uid = uid;
    (*scratch).fd = fd;
    (*scratch).payload_len = read_len as u16;
    (*scratch)._pad0 = 0;
    (*scratch).query_name = [0u8; 96];
    (*scratch).query_results = [0u8; 96];
    (*scratch).record_type = [0u8; 16];
    write_record_type(qtype, &mut (*scratch).record_type);

    // ── Stage 3: ring-buffer commit ──────────────────────────────────────────

    if let Some(mut entry) = DNS_RING.reserve::<DnsEvent>(0) {
        entry.write(*scratch);
        entry.submit(0);
    }
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

#[inline(always)]
fn write_record_type(record_type: u16, out: &mut [u8; 16]) {
    let value: &[u8] = match record_type {
        DNS_TYPE_A => b"A",
        DNS_TYPE_NS => b"NS",
        DNS_TYPE_CNAME => b"CNAME",
        DNS_TYPE_PTR => b"PTR",
        DNS_TYPE_TXT => b"TXT",
        DNS_TYPE_AAAA => b"AAAA",
        _ => b"OTHER",
    };

    let mut idx = 0usize;
    while idx < value.len() && idx < 15 {
        out[idx] = value[idx];
        idx += 1;
    }
    if idx < 16 {
        out[idx] = 0;
    }
}
