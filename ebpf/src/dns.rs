//! DNS syscall telemetry eBPF programs.
//!
//! Emits outbound DNS query telemetry from `sendto(2)` payloads, capturing
//! PID/UID/FD and the DNS record type (QTYPE).  The domain name is **not**
//! extracted in eBPF — doing so exceeded the BPF verifier's 1 M-instruction
//! complexity limit.  Callers should enrich the event with the domain in
//! userspace via `/proc/<pid>/net/` or application-layer tracing.

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

    // ── Stage 1: one probe read ──────────────────────────────────────────────

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

    // ── Stage 2: parse (kernel memory only) ─────────────────────────────────

    // Validate DNS header: must be a query (QR=0) with at least one question.
    let flags = (((*scratch).payload[2] as u16) << 8) | ((*scratch).payload[3] as u16);
    let qdcount = (((*scratch).payload[4] as u16) << 8) | ((*scratch).payload[5] as u16);
    if flags & 0x8000 != 0 || qdcount == 0 {
        return Ok(0);
    }

    // Locate QTYPE: scan past the name (null-terminated labels) to the QTYPE
    // field.  We only scan forward for the null byte — no label structure
    // tracking.  Trip count is bounded by MAX_DNS_PAYLOAD so the verifier
    // sees a small, fixed upper bound with no nested state.
    let mut pos = DNS_HEADER_LEN;
    let mut i = 0usize;
    while i < MAX_DNS_PAYLOAD {
        if pos >= read_len {
            return Ok(0);
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
        return Ok(0);
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

    Ok(0)
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
