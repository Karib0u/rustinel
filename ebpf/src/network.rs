//! Connection syscall fallback. The fexit tier reads the bound kernel socket.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

use crate::events::{connect_result_is_connection, event_metadata, NetworkEvent};
use crate::process::current_process_start_time;
use crate::socket_tuple_abi::{raw_socket, AF_INET, AF_INET6, AF_PACKET, NETWORK_RAW_SOCKET};
use crate::telemetry::{record_map_full, record_ring_full, record_submitted, NETWORK_FAMILY};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkTracepointOffsets {
    pub connect_addr: u32,
    pub connect_ret: u32,
    pub socket_family: u32,
    pub socket_type: u32,
    pub socket_protocol: u32,
    pub socket_ret: u32,
}

#[no_mangle]
pub static NETWORK_TRACEPOINT_OFFSETS: NetworkTracepointOffsets = NetworkTracepointOffsets {
    connect_addr: 0,
    connect_ret: 0,
    socket_family: 0,
    socket_type: 0,
    socket_protocol: 0,
    socket_ret: 0,
};

#[inline(always)]
unsafe fn tracepoint_offset(value: *const u32) -> usize {
    core::ptr::read_volatile(value) as usize
}

/// IPv4 socket address as laid out by the C ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: u16,     // network byte order
    addr: [u8; 4], // network byte order
    _pad: [u8; 8],
}

/// IPv6 socket address as laid out by the C ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port: u16, // network byte order
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

/// Ring buffer shared with the userspace loader for network events.
#[map]
pub static NETWORK_RING: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Connect candidate a thread is currently inside, keyed by TID.
///
/// A thread is inside exactly one `connect(2)` at a time, so one slot per
/// thread is enough to carry the event from entry to exit. At 80 bytes per
/// entry this map costs well under a megabyte of kernel memory.
#[map]
static NETWORK_PENDING: HashMap<u32, NetworkEvent> = HashMap::with_max_entries(16_384, 0);

/// Tracepoint handler for `syscalls/sys_enter_connect`, where the destination
/// is still readable.
#[tracepoint]
pub fn handle_connect(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_connect(&ctx) }.unwrap_or(1)
}

/// Tracepoint handler for `syscalls/sys_exit_connect`, where the outcome of
/// the attempt is finally known.
#[tracepoint]
pub fn handle_connect_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_connect_exit(&ctx) }.unwrap_or(1)
}

#[inline(always)]
unsafe fn try_handle_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    // pid_tgid: high 32 bits = TGID (POSIX PID), low 32 bits = kernel thread ID.
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // A thread cannot be inside two syscalls at once, so anything still
    // pending belongs to a connect whose exit never ran — a task killed
    // mid-syscall. Drop it before this syscall's exit can emit it.
    let _ = NETWORK_PENDING.remove(&tid);

    let uid = crate::task_identity::effective_uid().unwrap_or(u32::MAX);

    // Read pointer to user-space sockaddr structure.
    let uservaddr: u64 = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        NETWORK_TRACEPOINT_OFFSETS.connect_addr
    )))?;
    if uservaddr == 0 {
        return Ok(0);
    }

    // Probe the address family (first 2 bytes of any sockaddr).
    let family: u16 = bpf_probe_read_user(uservaddr as *const u16)?;

    let mut daddr = [0u8; 16];
    let dport: u16;

    match family {
        AF_INET => {
            let sa = bpf_probe_read_user::<SockAddrIn>(uservaddr as *const _)?;
            dport = u16::from_be(sa.port);
            daddr[..4].copy_from_slice(&sa.addr);
        }
        AF_INET6 => {
            let sa = bpf_probe_read_user::<SockAddrIn6>(uservaddr as *const _)?;
            dport = u16::from_be(sa.port);
            daddr.copy_from_slice(&sa.addr);
        }
        // Skip non-IP address families (AF_UNIX, AF_NETLINK, etc.).
        _ => return Ok(0),
    }

    // Skip loopback-only connects (127.0.0.0/8 and ::1).
    if crate::socket_tuple_abi::loopback(family, &daddr) {
        return Ok(0);
    }

    let event = NetworkEvent {
        event_time_ns: 0,
        source_seq: 0,
        pid,
        uid,
        socket_protocol: 0,
        // Filled in by the exit handler, which is the only place the outcome
        // is known.
        ret: 0,
        dport,
        // Source address and port are still unassigned here and are not read
        // back at exit; the syscall fallback leaves source fields absent.
        sport: 0,
        af: family,
        protocol: 0,
        tuple_flags: 0,
        daddr,
        saddr: [0u8; 16],
        process_start_time: current_process_start_time(pid),
    };
    if NETWORK_PENDING.insert(&tid, &event, 0).is_err() {
        record_map_full(NETWORK_FAMILY);
    }

    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_connect_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        NETWORK_TRACEPOINT_OFFSETS.connect_ret
    )))? as i32;
    let tid = bpf_get_current_pid_tgid() as u32;

    let Some(pending) = NETWORK_PENDING.get(&tid) else {
        return Ok(0);
    };
    let mut event = *pending;
    let _ = NETWORK_PENDING.remove(&tid);

    if !connect_result_is_connection(ret) {
        return Ok(0);
    }
    event.ret = ret;

    submit_network(event);
    Ok(0)
}

#[inline(always)]
pub(crate) fn submit_network(mut event: NetworkEvent) -> bool {
    let Some(mut entry) = NETWORK_RING.reserve::<NetworkEvent>(0) else {
        record_ring_full(NETWORK_FAMILY);
        return false;
    };
    (event.event_time_ns, event.source_seq) = event_metadata();
    entry.write(event);
    entry.submit(0);
    record_submitted(NETWORK_FAMILY);
    true
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSocket {
    protocol: u32,
    family: u16,
    _pad: u16,
}

#[map]
static RAW_SOCKET_PENDING: HashMap<u32, RawSocket> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn handle_raw_socket(ctx: TracePointContext) -> u32 {
    unsafe { raw_socket_enter(&ctx) }.unwrap_or(1)
}

#[inline(always)]
unsafe fn raw_socket_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let family = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        NETWORK_TRACEPOINT_OFFSETS.socket_family
    )))? as u16;
    let socket_type = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        NETWORK_TRACEPOINT_OFFSETS.socket_type
    )))? as i32;
    let tid = bpf_get_current_pid_tgid() as u32;
    if !raw_socket(family, socket_type) {
        let _ = RAW_SOCKET_PENDING.remove(&tid);
        return Ok(0);
    }
    let protocol = ctx.read_at::<u64>(tracepoint_offset(core::ptr::addr_of!(
        NETWORK_TRACEPOINT_OFFSETS.socket_protocol
    )))? as u32;
    let socket = RawSocket {
        family,
        protocol: if family == AF_PACKET {
            u16::from_be(protocol as u16) as u32
        } else {
            protocol
        },
        _pad: 0,
    };
    if RAW_SOCKET_PENDING.insert(&tid, &socket, 0).is_err() {
        record_map_full(NETWORK_FAMILY);
    }
    Ok(0)
}

#[tracepoint]
pub fn handle_raw_socket_exit(ctx: TracePointContext) -> u32 {
    unsafe { raw_socket_exit(&ctx) }.unwrap_or(1)
}

#[inline(always)]
unsafe fn raw_socket_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    let Some(pending) = RAW_SOCKET_PENDING.get(&tid) else {
        return Ok(0);
    };
    let socket = *pending;
    let _ = RAW_SOCKET_PENDING.remove(&tid);
    let ret = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        NETWORK_TRACEPOINT_OFFSETS.socket_ret
    )))? as i32;
    if ret < 0 {
        return Ok(0);
    }
    let pid = (pid_tgid >> 32) as u32;
    submit_network(NetworkEvent {
        event_time_ns: 0,
        source_seq: 0,
        pid,
        uid: crate::task_identity::effective_uid().unwrap_or(u32::MAX),
        socket_protocol: socket.protocol,
        ret,
        dport: 0,
        sport: 0,
        af: socket.family,
        protocol: 0,
        tuple_flags: NETWORK_RAW_SOCKET,
        daddr: [0; 16],
        saddr: [0; 16],
        process_start_time: current_process_start_time(pid),
    });
    Ok(0)
}
