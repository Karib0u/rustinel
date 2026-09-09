//! Connection syscall fallback. The fexit tier reads the bound kernel socket.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

use crate::events::{connect_result_is_connection, event_metadata, NetworkEvent};
use crate::process::current_process_start_time;
use crate::telemetry::{record_map_full, record_ring_full, record_submitted, NETWORK_FAMILY};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkTracepointOffsets {
    pub connect_fd: u32,
    pub connect_addr: u32,
    pub connect_ret: u32,
}

#[no_mangle]
pub static NETWORK_TRACEPOINT_OFFSETS: NetworkTracepointOffsets = NetworkTracepointOffsets {
    connect_fd: 0,
    connect_addr: 0,
    connect_ret: 0,
};

#[inline(always)]
unsafe fn tracepoint_offset(value: *const u32) -> usize {
    core::ptr::read_volatile(value) as usize
}

/// AF_INET (IPv4).
const AF_INET: u16 = 2;
/// AF_INET6 (IPv6).
const AF_INET6: u16 = 10;

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
    let fd = ctx.read_at::<i64>(tracepoint_offset(core::ptr::addr_of!(
        NETWORK_TRACEPOINT_OFFSETS.connect_fd
    )))? as i32;

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
        fd,
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

    let Some(mut entry) = NETWORK_RING.reserve::<NetworkEvent>(0) else {
        record_ring_full(NETWORK_FAMILY);
        return Ok(0);
    };
    (event.event_time_ns, event.source_seq) = event_metadata();
    entry.write(event);
    entry.submit(0);
    record_submitted(NETWORK_FAMILY);

    Ok(0)
}
