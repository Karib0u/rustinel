//! Read the connection tuple using offsets resolved from the running kernel.

use crate::{
    events::{connect_result_is_connection, NetworkEvent},
    network::submit_network,
    process::current_process_start_time,
    socket_tuple_abi::{
        loopback, udp_budget_update, udp_budget_window, udp_dedup_window, SocketOffsets,
        UdpOffsets, AF_INET, AF_INET6, INBOUND, NETWORK_LISTEN, NETWORK_UDP_SEND, TUPLE_MEASURED,
    },
    telemetry::{
        record_deduplicated, record_map_full, record_rate_limited, record_read_error,
        NETWORK_FAMILY,
    },
};
use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, LruHashMap},
    programs::{FEntryContext, FExitContext},
};

const IPPROTO_UDP: u8 = 17;
const TCP_ESTABLISHED: u8 = 1;
const EEXIST: i32 = -17;

#[map]
pub static SOCKET_OFFSETS: Array<SocketOffsets> = Array::with_max_entries(1, 0);

// Only the BTF-selected accept variant is loaded. Each context access must
// have a constant index so the verifier can check it against the prototype.
#[fexit]
pub fn handle_accept2(ctx: FExitContext) -> u32 {
    unsafe { emit(ctx.arg::<u64>(2), 0, true) }.unwrap_or(1)
}

#[fexit]
pub fn handle_accept4(ctx: FExitContext) -> u32 {
    unsafe { emit(ctx.arg::<u64>(4), 0, true) }.unwrap_or(1)
}

#[fexit]
pub fn handle_stream_connect(ctx: FExitContext) -> u32 {
    unsafe { connect(&ctx) }.unwrap_or(1)
}

#[fexit]
pub fn handle_dgram_connect(ctx: FExitContext) -> u32 {
    unsafe { connect(&ctx) }.unwrap_or(1)
}

#[inline(always)]
unsafe fn read<T: Copy>(ptr: u64, offset: u32) -> Result<T, i64> {
    Ok(bpf_probe_read_kernel(
        (ptr + (offset & 65535) as u64) as *const T,
    )?)
}

#[inline(always)]
unsafe fn connect(ctx: &FExitContext) -> Result<u32, i64> {
    let ret = ctx.arg::<i32>(4);
    if !connect_result_is_connection(ret) {
        return Ok(0);
    }
    let Some(offsets) = SOCKET_OFFSETS.get(0) else {
        return Ok(0);
    };
    let sk = read::<u64>(ctx.arg::<u64>(0), offsets.socket_sk)?;
    emit(sk, ret, false)
}

#[inline(always)]
unsafe fn emit(sk: u64, ret: i32, inbound: bool) -> Result<u32, i64> {
    // accept returns NULL on failure. Reject ERR_PTR values as well.
    if sk == 0 || sk >= u64::MAX - 4095 {
        return Ok(0);
    }
    let Some(o) = SOCKET_OFFSETS.get(0) else {
        return Ok(0);
    };
    let af = read::<u16>(sk, o.family)?;
    if !matches!(af, AF_INET | AF_INET6) {
        return Ok(0);
    }
    let saddr = socket_address(sk, af, o.saddr, o.saddr6)?;
    let daddr = socket_address(sk, af, o.daddr, o.daddr6)?;
    if loopback(af, &daddr) {
        return Ok(0);
    }
    let Some(protocol) = socket_protocol(sk, o)? else {
        return Ok(0);
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let mut event = NetworkEvent {
        event_time_ns: 0,
        source_seq: 0,
        pid,
        uid: crate::task_identity::effective_uid().unwrap_or(u32::MAX),
        socket_protocol: 0,
        ret,
        af,
        protocol,
        tuple_flags: TUPLE_MEASURED | if inbound { INBOUND } else { 0 },
        sport: read(sk, o.sport)?,
        dport: u16::from_be(read(sk, o.dport)?),
        saddr,
        daddr,
        process_start_time: current_process_start_time(pid),
    };
    if inbound {
        core::mem::swap(&mut event.saddr, &mut event.daddr);
        core::mem::swap(&mut event.sport, &mut event.dport);
    }
    submit_network(event);
    Ok(0)
}

#[inline(always)]
unsafe fn socket_address(sk: u64, af: u16, v4: u32, v6: u32) -> Result<[u8; 16], i64> {
    if af == AF_INET {
        let mut addr = [0; 16];
        addr[..4].copy_from_slice(&read::<[u8; 4]>(sk, v4)?);
        Ok(addr)
    } else {
        read(sk, v6)
    }
}

#[inline(always)]
unsafe fn socket_protocol(sk: u64, offsets: &SocketOffsets) -> Result<Option<u8>, i64> {
    if offsets.protocol_width == 1 {
        Ok(Some(read(sk, offsets.protocol)?))
    } else {
        let value = read::<u16>(sk, offsets.protocol)?;
        Ok((value <= u8::MAX as u16).then_some(value as u8))
    }
}

#[map]
static LISTENING_SOCKETS: HashMap<u64, u8> = HashMap::with_max_entries(16_384, 0);

#[fentry]
pub fn handle_listen_cleanup(ctx: FEntryContext) -> u32 {
    // Remove the key before the kernel can recycle the socket address.
    let _ = LISTENING_SOCKETS.remove(&ctx.arg::<u64>(0));
    0
}

#[fexit]
pub fn handle_listen(ctx: FExitContext) -> u32 {
    if ctx.arg::<i32>(2) == 0 && unsafe { listen(ctx.arg::<u64>(0)) }.is_err() {
        record_read_error(NETWORK_FAMILY);
    }
    0
}

#[inline(always)]
unsafe fn listen(socket: u64) -> Result<(), i64> {
    let Some(o) = SOCKET_OFFSETS.get(0) else {
        return Ok(());
    };
    let sk = read::<u64>(socket, o.socket_sk)?;
    if LISTENING_SOCKETS.get_ptr(&sk).is_some() {
        record_deduplicated(NETWORK_FAMILY);
        return Ok(());
    }
    let af = read::<u16>(sk, o.family)?;
    if !matches!(af, AF_INET | AF_INET6) {
        return Ok(());
    }
    let Some(protocol) = socket_protocol(sk, o)? else {
        return Ok(());
    };
    let sport = read(sk, o.sport)?;
    let saddr = socket_address(sk, af, o.saddr, o.saddr6)?;
    match LISTENING_SOCKETS.insert(&sk, &1, BPF_NOEXIST as u64) {
        Ok(()) => {}
        Err(EEXIST) => {
            record_deduplicated(NETWORK_FAMILY);
            return Ok(());
        }
        Err(_) => {
            record_map_full(NETWORK_FAMILY);
            return Ok(());
        }
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !submit_network(NetworkEvent {
        event_time_ns: 0,
        source_seq: 0,
        pid,
        uid: crate::task_identity::effective_uid().unwrap_or(u32::MAX),
        socket_protocol: 0,
        ret: 0,
        dport: 0,
        sport,
        af,
        protocol,
        tuple_flags: TUPLE_MEASURED | NETWORK_LISTEN,
        daddr: [0; 16],
        saddr,
        process_start_time: current_process_start_time(pid),
    }) {
        let _ = LISTENING_SOCKETS.remove(&sk);
    }
    Ok(())
}

#[repr(C)]
struct UdpPeer {
    window: u64,
    process_start_time: u64,
    addr: [u8; 16],
    pid: u32,
    port: u16,
    family: u16,
}

#[map]
pub static UDP_OFFSETS: Array<UdpOffsets> = Array::with_max_entries(1, 0);
#[map]
static UDP_PEERS: LruHashMap<UdpPeer, u8> = LruHashMap::with_max_entries(8192, 0);
#[map]
static UDP_BUDGET: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static UDP_BUDGET_LOCK: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[fexit]
pub fn handle_udp4_send(ctx: FExitContext) -> u32 {
    handle_udp_send(&ctx, AF_INET)
}

#[fexit]
pub fn handle_udp6_send(ctx: FExitContext) -> u32 {
    handle_udp_send(&ctx, AF_INET6)
}

#[inline(always)]
fn handle_udp_send(ctx: &FExitContext, family: u16) -> u32 {
    let ret = ctx.arg::<i32>(3);
    if ret >= 0 && unsafe { udp_send(ctx.arg::<u64>(0), ctx.arg::<u64>(1), family, ret) }.is_err() {
        record_read_error(NETWORK_FAMILY);
    }
    0
}

#[inline(always)]
unsafe fn udp_send(sk: u64, msg: u64, family: u16, ret: i32) -> Result<(), i64> {
    let Some(u) = UDP_OFFSETS.get(0) else {
        return Ok(());
    };
    let name = read::<u64>(msg, u.msg_name)?;
    if name == 0 || read::<u8>(sk, u.state)? == TCP_ESTABLISHED {
        return Ok(());
    }
    let Some(o) = SOCKET_OFFSETS.get(0) else {
        return Ok(());
    };
    if socket_protocol(sk, o)? != Some(IPPROTO_UDP) {
        return Ok(());
    }
    if read::<u16>(name, 0)? != family {
        return Ok(());
    }
    let port = u16::from_be(read::<u16>(name, 2)?);
    let addr = socket_address(name, family, 4, 8)?;
    if port == 0 || addr == [0; 16] {
        return Ok(());
    }
    // The IPv6 implementation delegates IPv4 and mapped IPv6 destinations
    // to udp_sendmsg, whose hook observes the actual IPv4 peer.
    if family == AF_INET6 && addr[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255] {
        return Ok(());
    }
    let now = bpf_ktime_get_ns();
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let start = crate::task_identity::start_boottime();
    let key = UdpPeer {
        window: udp_dedup_window(now),
        process_start_time: start.unwrap_or_else(|| current_process_start_time(pid)),
        addr,
        pid,
        port,
        family,
    };
    if !claim_udp_peer(&key, now) {
        return Ok(());
    }
    submit_network(NetworkEvent {
        event_time_ns: 0,
        source_seq: 0,
        pid,
        uid: crate::task_identity::effective_uid().unwrap_or(u32::MAX),
        socket_protocol: 0,
        ret,
        dport: port,
        sport: 0,
        af: family,
        protocol: IPPROTO_UDP,
        tuple_flags: NETWORK_UDP_SEND,
        daddr: addr,
        saddr: [0; 16],
        process_start_time: current_process_start_time(pid),
    });
    Ok(())
}

#[inline(always)]
unsafe fn claim_udp_peer(key: &UdpPeer, now: u64) -> bool {
    if UDP_PEERS.get_ptr(key).is_some() {
        record_deduplicated(NETWORK_FAMILY);
        return false;
    }
    if !claim_udp_budget(udp_budget_window(now)) {
        return false;
    }
    match UDP_PEERS.insert(key, &1, BPF_NOEXIST as u64) {
        Ok(()) => true,
        Err(EEXIST) => {
            record_deduplicated(NETWORK_FAMILY);
            false
        }
        Err(_) => {
            record_map_full(NETWORK_FAMILY);
            false
        }
    }
}

#[inline(always)]
unsafe fn claim_udp_budget(window: u64) -> bool {
    // Inserting this single key serializes the counter across CPUs on kernels
    // that cannot use compare-and-swap in tracing programs. Contenders drop
    // their candidate immediately so a send never waits on another CPU.
    if UDP_BUDGET_LOCK.insert(&0, &1, BPF_NOEXIST as u64).is_err() {
        record_rate_limited(NETWORK_FAMILY);
        return false;
    }
    let granted = UDP_BUDGET.get_ptr_mut(0).is_some_and(|budget| {
        let Some(next) = udp_budget_update(*budget, window) else {
            return false;
        };
        *budget = next;
        true
    });
    let _ = UDP_BUDGET_LOCK.remove(&0);
    if !granted {
        record_rate_limited(NETWORK_FAMILY);
    }
    granted
}
