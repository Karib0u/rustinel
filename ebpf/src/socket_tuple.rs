//! Read the connection tuple using offsets resolved from the running kernel.

use crate::{
    events::{connect_result_is_connection, event_metadata, NetworkEvent},
    network::NETWORK_RING,
    process::current_process_start_time,
    socket_tuple_abi::{loopback, SocketOffsets, INBOUND, TUPLE_MEASURED},
    telemetry::{record_ring_full, record_submitted, NETWORK_FAMILY},
};
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{fexit, map},
    maps::Array,
    programs::FExitContext,
};

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
    let mut saddr = [0; 16];
    let mut daddr = [0; 16];
    match af {
        2 => {
            saddr[..4].copy_from_slice(&read::<[u8; 4]>(sk, o.saddr)?);
            daddr[..4].copy_from_slice(&read::<[u8; 4]>(sk, o.daddr)?);
        }
        10 => {
            saddr = read(sk, o.saddr6)?;
            daddr = read(sk, o.daddr6)?;
        }
        _ => return Ok(0),
    }
    if loopback(af, &daddr) {
        return Ok(0);
    }
    let protocol = if o.protocol_width == 1 {
        read::<u8>(sk, o.protocol)?
    } else {
        let value = read::<u16>(sk, o.protocol)?;
        if value > 255 {
            return Ok(0);
        }
        value as u8
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let mut event = NetworkEvent {
        event_time_ns: 0,
        source_seq: 0,
        pid,
        uid: crate::task_identity::effective_uid().unwrap_or(u32::MAX),
        fd: -1,
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
