//! Network connection eBPF programs.
//!
//! A `connect(2)` is captured across `syscalls/sys_enter_connect` and
//! `syscalls/sys_exit_connect`, because neither point alone can describe the
//! event. The destination sockaddr lives in user memory that is only
//! guaranteed readable while the syscall is on its way in, so entry is where
//! it has to be read; entry also runs in full task context, so
//! `bpf_get_current_pid_tgid()` is valid. Whether a connection was made is
//! only known at exit — hooking entry alone reports `ECONNREFUSED`,
//! `EHOSTUNREACH`, and `ETIMEDOUT` as connections.
//!
//! `handle_connect` therefore stashes the candidate in a per-thread map and
//! `handle_connect_exit` emits it only when the return value says a connection
//! was established or is under way. Everything else is dropped in the kernel,
//! so a failed attempt never reaches the ring buffer, let alone a rule.
//!
//! `connect(2)` itself never says which transport it speaks — that was decided
//! when the socket was created. So `socket(2)` is watched as well and the type
//! it returns is indexed by `(pid, fd)` for the connect hook to read back. The
//! type argument is only known at syscall entry and the descriptor only at
//! syscall exit, so the two are joined through a per-thread slot.
//!
//! A descriptor the sensor never watched being created reports
//! [`SOCK_TYPE_UNKNOWN`], and userspace leaves `Protocol` absent rather than
//! guessing. That covers sockets opened before the agent started, inherited
//! across `fork` (the key is per-process), or received over `SCM_RIGHTS`.
//!
//! Descriptor numbers are recycled, so an index entry is dropped as soon as its
//! descriptor can name a different socket: on `close`, and on the `dup2`/`dup3`
//! target that is closed implicitly. Those tracepoints already carry a program
//! for the directory index, which calls [`forget_socket_type`] rather than pay
//! a second tracepoint dispatch on paths as hot as `close`.
//!
//! sys_enter_connect tracepoint format (x86_64, 64-bit ABI):
//!   offset  0: common_type         (u16)
//!   offset  2: common_flags        (u8)
//!   offset  3: common_preempt_count(u8)
//!   offset  4: common_pid          (i32)
//!   offset  8: __syscall_nr        (i32)
//!   offset 12: _padding            (4 bytes)
//!   offset 16: fd                  (i64)
//!   offset 24: uservaddr           (u64 — pointer to user-space sockaddr)
//!   offset 32: addrlen             (i32)
//!
//! sys_exit_connect tracepoint format (same header):
//!   offset 16: ret                 (i64)
//!
//! sys_enter_socket tracepoint format (same header):
//!   offset 16: family              (i64)
//!   offset 24: type                (i64 — socket type OR'd with SOCK_* flags)
//!   offset 32: protocol            (i64)
//!
//! sys_exit_socket tracepoint format (same header):
//!   offset 16: ret                 (i64 — the new descriptor, or -errno)

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};

use crate::events::{connect_result_is_connection, NetworkEvent, SOCK_TYPE_UNKNOWN};

/// AF_INET (IPv4).
const AF_INET: u16 = 2;
/// AF_INET6 (IPv6).
const AF_INET6: u16 = 10;

/// Bits of the `socket(2)` type argument that name the type. The rest carry
/// `SOCK_NONBLOCK` and `SOCK_CLOEXEC`, which say nothing about the transport.
const SOCK_TYPE_MASK: i64 = 0xf;

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

/// Socket type of the `socket(2)` call a thread is currently inside, keyed by
/// TID. A thread is inside at most one syscall at a time, so one slot per
/// thread is enough to carry the type from entry to exit.
#[map]
static SOCKET_PENDING: HashMap<u32, u8> = HashMap::with_max_entries(16_384, 0);

/// Socket type of every IP socket the sensor watched being created, keyed by
/// `(pid, fd)`.
///
/// LRU rather than plain hash: entries are dropped when their descriptor is
/// closed, but a process killed with sockets open leaves its entries behind,
/// and eviction bounds that. An evicted entry costs a `Protocol` value, never
/// a wrong one.
#[map]
static SOCKET_TYPES: LruHashMap<u64, u8> = LruHashMap::with_max_entries(16_384, 0);

/// Connect candidate a thread is currently inside, keyed by TID.
///
/// A thread is inside exactly one `connect(2)` at a time, so one slot per
/// thread is enough to carry the event from entry to exit. At 56 bytes per
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

/// Tracepoint handler for `syscalls/sys_enter_socket`, where the socket type
/// is still visible.
#[tracepoint]
pub fn handle_socket(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_socket(&ctx) }.unwrap_or(1)
}

/// Tracepoint handler for `syscalls/sys_exit_socket`, where the descriptor the
/// pending type belongs to is finally known.
#[tracepoint]
pub fn handle_socket_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_handle_socket_exit(&ctx) }.unwrap_or(1)
}

#[inline(always)]
fn socket_key(pid: u32, fd: i32) -> u64 {
    ((pid as u64) << 32) | (fd as u32 as u64)
}

/// Drop the indexed socket type for `(pid, fd)`.
///
/// Called from the descriptor-lifetime hooks in [`crate::file`] — see this
/// module's documentation for why they are shared.
///
/// # Safety
///
/// Must be called from a BPF program context.
#[inline(always)]
pub unsafe fn forget_socket_type(pid: u32, fd: i32) {
    if fd < 0 {
        return;
    }
    let _ = SOCKET_TYPES.remove(&socket_key(pid, fd));
}

#[inline(always)]
unsafe fn try_handle_socket(ctx: &TracePointContext) -> Result<u32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;

    // Only IP sockets can reach the connect hook's address-family filter;
    // indexing AF_UNIX and AF_NETLINK would evict entries that can be used.
    let family = ctx.read_at::<i64>(16)?;
    if family != AF_INET as i64 && family != AF_INET6 as i64 {
        // Anything still pending belongs to a thread that was killed inside an
        // earlier `socket()`; drop it so this call's exit cannot claim it.
        let _ = SOCKET_PENDING.remove(&tid);
        return Ok(0);
    }

    let sock_type = (ctx.read_at::<i64>(24)? & SOCK_TYPE_MASK) as u8;
    let _ = SOCKET_PENDING.insert(&tid, &sock_type, 0);
    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_socket_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(sock_type) = SOCKET_PENDING.get(&tid).copied() else {
        return Ok(0);
    };
    let _ = SOCKET_PENDING.remove(&tid);

    // A failed socket(2) returns -errno and owns no descriptor.
    let ret = ctx.read_at::<i64>(16)?;
    if ret < 0 {
        return Ok(0);
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = SOCKET_TYPES.insert(&socket_key(pid, ret as i32), &sock_type, 0);
    Ok(0)
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

    let uid = bpf_get_current_uid_gid() as u32;
    let fd = ctx.read_at::<i64>(16)? as i32;

    // Read pointer to user-space sockaddr structure.
    let uservaddr: u64 = ctx.read_at::<u64>(24)?;
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

    // Skip loopback-only connects to reduce noise (127.0.0.0/8).
    if family == AF_INET && daddr[0] == 127 {
        return Ok(0);
    }

    let sock_type = match SOCKET_TYPES.get(&socket_key(pid, fd)) {
        Some(value) => *value,
        None => SOCK_TYPE_UNKNOWN,
    };

    let event = NetworkEvent {
        pid,
        uid,
        fd,
        // Filled in by the exit handler, which is the only place the outcome
        // is known.
        ret: 0,
        dport,
        // Source address and port are still unassigned here and are not read
        // back at exit either; userspace fills them from the socket.
        sport: 0,
        af: family,
        sock_type,
        _pad1: 0,
        daddr,
        saddr: [0u8; 16],
    };
    let _ = NETWORK_PENDING.insert(&tid, &event, 0);

    Ok(0)
}

#[inline(always)]
unsafe fn try_handle_connect_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret = ctx.read_at::<i64>(16)? as i32;
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

    if let Some(mut entry) = NETWORK_RING.reserve::<NetworkEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}
