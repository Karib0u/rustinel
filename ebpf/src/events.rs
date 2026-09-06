//! Shared event types emitted by eBPF programs into ring buffers.
//!
//! These types are `#[repr(C)]` and **must be mirrored exactly** in
//! `src/sensor/linux/events.rs` so the userspace loader can safely
//! transmute ring-buffer bytes into structured event records.
//!
//! Layout rules:
//! - No padding between fields (sizes chosen to be naturally aligned).
//! - Fixed-size arrays for strings (null-terminated, rest zeroed).
//! - All integer fields use explicit sizes (`u32`, `u16`, etc.).

/// Maximum bytes of argv captured in the kernel for one `execve`.
///
/// A power of two so the verifier can bound the write offset with a mask.
/// Anything past this is dropped and the event is flagged truncated; the
/// userspace loader then falls back to `/proc/<pid>/cmdline`.
pub const ARGV_CAPACITY: usize = 512;

/// Process lifecycle event.
///
/// - kind 1 = exec (`sched_process_exec`)
/// - kind 2 = exit (`sched_process_exit`)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    /// Event kind: 1 = exec, 2 = exit.
    pub kind: u32,
    /// Thread group ID — the POSIX "process ID".
    pub pid: u32,
    /// Effective UID of the new process.
    pub uid: u32,
    pub _pad: u32,
    /// Null-terminated process name (`comm`, up to 15 chars).
    pub comm: [u8; 16],
    /// Null-terminated executable path (up to 127 chars).
    ///
    /// Empty for exit events.
    pub image: [u8; 128],
    /// Number of valid bytes in `args`. Zero when no argv was captured.
    pub args_len: u16,
    /// Number of argv entries captured in `args`.
    pub args_count: u16,
    /// 1 when argv did not fit the capture limits, 0 when complete.
    pub args_truncated: u8,
    pub _pad1: [u8; 3],
    /// Argv captured at `execve` entry, NUL-separated (no trailing NUL
    /// guaranteed). Only the first `args_len` bytes are meaningful.
    ///
    /// Empty for exit events.
    pub args: [u8; ARGV_CAPACITY],
}

/// `connect(2)` succeeded — the connection is established.
pub const CONNECT_RESULT_OK: i32 = 0;

/// `-EINPROGRESS`: a non-blocking `connect(2)` has been started and the
/// handshake is under way. Every asynchronous client returns this, so it must
/// count as a connection.
pub const CONNECT_RESULT_EINPROGRESS: i32 = -115;

/// `-EINTR`: a signal interrupted the wait. The kernel completes the connect
/// in the background, so this is an attempt that was made, not one that
/// failed.
pub const CONNECT_RESULT_EINTR: i32 = -4;

/// Whether a `connect(2)` return value describes a connection that was
/// established or is under way.
///
/// Everything else — `ECONNREFUSED`, `EHOSTUNREACH`, `ETIMEDOUT`,
/// `ENETUNREACH`, and the rest — is a failed attempt and is not a connection.
/// `EALREADY` and `EISCONN` are excluded for a different reason: they report a
/// connect that an earlier call already emitted.
///
/// **Mirrored in `src/sensor/linux/events.rs`** — keep both copies in step.
#[inline(always)]
pub fn connect_result_is_connection(result: i32) -> bool {
    matches!(
        result,
        CONNECT_RESULT_OK | CONNECT_RESULT_EINPROGRESS | CONNECT_RESULT_EINTR
    )
}

/// The sensor did not watch this socket being created, so its type is not
/// known. Userspace reports no `Protocol` rather than guessing one.
pub const SOCK_TYPE_UNKNOWN: u8 = 0;

/// `SOCK_STREAM` — TCP for AF_INET and AF_INET6.
pub const SOCK_STREAM: u8 = 1;

/// `SOCK_DGRAM` — UDP for AF_INET and AF_INET6.
pub const SOCK_DGRAM: u8 = 2;

/// Outbound connection event. Queued by `handle_connect` on
/// `syscalls/sys_enter_connect` and emitted by `handle_connect_exit` on
/// `syscalls/sys_exit_connect`, which drops attempts that never connected.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    /// Thread group ID of the connecting process.
    pub pid: u32,
    /// Effective UID.
    pub uid: u32,
    /// Socket file descriptor supplied to `connect(2)`.
    pub fd: i32,
    /// `connect(2)` return value: 0, or the negative errno of a connect that
    /// is still under way. Failed attempts are never emitted, so this is
    /// always one of the values [`connect_result_is_connection`] accepts.
    pub ret: i32,
    /// Destination port in **host** byte order.
    pub dport: u16,
    /// Source port (best-effort; may be 0 before bind completes).
    pub sport: u16,
    /// Address family: 2 = AF_INET, 10 = AF_INET6.
    pub af: u16,
    /// Socket type the descriptor was created with, masked to
    /// `SOCK_TYPE_MASK`: [`SOCK_STREAM`], [`SOCK_DGRAM`], another `SOCK_*`
    /// value, or [`SOCK_TYPE_UNKNOWN`] when the creation was not observed.
    pub sock_type: u8,
    pub _pad1: u8,
    /// Destination address. For AF_INET: first 4 bytes hold the IPv4 address
    /// (network byte order); remaining bytes are zero. For AF_INET6: all 16
    /// bytes hold the address.
    pub daddr: [u8; 16],
    /// Source address (best-effort; may be all-zero at connect time).
    pub saddr: [u8; 16],
}

/// Bytes captured for one file path, including the NUL terminator.
///
/// `PATH_MAX` is 4096, but a `FileEvent` holds two paths and one lives in a
/// per-thread pending map slot for the duration of every `openat`, `unlinkat`,
/// and `renameat*` call on the machine, so capturing `PATH_MAX` would cost
/// 8 KiB per in-flight syscall. 512 covers the overwhelming majority of real
/// paths; anything longer is flagged through [`FILE_FLAG_PATH_TRUNCATED`]
/// rather than passed off as complete.
pub const FILE_PATH_LEN: usize = 512;

/// `path` did not fit in [`FILE_PATH_LEN`] and was cut short.
pub const FILE_FLAG_PATH_TRUNCATED: u32 = 1 << 0;

/// `aux_path` did not fit in [`FILE_PATH_LEN`] and was cut short.
pub const FILE_FLAG_AUX_PATH_TRUNCATED: u32 = 1 << 1;

/// `dfd` value meaning "resolve against the process working directory".
pub const AT_FDCWD: i32 = -100;

/// File create, delete, rename, or change event.
///
/// - kind 1 = create (`openat` with `O_CREAT`, emitted on successful return)
/// - kind 2 = delete (`unlinkat`, emitted on successful return)
/// - kind 3 = rename (`renameat*`, emitted on successful return)
/// - kind 4 = change (`openat` with write intent, emitted on successful return)
///
/// `path` and `aux_path` are the raw pathname arguments, which the `*at`
/// syscalls allow to be relative. Each carries the directory descriptor it is
/// relative to (`dfd` for `path`, `aux_dfd` for `aux_path`) so userspace can
/// rebuild the absolute path; a path that is already absolute is paired with
/// [`AT_FDCWD`] and needs no descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    /// Event kind: 1 = create, 2 = delete, 3 = rename, 4 = change.
    pub kind: u32,
    /// Thread group ID.
    pub pid: u32,
    /// Effective UID.
    pub uid: u32,
    /// Bitmask of `FILE_FLAG_*` — currently path truncation.
    pub flags: u32,
    /// Directory descriptor `path` is relative to, or [`AT_FDCWD`].
    pub dfd: i32,
    /// Directory descriptor `aux_path` is relative to, or [`AT_FDCWD`].
    pub aux_dfd: i32,
    /// Kernel token for the indexed directory currently held in `dfd`.
    /// Zero means userspace must use the `/proc` fallback.
    pub dfd_token: u64,
    /// Kernel token for the indexed directory currently held in `aux_dfd`.
    /// Zero means userspace must use the `/proc` fallback.
    pub aux_dfd_token: u64,
    /// Null-terminated file path (target/new name for renames).
    pub path: [u8; FILE_PATH_LEN],
    /// Null-terminated auxiliary path (source/old name for renames).
    pub aux_path: [u8; FILE_PATH_LEN],
    /// Null-terminated process name (`comm`, up to 15 chars).
    pub comm: [u8; 16],
}

/// Compact maintenance event carried on the file ring.
///
/// Kind 6 resets every userspace directory-index entry owned by `pid`. It is
/// emitted on exec, thread exit, and `close_range`, in the same ring as file
/// events so maintenance cannot be reordered across ring drains.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileIndexEvent {
    pub kind: u32,
    pub pid: u32,
    pub fd: i32,
    pub _pad: u32,
}

/// DNS query/response event.
///
/// - kind 1 = query (`sendto`)
/// - kind 2 = response (`recvfrom`)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    /// Event kind: 1 = query, 2 = response.
    pub kind: u32,
    /// Thread group ID.
    pub pid: u32,
    /// Effective UID.
    pub uid: u32,
    /// Socket file descriptor.
    pub fd: i32,
    /// Number of valid bytes in `payload`.
    pub payload_len: u16,
    pub _pad0: u16,
    /// Null-terminated DNS query name (up to 95 chars).
    pub query_name: [u8; 96],
    /// Null-terminated DNS answer/result summary (up to 95 chars).
    pub query_results: [u8; 96],
    /// Null-terminated query type string (up to 15 chars).
    pub record_type: [u8; 16],
    /// Raw DNS payload copied from userspace for userspace parsing.
    pub payload: [u8; 256],
}
