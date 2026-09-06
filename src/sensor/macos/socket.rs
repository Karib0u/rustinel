//! Best-effort socket-to-process attribution for captured flows.
//!
//! The bpf sensor observes packets on the wire without an owning process, so
//! this module maps a connection back to a PID by scanning every process's
//! socket descriptors (the macOS equivalent of walking `/proc/net` on Linux).
//!
//! A single scan is `O(processes x descriptors)`, so it is never run per
//! connection. One scan builds a [`SocketTable`] indexing *every* live TCP
//! socket by its port pair, and [`SocketOwnerCache`] reuses that table for a
//! bounded interval. A burst of queued connections therefore shares one
//! traversal, and a lookup miss answers from the current table instead of
//! rescanning.
//!
//! Attribution stays inherently best-effort and racy: the socket may have
//! closed before the scan, and a connection seen just after a scan is answered
//! from a table that predates it. The NetworkExtension framework is the future
//! high-fidelity alternative that carries the owning PID with each flow.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libc::c_int;
use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::proc_pid::{listpidinfo, pidpath};
use libproc::processes::{pids_by_type, ProcFilter};

/// Maximum file descriptors inspected per process. Processes with more open
/// descriptors than this may not be matched (rare in practice).
const MAX_FDS: usize = 1024;

/// How long a socket table is reused before a lookup may rebuild it. Bounds
/// the scan rate to one traversal per interval no matter how many connections
/// are queued, which is what keeps a burst (and its misses) from turning into
/// a rescan per connection.
pub(super) const INVENTORY_TTL: Duration = Duration::from_millis(250);

/// Owner of a captured connection.
pub(super) struct SocketOwner {
    pub pid: u32,
    pub image: Option<String>,
}

/// Every live TCP socket on the system, keyed by `(local_port, remote_port)`,
/// as observed by one system-wide scan.
///
/// The local (ephemeral) port plus remote port is effectively unique to a
/// single active connection, which is what makes the pair a usable key.
pub(super) struct SocketTable {
    owners: HashMap<(u16, u16), i32>,
}

impl SocketTable {
    /// The PID owning the socket with this port pair, if the scan saw one.
    fn owner_pid(&self, local_port: u16, remote_port: u16) -> Option<i32> {
        self.owners.get(&(local_port, remote_port)).copied()
    }
}

/// A [`SocketTable`] reused across lookups for [`INVENTORY_TTL`].
///
/// A lookup rebuilds the table only when the current one has expired, so the
/// scan rate is bounded by the TTL rather than by connection volume. Misses
/// are answered from the table in hand: a connection the scan did not see
/// stays unattributed until the next rebuild is due.
pub(super) struct SocketOwnerCache {
    table: Option<(Instant, SocketTable)>,
    ttl: Duration,
}

impl SocketOwnerCache {
    pub fn new(ttl: Duration) -> Self {
        Self { table: None, ttl }
    }

    /// Find the process owning a TCP connection identified by its local and
    /// remote ports. Returns `None` when no scanned socket matches or when the
    /// scan itself is denied.
    pub fn find_tcp_socket_owner(
        &mut self,
        local_port: u16,
        remote_port: u16,
    ) -> Option<SocketOwner> {
        let pid = self.owner_pid(local_port, remote_port, Instant::now(), scan_tcp_sockets)?;
        Some(SocketOwner {
            pid: pid as u32,
            image: pidpath(pid).ok(),
        })
    }

    /// Table lookup behind [`Self::find_tcp_socket_owner`], with the clock and
    /// the scan injected so tests can count traversals.
    fn owner_pid(
        &mut self,
        local_port: u16,
        remote_port: u16,
        now: Instant,
        scan: impl FnOnce() -> Option<SocketTable>,
    ) -> Option<i32> {
        let expired = match &self.table {
            Some((built_at, _)) => now.duration_since(*built_at) >= self.ttl,
            None => true,
        };
        if expired {
            if let Some(table) = scan() {
                self.table = Some((now, table));
            }
        }
        let (_, table) = self.table.as_ref()?;
        table.owner_pid(local_port, remote_port)
    }
}

/// Walk every process's socket descriptors once, indexing the TCP sockets by
/// port pair. Returns `None` only when the process list itself is unavailable;
/// processes and descriptors that cannot be inspected are skipped.
fn scan_tcp_sockets() -> Option<SocketTable> {
    let pids = pids_by_type(ProcFilter::All).ok()?;
    let mut owners = HashMap::new();
    for pid in pids {
        if pid == 0 {
            continue;
        }
        let pid = pid as i32;
        let Ok(fds) = listpidinfo::<ListFDs>(pid, MAX_FDS) else {
            continue;
        };
        for fd in fds {
            if fd.proc_fdtype != ProcFDType::Socket as u32 {
                continue;
            }
            let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) else {
                continue;
            };
            if let Some(ports) = tcp_ports(&socket) {
                // First writer wins: the earliest process seen owning a port
                // pair is kept, matching the old scan's first-match return.
                owners.entry(ports).or_insert(pid);
            }
        }
    }
    Some(SocketTable { owners })
}

/// The `(local_port, remote_port)` pair of a TCP socket descriptor, or `None`
/// for any other socket kind.
fn tcp_ports(socket: &SocketFDInfo) -> Option<(u16, u16)> {
    let info = &socket.psi;
    if !matches!(SocketInfoKind::from(info.soi_kind), SocketInfoKind::Tcp) {
        return None;
    }
    // SAFETY: soi_kind == Tcp guarantees the TCP arm of the proto union is the
    // active variant, so reading pri_tcp is sound.
    let in_info = unsafe { info.soi_proto.pri_tcp.tcpsi_ini };
    Some((
        port_from_network(in_info.insi_lport),
        port_from_network(in_info.insi_fport),
    ))
}

/// Convert a port stored in network byte order (low 16 bits of a `c_int`) to a
/// host-order `u16`.
fn port_from_network(port: c_int) -> u16 {
    u16::from_be(port as u16)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::net::{TcpListener, TcpStream};

    use super::*;
    use libproc::net_info::{InSockInfo, TcpSockInfo};

    // The proto union has no nameable type to construct via struct literal, so
    // the FFI structs are built by field assignment after Default.
    #[allow(clippy::field_reassign_with_default)]
    fn tcp_socket(local_port: u16, remote_port: u16) -> SocketFDInfo {
        let mut ini = InSockInfo::default();
        ini.insi_lport = i32::from(local_port.to_be());
        ini.insi_fport = i32::from(remote_port.to_be());
        let mut tcp = TcpSockInfo::default();
        tcp.tcpsi_ini = ini;

        let mut socket = SocketFDInfo::default();
        socket.psi.soi_kind = SocketInfoKind::Tcp as c_int;
        socket.psi.soi_proto.pri_tcp = tcp;
        socket
    }

    fn table(entries: &[((u16, u16), i32)]) -> SocketTable {
        SocketTable {
            owners: entries.iter().copied().collect(),
        }
    }

    #[test]
    fn matches_tcp_socket_by_ports() {
        let socket = tcp_socket(51324, 443);
        assert_eq!(tcp_ports(&socket), Some((51324, 443)));
    }

    #[test]
    fn ignores_non_tcp_sockets() {
        let mut socket = tcp_socket(51324, 443);
        socket.psi.soi_kind = SocketInfoKind::In as c_int;
        assert_eq!(tcp_ports(&socket), None);
    }

    #[test]
    fn connection_burst_shares_one_scan() {
        let scans = Cell::new(0);
        let mut cache = SocketOwnerCache::new(INVENTORY_TTL);
        let now = Instant::now();

        // A burst of distinct connections, all within the TTL: one traversal
        // serves every lookup, hit or miss.
        for local_port in 50_000u16..50_500 {
            let owner = cache.owner_pid(local_port, 443, now, || {
                scans.set(scans.get() + 1);
                Some(table(&[((50_000, 443), 42), ((50_001, 443), 99)]))
            });
            let expected = match local_port {
                50_000 => Some(42),
                50_001 => Some(99),
                _ => None,
            };
            assert_eq!(owner, expected, "port {local_port}");
        }

        assert_eq!(scans.get(), 1);
    }

    #[test]
    fn misses_do_not_rescan_within_the_ttl() {
        let scans = Cell::new(0);
        let mut cache = SocketOwnerCache::new(INVENTORY_TTL);
        let start = Instant::now();
        let scan = || {
            scans.set(scans.get() + 1);
            Some(table(&[]))
        };

        assert_eq!(cache.owner_pid(50_000, 443, start, scan), None);
        let just_before_expiry = start + INVENTORY_TTL - Duration::from_millis(1);
        assert_eq!(cache.owner_pid(50_001, 443, just_before_expiry, scan), None);

        assert_eq!(scans.get(), 1);
    }

    #[test]
    fn rebuilds_after_the_ttl_expires() {
        let scans = Cell::new(0);
        let mut cache = SocketOwnerCache::new(INVENTORY_TTL);
        let start = Instant::now();

        assert_eq!(
            cache.owner_pid(50_000, 443, start, || {
                scans.set(scans.get() + 1);
                Some(table(&[]))
            }),
            None
        );
        // The socket opened after the first scan is found once the table is
        // due for a rebuild.
        assert_eq!(
            cache.owner_pid(50_000, 443, start + INVENTORY_TTL, || {
                scans.set(scans.get() + 1);
                Some(table(&[((50_000, 443), 7)]))
            }),
            Some(7)
        );

        assert_eq!(scans.get(), 2);
    }

    #[test]
    fn keeps_the_previous_table_when_a_scan_fails() {
        let mut cache = SocketOwnerCache::new(INVENTORY_TTL);
        let start = Instant::now();

        assert_eq!(
            cache.owner_pid(50_000, 443, start, || Some(table(&[((50_000, 443), 7)]))),
            Some(7)
        );
        assert_eq!(
            cache.owner_pid(50_000, 443, start + INVENTORY_TTL, || None),
            Some(7)
        );
    }

    /// End-to-end check of the real libproc scan: a live loopback connection
    /// this process owns must be attributed back to this process.
    #[test]
    fn scan_attributes_a_live_loopback_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let server_port = listener.local_addr().expect("listener addr").port();
        let client = TcpStream::connect(("127.0.0.1", server_port)).expect("connect to listener");
        let accepted = listener.accept().expect("accept connection").0;
        let local_port = client.local_addr().expect("client addr").port();

        let mut cache = SocketOwnerCache::new(INVENTORY_TTL);
        let owner = cache
            .find_tcp_socket_owner(local_port, server_port)
            .expect("live connection is attributed");

        assert_eq!(owner.pid, std::process::id());
        drop(accepted);
    }
}
