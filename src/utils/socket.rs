//! Linux socket inspection helpers.
//!
//! The kernel's `connect(2)` tracepoints carry the destination the caller
//! asked for, but not the local address the stack assigned — that is decided
//! inside the syscall, and neither tracepoint can see it. The only place
//! userspace can read it back is `/proc/net/{tcp,tcp6,udp,udp6}`, keyed by the
//! socket inode behind `/proc/<pid>/fd/<fd>`.
//!
//! Those tables are system-wide and unindexed, so resolving one socket by
//! re-reading them costs a scan proportional to every socket on the host. Done
//! once per network event, that cost scales with events multiplied by sockets
//! and lands on the thread draining the ring buffer, where it turns into lost
//! events rather than a slow lookup.
//!
//! [`SocketInventory`] separates the two halves. Scanning is
//! [`SocketInventory::refresh_if_due`], which the caller runs once per batch of
//! events; answering is [`SocketInventory::lookup`], which reads the snapshot
//! and never scans. A drain batch of any size therefore costs at most one pass
//! over the tables.
//!
//! Where in the batch the scan goes is the whole design. Scanning per event
//! resolves each connect against a table read after it, which is why the old
//! code was accurate; scanning *before* a batch resolves it against a table
//! read before the batch's connects happened, which is accurate for nothing.
//! The scan therefore goes after the ring has been drained and before the
//! events are sent, where one read describes every socket the batch asks
//! about.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketMetadata {
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
}

/// The `/proc/net` tables an inventory can read, with the protocol each one
/// names and whether its addresses are 32 hex characters wide. The position in
/// this array is the bit a [`SocketTableSet`] sets for it.
const PROC_NET_TABLES: [(&str, &str, bool); 4] = [
    ("/proc/net/tcp", "tcp", false),
    ("/proc/net/tcp6", "tcp", true),
    ("/proc/net/udp", "udp", false),
    ("/proc/net/udp6", "udp", true),
];

/// AF_INET, as the `connect(2)` probe reports it.
const AF_INET: u16 = 2;
/// AF_INET6, as the `connect(2)` probe reports it.
const AF_INET6: u16 = 10;

/// Which of the four tables a scan has to read.
///
/// A socket lives in exactly one of them, and the kernel event already says
/// which: its address family picks the width and its socket type picks the
/// transport. Reading the one table that can hold the answer instead of all
/// four is the same attribution for a quarter of the cost - and because the
/// scan budget is a share of time, a cheaper scan is also a scan that may
/// repeat sooner.
///
/// An event that names neither falls back to whatever it does name, and to all
/// four if it names nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketTableSet(u8);

impl SocketTableSet {
    /// Every table, for a socket whose family and transport are both unknown.
    pub const EVERY: Self = Self(0b1111);

    /// The tables that can describe a socket of this address family and
    /// transport, as the kernel event reported them.
    pub fn for_socket(address_family: u16, transport: Option<&str>) -> Self {
        let mut mask = 0u8;
        for (index, (_, protocol, ipv6)) in PROC_NET_TABLES.iter().enumerate() {
            let family_matches = match address_family {
                AF_INET => !ipv6,
                AF_INET6 => *ipv6,
                _ => true,
            };
            let transport_matches = transport.is_none_or(|value| value == *protocol);
            if family_matches && transport_matches {
                mask |= 1 << index;
            }
        }
        // A family the probe does not report leaves nothing to narrow by; an
        // empty set would silently resolve nothing at all.
        if mask == 0 {
            return Self::EVERY;
        }
        Self(mask)
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn contains(self, index: usize) -> bool {
        self.0 & (1 << index) != 0
    }
}

/// Sanity floor between two scans of the socket tables.
///
/// The real governor is [`SCAN_DUTY_DIVISOR`], which is proportional to what a
/// scan costs. This is only a guard against a cost measurement that rounds to
/// nothing — a clock with coarse resolution, or four tables so small the read
/// is faster than it can be timed — which would otherwise leave no floor at
/// all.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_millis(1);

/// How much of the drain thread a scan is allowed to claim, as a divisor: one
/// part scanning to `SCAN_DUTY_DIVISOR - 1` parts everything else.
///
/// A fixed floor bounds how *often* the tables are read but not what a read
/// costs, and that cost is the number of sockets on the host. Connection churn
/// is exactly the workload that inflates it: twenty thousand closed connects
/// leave a `TIME_WAIT` backlog that a scan then walks in full, so a floor that
/// was cheap on an idle host becomes the same CPU sink it replaced.
///
/// Timing the last scan and holding the next one off for a multiple of it
/// bounds the share of the drain thread attribution can take at one part in
/// `SCAN_DUTY_DIVISOR`, whatever the table grows to and however many events
/// arrive. That bound is what makes the cost independent of the event rate;
/// everything else is the fidelity it buys.
///
/// A fixed floor was tried first and rejected: it is a worse trade in both
/// directions. Ten milliseconds is far too slow to refresh when the tables are
/// small — a host opening 400 connections a second resolved 8% of them — and
/// far too fast when they are large, where it was measured spending seconds of
/// CPU per burst. The effective floor is the product clamped into
/// [`MIN_REFRESH_INTERVAL`]..=[`MAX_SNAPSHOT_AGE`].
///
/// Four is a measured point on the curve, not a round number. Against a
/// 20 000-connect burst and a paced 400/s workload on the same host, where the
/// unbounded per-event scan this replaces cost 9.3 s of CPU and lost three
/// quarters of the burst to the ring buffer:
///
/// | divisor | burst CPU | 400/s attributed | 400/s CPU |
/// |---------|-----------|------------------|-----------|
/// | 8       | 1.0 s     | 27%              | 150 ms    |
/// | **4**   | **2.2 s** | **45%**          | **230 ms**|
/// | 2       | 3.1 s     | 65%              | 330 ms    |
/// | ∞ (old) | 9.3 s     | ~100%            | 510 ms    |
///
/// The burst is what the ring buffer cannot survive, so the budget is set
/// nearer the cheap end; attribution is best-effort by design and its shortfall
/// is reported, while a lost event is neither.
const SCAN_DUTY_DIVISOR: u32 = 4;

/// Longest a snapshot is consulted before being scanned again.
///
/// Inode numbers are recycled, so an entry that outlives its socket can
/// describe a different one. Callers filter an answer against the destination
/// the kernel reported, but bounding the age keeps that filter from being the
/// only thing standing between a recycled inode and a wrong local address.
const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(1);

/// One socket as `/proc/net` describes it.
///
/// Addresses are kept parsed rather than as the `String`s [`SocketMetadata`]
/// carries: a refresh indexes every socket on the host, and all but a handful
/// are never looked up, so the formatting is deferred to the lookup that hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketEntry {
    source_ip: IpAddr,
    source_port: u16,
    destination_ip: IpAddr,
    destination_port: u16,
    protocol: &'static str,
}

impl SocketEntry {
    fn to_metadata(self) -> SocketMetadata {
        SocketMetadata {
            source_ip: Some(self.source_ip.to_string()),
            source_port: Some(self.source_port),
            destination_ip: Some(self.destination_ip.to_string()),
            destination_port: Some(self.destination_port),
            protocol: Some(self.protocol.to_string()),
        }
    }
}

/// A snapshot of the host's IP sockets, keyed by inode.
///
/// Not `Sync`, and deliberately not shared: it belongs to the thread draining
/// the network ring, so a lookup costs no synchronisation and the refresh
/// policy answers to one batch of events at a time.
#[derive(Debug)]
pub struct SocketInventory {
    entries: HashMap<u64, SocketEntry>,
    refreshed_at: Option<Instant>,
    /// How long the last scan took. The budget the effective floor is derived
    /// from; see [`SCAN_DUTY_DIVISOR`].
    last_scan_cost: Duration,
    min_refresh_interval: Duration,
    max_snapshot_age: Duration,
    scan_duty_divisor: u32,
    scans: u64,
}

impl Default for SocketInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketInventory {
    pub fn new() -> Self {
        Self::with_refresh_policy(MIN_REFRESH_INTERVAL, MAX_SNAPSHOT_AGE, SCAN_DUTY_DIVISOR)
    }

    /// Build an inventory with an explicit refresh policy.
    ///
    /// Exists for tests and benchmarks, which need the policy pinned to make a
    /// scan count reproducible rather than a function of how fast the machine
    /// got through the loop and how many sockets it happened to have open. A
    /// `scan_duty_divisor` of zero turns the cost-proportional widening off and
    /// leaves the fixed floor alone.
    pub fn with_refresh_policy(
        min_refresh_interval: Duration,
        max_snapshot_age: Duration,
        scan_duty_divisor: u32,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            refreshed_at: None,
            last_scan_cost: Duration::ZERO,
            min_refresh_interval,
            max_snapshot_age,
            scan_duty_divisor,
            scans: 0,
        }
    }

    /// Local address and transport of the socket `fd` names in `pid`, or
    /// `None` when the current snapshot does not describe it.
    ///
    /// Answers from the snapshot alone and never scans, so a burst of lookups
    /// costs a `readlink` each and nothing more. Taking the snapshot is
    /// [`refresh_if_due`](Self::refresh_if_due)'s job, and the caller places
    /// that call — after a batch of events has been decoded, when every socket
    /// the batch asks about already exists.
    ///
    /// The inode still comes from a `readlink` on `/proc/<pid>/fd/<fd>`, which
    /// is one syscall against one process and does not grow with the number of
    /// sockets on the host. What the snapshot removes is the table scan behind
    /// it.
    pub fn lookup(&self, pid: u32, fd: i32) -> Option<SocketMetadata> {
        if pid == 0 || fd < 0 {
            return None;
        }
        let inode = read_socket_inode(pid, fd)?;
        self.entries.get(&inode).map(|entry| entry.to_metadata())
    }

    /// Take a new snapshot if the refresh floor allows one.
    ///
    /// Call this once per batch of events that need attribution, before
    /// resolving them: one scan then answers the whole batch, and it is taken
    /// after the batch's connects have happened rather than before, which is
    /// the difference between resolving a burst and missing it.
    ///
    /// Returns whether a scan was taken.
    pub fn refresh_if_due(&mut self, tables: SocketTableSet) -> bool {
        if tables.is_empty() {
            return false;
        }
        let floor = self.effective_refresh_floor();
        if self.age().is_some_and(|age| age < floor) {
            return false;
        }
        self.refresh(tables);
        true
    }

    /// Table scans this inventory has performed. The number the per-event
    /// lookup existed to bound.
    pub fn scans(&self) -> u64 {
        self.scans
    }

    /// Sockets in the current snapshot.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn age(&self) -> Option<Duration> {
        self.refreshed_at.map(|at| at.elapsed())
    }

    /// The floor a batch refresh has to clear, widened when the last scan
    /// was expensive. See [`SCAN_DUTY_DIVISOR`].
    fn effective_refresh_floor(&self) -> Duration {
        (self.last_scan_cost * self.scan_duty_divisor)
            .clamp(self.min_refresh_interval, self.max_snapshot_age)
    }

    /// Re-read the requested tables into the snapshot.
    ///
    /// The snapshot then describes those tables and nothing else, so a lookup
    /// against a table this scan skipped misses rather than answering from a
    /// stale one. The map is cleared rather than rebuilt so a steady-state host
    /// stops reallocating it, and a table that cannot be read is skipped: a
    /// missing `/proc/net/tcp6` on a kernel built without IPv6 is not a reason
    /// to lose the other three.
    fn refresh(&mut self, tables: SocketTableSet) {
        let started = Instant::now();
        self.entries.clear();
        for (index, (path, protocol, ipv6)) in PROC_NET_TABLES.into_iter().enumerate() {
            if tables.contains(index) {
                index_proc_net(path, protocol, ipv6, &mut self.entries);
            }
        }
        let finished = Instant::now();
        self.last_scan_cost = finished.saturating_duration_since(started);
        self.refreshed_at = Some(finished);
        self.scans = self.scans.saturating_add(1);
    }
}

/// Resolve the socket inode from `/proc/{pid}/fd/{fd}`.
///
/// Uses `readlink` rather than `open(2)`, which returns `ENXIO` for a socket.
/// The symlink target is `"socket:[inode]"` for socket fds.
fn read_socket_inode(pid: u32, fd: i32) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let s = link.to_string_lossy();
    let inner = s.strip_prefix("socket:[")?;
    inner.strip_suffix(']')?.parse().ok()
}

/// Index one `/proc/net/{tcp,tcp6,udp,udp6}` table by socket inode.
///
/// Field layout (whitespace-separated, 0-indexed, header skipped):
///   0: sl   1: local_addr   2: rem_addr   3: state   …   9: inode
///
/// Addresses are printed as `XXXXXXXX:PPPP` (IPv4) or
/// `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP` (IPv6) in host byte order.
///
/// A line that does not parse is skipped rather than aborting the table: the
/// tables grow columns between kernel releases, and one unreadable row must
/// not cost the rest of the host's sockets.
fn index_proc_net(
    path: &str,
    protocol: &'static str,
    ipv6: bool,
    entries: &mut HashMap<u64, SocketEntry>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };

    for line in content.lines().skip(1) {
        if let Some((inode, entry)) = parse_proc_net_line(line, protocol, ipv6) {
            entries.insert(inode, entry);
        }
    }
}

fn parse_proc_net_line(
    line: &str,
    protocol: &'static str,
    ipv6: bool,
) -> Option<(u64, SocketEntry)> {
    let mut iter = line.split_whitespace();
    let _sl = iter.next()?;
    let local = iter.next()?;
    let remote = iter.next()?;
    let _state = iter.next()?;
    // tx_queue:rx_queue, tr:tm, retrnsmt, uid, timeout
    for _ in 0..5 {
        iter.next()?;
    }
    let inode: u64 = iter.next()?.parse().ok()?;

    // A socket in `TIME_WAIT` or `FIN_WAIT2` has been detached from its
    // descriptor and is listed with inode 0. No `/proc/<pid>/fd` link can name
    // it, so it can never be looked up - and under connection churn these are
    // most of the table. Rejecting them on the integer before parsing two
    // addresses is what keeps a scan proportional to live sockets rather than
    // to the churn backlog.
    if inode == 0 {
        return None;
    }

    let (source_ip, source_port) = parse_addr(local, ipv6)?;
    let (destination_ip, destination_port) = parse_addr(remote, ipv6)?;

    Some((
        inode,
        SocketEntry {
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
        },
    ))
}

fn parse_addr(s: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ipv6 {
        parse_ipv6_hex(ip_hex)?
    } else {
        parse_ipv4_hex(ip_hex)?
    };
    Some((ip, port))
}

/// Parse a hex IPv4 address from `/proc/net/tcp`.
///
/// The kernel prints the raw `__be32` with `%08X`, which on a little-endian
/// host produces a byte-reversed hex string. `n.to_be()` undoes that reversal
/// on LE and is a no-op on BE, yielding a u32 in network byte order suitable
/// for `Ipv4Addr::from`.
fn parse_ipv4_hex(s: &str) -> Option<IpAddr> {
    let n = u32::from_str_radix(s, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(n.to_be())))
}

/// Parse a 32-hex-char IPv6 address from `/proc/net/tcp6`.
///
/// The address is four consecutive native-endian u32 words. Each word is
/// byte-swapped independently to produce the 16-byte network-order address.
fn parse_ipv6_hex(s: &str) -> Option<IpAddr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&s[i * 8..(i + 1) * 8], 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be().to_be_bytes());
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    /// Bind a loopback listener, or `None` where the sandbox forbids it.
    fn loopback_listener() -> Option<TcpListener> {
        match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(err) => panic!("listener bind: {err}"),
        }
    }

    #[test]
    fn lookup_reads_connected_tcp_socket() {
        let Some(listener) = loopback_listener() else {
            return;
        };
        let listener_addr = listener.local_addr().expect("listener addr");

        let client = TcpStream::connect(listener_addr).expect("client connect");
        let (_server, _) = listener.accept().expect("accept");

        let mut inventory = SocketInventory::new();
        assert!(inventory.refresh_if_due(SocketTableSet::EVERY));
        let metadata = inventory
            .lookup(std::process::id(), client.as_raw_fd())
            .expect("connected client socket should resolve");

        assert_eq!(metadata.protocol.as_deref(), Some("tcp"));
        assert_eq!(metadata.destination_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(metadata.destination_port, Some(listener_addr.port()));
        assert_eq!(metadata.source_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            metadata.source_port,
            Some(client.local_addr().expect("client addr").port())
        );
    }

    /// The drain-batch case the inventory exists for: one scan, then as many
    /// lookups as the batch holds.
    #[test]
    fn one_scan_answers_a_whole_batch() {
        let Some(listener) = loopback_listener() else {
            return;
        };
        let listener_addr = listener.local_addr().expect("listener addr");

        let clients: Vec<TcpStream> = (0..16)
            .map(|_| {
                let client = TcpStream::connect(listener_addr).expect("client connect");
                let (_server, _) = listener.accept().expect("accept");
                client
            })
            .collect();

        let mut inventory = SocketInventory::new();
        inventory.refresh_if_due(SocketTableSet::EVERY);
        for client in &clients {
            assert!(inventory
                .lookup(std::process::id(), client.as_raw_fd())
                .is_some());
        }

        assert_eq!(
            inventory.scans(),
            1,
            "lookups must answer from the snapshot rather than scan for themselves"
        );
    }

    /// A socket created after the last scan resolves once the batch it belongs
    /// to refreshes — which is why the caller refreshes after draining, not
    /// before.
    #[test]
    fn a_socket_newer_than_the_snapshot_resolves_at_the_next_refresh() {
        let Some(listener) = loopback_listener() else {
            return;
        };
        let listener_addr = listener.local_addr().expect("listener addr");

        let mut inventory =
            SocketInventory::with_refresh_policy(Duration::ZERO, Duration::from_secs(60), 0);
        assert!(inventory.refresh_if_due(SocketTableSet::EVERY));

        let client = TcpStream::connect(listener_addr).expect("client connect");
        let (_server, _) = listener.accept().expect("accept");
        let pid = std::process::id();
        let fd = client.as_raw_fd();

        assert!(
            inventory.lookup(pid, fd).is_none(),
            "the snapshot predates the socket, so it cannot describe it"
        );
        assert!(inventory.refresh_if_due(SocketTableSet::EVERY));
        assert!(
            inventory.lookup(pid, fd).is_some(),
            "the refresh that follows the batch must pick it up"
        );
    }

    #[test]
    fn the_floor_caps_how_often_a_batch_can_scan() {
        let mut inventory = SocketInventory::with_refresh_policy(
            Duration::from_secs(60),
            Duration::from_secs(60),
            0,
        );
        assert!(
            inventory.refresh_if_due(SocketTableSet::EVERY),
            "the first batch has no snapshot"
        );
        for _ in 0..64 {
            assert!(!inventory.refresh_if_due(SocketTableSet::EVERY));
        }
        assert_eq!(inventory.scans(), 1);
    }

    #[test]
    fn a_table_set_names_only_the_table_that_can_hold_the_socket() {
        // /proc/net/tcp alone: index 0 of PROC_NET_TABLES.
        assert_eq!(
            SocketTableSet::for_socket(2, Some("tcp")),
            SocketTableSet(0b0001)
        );
        // /proc/net/udp6 alone: index 3.
        assert_eq!(
            SocketTableSet::for_socket(10, Some("udp")),
            SocketTableSet(0b1000)
        );
        // A socket opened before the sensor started names no transport, so
        // both tables of its family stay in play.
        assert_eq!(SocketTableSet::for_socket(2, None), SocketTableSet(0b0101));
        // A family the probe does not report narrows nothing.
        assert_eq!(SocketTableSet::for_socket(0, None), SocketTableSet::EVERY);
    }

    /// A scan reads what it was asked for, so a lookup against a table it
    /// skipped must miss rather than answer from the previous snapshot.
    #[test]
    fn a_narrowed_scan_does_not_answer_for_the_tables_it_skipped() {
        let Some(listener) = loopback_listener() else {
            return;
        };
        let listener_addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(listener_addr).expect("client connect");
        let (_server, _) = listener.accept().expect("accept");

        let mut inventory =
            SocketInventory::with_refresh_policy(Duration::ZERO, Duration::from_secs(60), 0);
        let pid = std::process::id();
        let fd = client.as_raw_fd();

        inventory.refresh_if_due(SocketTableSet::for_socket(2, Some("udp")));
        assert!(inventory.lookup(pid, fd).is_none());

        inventory.refresh_if_due(SocketTableSet::for_socket(2, Some("tcp")));
        assert!(inventory.lookup(pid, fd).is_some());
    }

    #[test]
    fn an_expensive_scan_widens_the_refresh_floor() {
        let mut inventory = SocketInventory::new();

        inventory.last_scan_cost = Duration::from_micros(500);
        assert_eq!(
            inventory.effective_refresh_floor(),
            Duration::from_millis(2),
            "a cheap scan may repeat often, because repeating it costs little"
        );

        inventory.last_scan_cost = Duration::ZERO;
        assert_eq!(
            inventory.effective_refresh_floor(),
            MIN_REFRESH_INTERVAL,
            "a cost that rounds to nothing still leaves a floor"
        );

        inventory.last_scan_cost = Duration::from_millis(25);
        assert_eq!(
            inventory.effective_refresh_floor(),
            Duration::from_millis(100),
            "a 25 ms scan may repeat at most every 100 ms, i.e. a quarter of the thread"
        );

        inventory.last_scan_cost = Duration::from_secs(10);
        assert_eq!(
            inventory.effective_refresh_floor(),
            MAX_SNAPSHOT_AGE,
            "the ceiling keeps a pathological table from freezing the snapshot"
        );
    }

    /// Turning the widening off must leave the fixed floor exactly as it was,
    /// because that is what the tests and the benchmark pin.
    #[test]
    fn a_zero_duty_divisor_leaves_the_fixed_floor_alone() {
        let mut inventory = SocketInventory::with_refresh_policy(
            Duration::from_millis(7),
            Duration::from_secs(1),
            0,
        );
        inventory.last_scan_cost = Duration::from_millis(25);

        assert_eq!(
            inventory.effective_refresh_floor(),
            Duration::from_millis(7)
        );
    }

    #[test]
    fn parses_an_ipv4_table_line() {
        let line = "   1: 0100007F:0016 0200007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 20 0 0 10 0";
        let (inode, entry) = parse_proc_net_line(line, "tcp", false).expect("line should parse");

        assert_eq!(inode, 4242);
        assert_eq!(entry.source_ip.to_string(), "127.0.0.1");
        assert_eq!(entry.source_port, 22);
        assert_eq!(entry.destination_ip.to_string(), "127.0.0.2");
        assert_eq!(entry.destination_port, 40_000);
        assert_eq!(entry.protocol, "tcp");
    }

    /// The churn backlog: detached sockets no descriptor can name, and most of
    /// the table on a host that has been opening connections.
    #[test]
    fn skips_a_socket_with_no_descriptor_behind_it() {
        let time_wait = "   2: 0100007F:0016 0200007F:9C40 06 00000000:00000000 03:00000C1B 00000000     0        0 0 0 0000000000000000";
        assert!(parse_proc_net_line(time_wait, "tcp", false).is_none());
    }

    #[test]
    fn skips_a_line_it_cannot_parse() {
        assert!(parse_proc_net_line("  sl  local_address rem_address", "tcp", false).is_none());
        assert!(parse_proc_net_line("", "tcp", false).is_none());
    }
}
