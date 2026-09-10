//! Best-effort socket attribution using a bounded-age libproc inventory.
//! Socket closure, PID reuse, and packets arriving between scans can still
//! prevent attribution. Ambiguous owners are left unknown.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::net_info::{InSIAddr, SocketFDInfo, SocketInfoKind};
use libproc::proc_pid::{listpidinfo, pidpath};
use libproc::processes::{pids_by_type, ProcFilter};

const MAX_FDS: usize = 1024;
pub(super) const INVENTORY_TTL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Protocol {
    Tcp,
    Udp,
}

/// The packet source is the candidate local socket. Full addresses avoid
/// attributing forwarded or remote traffic merely because its ports match.
#[derive(Clone, Copy, Debug)]
pub(super) struct Flow {
    pub protocol: Protocol,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
}

pub(super) struct SocketOwner {
    pub pid: u32,
    pub image: Option<String>,
}

struct SocketRecord {
    flow: Flow,
    pid: i32,
}

#[derive(Default)]
pub(super) struct SocketTable {
    owners: HashMap<(Protocol, u16), Vec<SocketRecord>>,
}

impl SocketTable {
    fn insert(&mut self, flow: Flow, pid: i32) {
        self.owners
            .entry((flow.protocol, flow.local_port))
            .or_default()
            .push(SocketRecord { flow, pid });
    }

    fn owner_pid(&self, flow: Flow) -> Option<i32> {
        let mut owner = None;
        for record in self.owners.get(&(flow.protocol, flow.local_port))? {
            let socket = record.flow;
            let local_matches = socket.local_ip == flow.local_ip
                || (socket.local_ip.is_unspecified()
                    && socket.local_ip.is_ipv4() == flow.local_ip.is_ipv4());
            let unconnected_udp = flow.protocol == Protocol::Udp
                && socket.remote_port == 0
                && socket.remote_ip.is_unspecified();
            if !local_matches
                || (!unconnected_udp
                    && (socket.remote_port != flow.remote_port
                        || socket.remote_ip != flow.remote_ip))
            {
                continue;
            }
            if owner.is_some_and(|pid| pid != record.pid) {
                return None;
            }
            owner = Some(record.pid);
        }
        owner
    }
}

pub(super) struct SocketOwnerCache {
    table: Option<(Instant, SocketTable)>,
    ttl: Duration,
}

impl SocketOwnerCache {
    pub fn new(ttl: Duration) -> Self {
        Self { table: None, ttl }
    }

    pub fn find_socket_owner(&mut self, flow: Flow) -> Option<SocketOwner> {
        let pid = self.owner_pid(flow, Instant::now(), scan_sockets)?;
        Some(SocketOwner {
            pid: pid as u32,
            image: pidpath(pid).ok(),
        })
    }

    fn owner_pid(
        &mut self,
        flow: Flow,
        now: Instant,
        scan: impl FnOnce() -> Option<SocketTable>,
    ) -> Option<i32> {
        let expired = self
            .table
            .as_ref()
            .is_none_or(|(built_at, _)| now.duration_since(*built_at) >= self.ttl);
        if expired {
            // Cache failures as an empty inventory too. A denied scan must not
            // trigger a system-wide retry per packet or retain stale owners.
            self.table = Some((now, scan().unwrap_or_default()));
        }
        self.table.as_ref()?.1.owner_pid(flow)
    }
}

/// Walk every process once for both TCP and UDP, rather than per protocol.
fn scan_sockets() -> Option<SocketTable> {
    let pids = pids_by_type(ProcFilter::All).ok()?;
    let mut table = SocketTable::default();
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
            for flow in socket_flows(&socket) {
                table.insert(flow, pid);
            }
        }
    }
    Some(table)
}

fn socket_flows(socket: &SocketFDInfo) -> Vec<Flow> {
    let info = &socket.psi;
    let (protocol, ini) = match SocketInfoKind::from(info.soi_kind) {
        // SAFETY: the kind selects the active arm of the kernel's union.
        SocketInfoKind::Tcp => (Protocol::Tcp, unsafe { info.soi_proto.pri_tcp.tcpsi_ini }),
        SocketInfoKind::In if info.soi_protocol == libc::IPPROTO_UDP => {
            (Protocol::Udp, unsafe { info.soi_proto.pri_in })
        }
        _ => return Vec::new(),
    };
    // INI_IPV4 and INI_IPV6 from sys/proc_info.h. A dual-stack socket
    // can be represented in both families.
    [1, 2]
        .into_iter()
        .filter(|flag| ini.insi_vflag & flag != 0)
        .map(|flag| Flow {
            protocol,
            local_ip: socket_ip(ini.insi_laddr, flag == 1),
            remote_ip: socket_ip(ini.insi_faddr, flag == 1),
            local_port: u16::from_be(ini.insi_lport as u16),
            remote_port: u16::from_be(ini.insi_fport as u16),
        })
        .collect()
}

fn socket_ip(address: InSIAddr, ipv4: bool) -> IpAddr {
    // SAFETY: insi_vflag identifies the initialized address representation.
    if ipv4 {
        IpAddr::V4(Ipv4Addr::from(
            unsafe { address.ina_46.i46a_addr4.s_addr }.to_ne_bytes(),
        ))
    } else {
        let ip = Ipv6Addr::from(unsafe { address.ina_6.s6_addr });
        ip.to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    fn flow(protocol: Protocol, local_port: u16, remote_port: u16) -> Flow {
        Flow {
            protocol,
            local_port,
            remote_port,
            local_ip: "127.0.0.1".parse().unwrap(),
            remote_ip: "127.0.0.1".parse().unwrap(),
        }
    }

    #[test]
    fn cache_bounds_scans_including_failures() {
        let scans = Cell::new(0);
        let mut cache = SocketOwnerCache::new(INVENTORY_TTL);
        let start = Instant::now();
        for i in 0..500 {
            assert!(cache
                .owner_pid(flow(Protocol::Tcp, 50000 + i, 443), start, || {
                    scans.set(scans.get() + 1);
                    None
                })
                .is_none());
        }
        assert_eq!(scans.get(), 1);
        assert_eq!(
            cache.owner_pid(
                flow(Protocol::Tcp, 50000, 443),
                start + INVENTORY_TTL,
                || {
                    scans.set(scans.get() + 1);
                    let mut table = SocketTable::default();
                    table.insert(flow(Protocol::Tcp, 50000, 443), 42);
                    Some(table)
                }
            ),
            Some(42)
        );
        assert_eq!(scans.get(), 2);
        assert_eq!(
            cache.owner_pid(
                flow(Protocol::Tcp, 50000, 443),
                start + INVENTORY_TTL * 2,
                || None
            ),
            None
        );
    }

    #[test]
    fn udp_matches_unconnected_sockets_but_rejects_ambiguous_or_wrong_flows() {
        let mut table = SocketTable::default();
        let query = flow(Protocol::Udp, 50000, 53);
        table.insert(flow(Protocol::Tcp, 50000, 53), 99);
        assert_eq!(table.owner_pid(query), None);
        let mut bound = flow(Protocol::Udp, 50000, 0);
        bound.remote_ip = "0.0.0.0".parse().unwrap();
        table.insert(bound, 42);
        assert_eq!(table.owner_pid(query), Some(42));
        assert_eq!(
            table.owner_pid(Flow {
                local_ip: "10.0.0.1".parse().unwrap(),
                ..query
            }),
            None
        );
        table.insert(bound, 43);
        assert_eq!(table.owner_pid(query), None);
    }

    #[test]
    fn connected_udp_requires_the_remote_address_and_port() {
        let mut table = SocketTable::default();
        let query = flow(Protocol::Udp, 50000, 53);
        table.insert(query, 42);
        assert_eq!(table.owner_pid(query), Some(42));
        assert_eq!(
            table.owner_pid(Flow {
                remote_port: 54,
                ..query
            }),
            None
        );
        assert_eq!(
            table.owner_pid(Flow {
                remote_ip: "10.0.0.1".parse().unwrap(),
                ..query
            }),
            None
        );
    }

    #[test]
    fn scan_attributes_live_tcp_and_udp_in_both_families() {
        for address in ["127.0.0.1", "::1"] {
            let listener = TcpListener::bind((address, 0)).unwrap();
            let remote = listener.local_addr().unwrap();
            let tcp = TcpStream::connect(remote).unwrap();
            let _accepted = listener.accept().unwrap();
            let udp_server = UdpSocket::bind((address, 0)).unwrap();
            let udp_remote = udp_server.local_addr().unwrap();
            let udp = UdpSocket::bind((address, 0)).unwrap();
            let connected = UdpSocket::bind((address, 0)).unwrap();
            connected.connect(udp_remote).unwrap();
            let mut cache = SocketOwnerCache::new(INVENTORY_TTL);
            for (protocol, local, remote) in [
                (Protocol::Tcp, tcp.local_addr().unwrap(), remote),
                (Protocol::Udp, udp.local_addr().unwrap(), udp_remote),
                (Protocol::Udp, connected.local_addr().unwrap(), udp_remote),
            ] {
                let owner = cache
                    .find_socket_owner(Flow {
                        protocol,
                        local_port: local.port(),
                        remote_port: remote.port(),
                        local_ip: local.ip(),
                        remote_ip: remote.ip(),
                    })
                    .expect("live socket is attributed");
                assert_eq!(owner.pid, std::process::id());
            }
        }
    }
}
