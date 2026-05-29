//! Best-effort socket-to-process attribution for captured flows.
//!
//! The bpf sensor observes packets on the wire without an owning process, so
//! this module maps a connection back to a PID by scanning every process's
//! socket descriptors (the macOS equivalent of walking `/proc/net` on Linux).
//!
//! This is inherently best-effort and racy: the socket may have closed by the
//! time we scan, and the scan is `O(processes x descriptors)`. It is therefore
//! used only for TCP connection initiations (one lookup per connection), not
//! for every DNS query. The NetworkExtension framework is the future
//! high-fidelity alternative that carries the owning PID with each flow.

use libc::c_int;
use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::proc_pid::{listpidinfo, pidpath};
use libproc::processes::{pids_by_type, ProcFilter};

/// Maximum file descriptors inspected per process. Processes with more open
/// descriptors than this may not be matched (rare in practice).
const MAX_FDS: usize = 1024;

/// Owner of a captured connection.
pub(super) struct SocketOwner {
    pub pid: u32,
    pub image: Option<String>,
}

/// Find the process owning a TCP connection identified by its local and remote
/// ports. Returns `None` when no live socket matches or inspection is denied.
///
/// Matching on the local (ephemeral) port plus remote port is reliable because
/// the local port is effectively unique to a single active connection.
pub(super) fn find_tcp_socket_owner(local_port: u16, remote_port: u16) -> Option<SocketOwner> {
    let pids = pids_by_type(ProcFilter::All).ok()?;
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
            if tcp_ports_match(&socket, local_port, remote_port) {
                return Some(SocketOwner {
                    pid: pid as u32,
                    image: pidpath(pid).ok(),
                });
            }
        }
    }
    None
}

/// Whether a socket descriptor is a TCP socket with the given local and remote
/// ports.
fn tcp_ports_match(socket: &SocketFDInfo, local_port: u16, remote_port: u16) -> bool {
    let info = &socket.psi;
    if !matches!(SocketInfoKind::from(info.soi_kind), SocketInfoKind::Tcp) {
        return false;
    }
    // SAFETY: soi_kind == Tcp guarantees the TCP arm of the proto union is the
    // active variant, so reading pri_tcp is sound.
    let in_info = unsafe { info.soi_proto.pri_tcp.tcpsi_ini };
    port_from_network(in_info.insi_lport) == local_port
        && port_from_network(in_info.insi_fport) == remote_port
}

/// Convert a port stored in network byte order (low 16 bits of a `c_int`) to a
/// host-order `u16`.
fn port_from_network(port: c_int) -> u16 {
    u16::from_be(port as u16)
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn matches_tcp_socket_by_ports() {
        let socket = tcp_socket(51324, 443);
        assert!(tcp_ports_match(&socket, 51324, 443));
        assert!(!tcp_ports_match(&socket, 51324, 80));
        assert!(!tcp_ports_match(&socket, 1234, 443));
    }

    #[test]
    fn ignores_non_tcp_sockets() {
        let mut socket = tcp_socket(51324, 443);
        socket.psi.soi_kind = SocketInfoKind::In as c_int;
        assert!(!tcp_ports_match(&socket, 51324, 443));
    }
}
