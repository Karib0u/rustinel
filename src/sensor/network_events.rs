use std::net::Ipv4Addr;

use super::SensorAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkProtocol {
    Tcp,
    Udp,
}

impl NetworkProtocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkAddressFamily {
    Ipv4,
    Ipv6,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkOperation {
    Send,
    Receive,
    Connect,
    Disconnect,
    Retransmit,
    Accept,
    Reconnect,
    Fail,
    Copy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelNetworkEvent {
    pub(crate) protocol: NetworkProtocol,
    pub(crate) address_family: NetworkAddressFamily,
    pub(crate) operation: NetworkOperation,
}

impl KernelNetworkEvent {
    pub(crate) fn connection_action(self) -> Option<SensorAction> {
        match self.operation {
            NetworkOperation::Connect => Some(SensorAction::Connect),
            NetworkOperation::Accept => Some(SensorAction::Accept),
            _ => None,
        }
    }
}

/// Classifies Microsoft-Windows-Kernel-Network manifest event IDs.
///
/// TCP and UDP operations share several classic ETW type values, but the
/// manifest provider assigns UDP its own IDs. Keep every known operation
/// explicit so packet and lifecycle events cannot become connections through
/// a range check.
pub(crate) fn classify_kernel_network_event(event_id: u16) -> Option<KernelNetworkEvent> {
    use NetworkAddressFamily::{Ipv4, Ipv6, Unspecified};
    use NetworkOperation::{
        Accept, Connect, Copy, Disconnect, Fail, Receive, Reconnect, Retransmit, Send,
    };
    use NetworkProtocol::{Tcp, Udp};

    let (protocol, address_family, operation) = match event_id {
        10 => (Tcp, Ipv4, Send),
        11 => (Tcp, Ipv4, Receive),
        12 => (Tcp, Ipv4, Connect),
        13 => (Tcp, Ipv4, Disconnect),
        14 => (Tcp, Ipv4, Retransmit),
        15 => (Tcp, Ipv4, Accept),
        16 => (Tcp, Ipv4, Reconnect),
        17 => (Tcp, Unspecified, Fail),
        18 => (Tcp, Ipv4, Copy),
        26 => (Tcp, Ipv6, Send),
        27 => (Tcp, Ipv6, Receive),
        28 => (Tcp, Ipv6, Connect),
        29 => (Tcp, Ipv6, Disconnect),
        30 => (Tcp, Ipv6, Retransmit),
        31 => (Tcp, Ipv6, Accept),
        32 => (Tcp, Ipv6, Reconnect),
        34 => (Tcp, Ipv6, Copy),
        42 => (Udp, Ipv4, Send),
        43 => (Udp, Ipv4, Receive),
        49 => (Udp, Unspecified, Fail),
        58 => (Udp, Ipv6, Send),
        59 => (Udp, Ipv6, Receive),
        _ => return None,
    };

    Some(KernelNetworkEvent {
        protocol,
        address_family,
        operation,
    })
}

/// ETW stores IPv4 address bytes in network order inside a UInt32 payload.
/// TDH exposes that payload as a little-endian integer on Windows, so preserve
/// its byte sequence instead of converting the integer to big-endian bytes.
pub(crate) fn decode_etw_ipv4(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(addr.to_le_bytes())
}

/// ETW port fields are encoded in network byte order.
pub(crate) fn decode_etw_port(port: u16) -> u16 {
    u16::from_be(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_connect_and_accept_routes_are_explicit_for_both_address_families() {
        for (event_id, address_family, action) in [
            (12, NetworkAddressFamily::Ipv4, SensorAction::Connect),
            (15, NetworkAddressFamily::Ipv4, SensorAction::Accept),
            (28, NetworkAddressFamily::Ipv6, SensorAction::Connect),
            (31, NetworkAddressFamily::Ipv6, SensorAction::Accept),
        ] {
            let event = classify_kernel_network_event(event_id).unwrap();
            assert_eq!(event.protocol, NetworkProtocol::Tcp);
            assert_eq!(event.protocol.as_str(), "tcp");
            assert_eq!(event.address_family, address_family);
            assert_eq!(event.connection_action(), Some(action));
        }
    }

    #[test]
    fn udp_event_ids_are_classified_without_becoming_connections() {
        for (event_id, address_family, operation) in [
            (42, NetworkAddressFamily::Ipv4, NetworkOperation::Send),
            (43, NetworkAddressFamily::Ipv4, NetworkOperation::Receive),
            (58, NetworkAddressFamily::Ipv6, NetworkOperation::Send),
            (59, NetworkAddressFamily::Ipv6, NetworkOperation::Receive),
        ] {
            let event = classify_kernel_network_event(event_id).unwrap();
            assert_eq!(event.protocol, NetworkProtocol::Udp);
            assert_eq!(event.protocol.as_str(), "udp");
            assert_eq!(event.address_family, address_family);
            assert_eq!(event.operation, operation);
            assert_eq!(event.connection_action(), None);
        }
    }

    #[test]
    fn packet_and_non_connection_tcp_operations_are_ignored() {
        for event_id in [10, 11, 13, 14, 16, 17, 18, 26, 27, 29, 30, 32, 34] {
            let event = classify_kernel_network_event(event_id).unwrap();
            assert_eq!(event.protocol, NetworkProtocol::Tcp);
            assert_eq!(event.connection_action(), None, "event {event_id}");
        }
    }

    #[test]
    fn unknown_event_ids_are_not_classified() {
        for event_id in [0, 9, 19, 25, 33, 35, 41, 44, 60, u16::MAX] {
            assert_eq!(classify_kernel_network_event(event_id), None);
        }
    }

    #[test]
    fn ipv4_payload_bytes_keep_network_order() {
        assert_eq!(decode_etw_ipv4(0x0100_007f), Ipv4Addr::LOCALHOST);
        assert_eq!(decode_etw_ipv4(0x0808_0808), Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn port_payload_bytes_keep_network_order() {
        assert_eq!(decode_etw_port(0x5000), 80);
        assert_eq!(decode_etw_port(0xbb01), 443);
    }
}
