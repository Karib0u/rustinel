//! Pure packet parsing for the macOS `/dev/bpf` sensor.
//!
//! Parses a captured link-layer frame down to its transport header. The parser
//! is deliberately defensive: it consumes untrusted bytes off the wire, never
//! panics, and bails out (`None`) on anything malformed or unsupported.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Link-layer header types reported by `BIOCGDLT`.
const DLT_NULL: u32 = 0;
pub(super) const DLT_EN10MB: u32 = 1;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// TCP control-flag bits used to detect connection initiations.
pub(super) const TCP_FLAG_SYN: u8 = 0x02;
pub(super) const TCP_FLAG_ACK: u8 = 0x10;

/// Parsed transport header for a captured packet.
pub(super) enum Transport<'a> {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &'a [u8],
    },
    Udp {
        dst_port: u16,
        payload: &'a [u8],
    },
}

/// A captured packet parsed down to its transport layer.
pub(super) struct ParsedPacket<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub transport: Transport<'a>,
}

/// Parse a captured link-layer frame into a [`ParsedPacket`].
pub(super) fn parse(link_type: u32, frame: &[u8]) -> Option<ParsedPacket<'_>> {
    let l3 = strip_link_layer(link_type, frame)?;
    parse_ip(l3)
}

/// Strip the link-layer header and return the network-layer (L3) bytes.
fn strip_link_layer(link_type: u32, frame: &[u8]) -> Option<&[u8]> {
    match link_type {
        // Loopback/null: a 4-byte address-family prefix. The IP version nibble
        // disambiguates v4/v6, so the family value itself is not needed.
        DLT_NULL => frame.get(4..),
        DLT_EN10MB => {
            let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
            match ethertype {
                ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => frame.get(14..),
                ETHERTYPE_VLAN => {
                    let inner = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
                    match inner {
                        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => frame.get(18..),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_ip(l3: &[u8]) -> Option<ParsedPacket<'_>> {
    match l3.first()? >> 4 {
        4 => parse_ipv4(l3),
        6 => parse_ipv6(l3),
        _ => None,
    }
}

fn parse_ipv4(l3: &[u8]) -> Option<ParsedPacket<'_>> {
    if l3.len() < 20 {
        return None;
    }
    let ihl = usize::from(l3[0] & 0x0f) * 4;
    if ihl < 20 || l3.len() < ihl {
        return None;
    }
    let protocol = l3[9];
    let src = Ipv4Addr::new(l3[12], l3[13], l3[14], l3[15]);
    let dst = Ipv4Addr::new(l3[16], l3[17], l3[18], l3[19]);
    let transport = parse_transport(protocol, l3.get(ihl..)?)?;
    Some(ParsedPacket {
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        transport,
    })
}

fn parse_ipv6(l3: &[u8]) -> Option<ParsedPacket<'_>> {
    if l3.len() < 40 {
        return None;
    }
    // Extension headers are not followed; only packets whose first next-header
    // is a transport we handle are parsed.
    let next_header = l3[6];
    let mut src = [0u8; 16];
    src.copy_from_slice(&l3[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&l3[24..40]);
    let transport = parse_transport(next_header, l3.get(40..)?)?;
    Some(ParsedPacket {
        src_ip: IpAddr::V6(Ipv6Addr::from(src)),
        dst_ip: IpAddr::V6(Ipv6Addr::from(dst)),
        transport,
    })
}

fn parse_transport(protocol: u8, l4: &[u8]) -> Option<Transport<'_>> {
    match protocol {
        IPPROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let data_offset = usize::from(l4[12] >> 4) * 4;
            if data_offset < 20 || l4.len() < data_offset {
                return None;
            }
            Some(Transport::Tcp {
                src_port,
                dst_port,
                flags: l4[13],
                payload: l4.get(data_offset..).unwrap_or(&[]),
            })
        }
        IPPROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            Some(Transport::Udp {
                dst_port: u16::from_be_bytes([l4[2], l4[3]]),
                payload: l4.get(8..).unwrap_or(&[]),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an Ethernet + IPv4 + TCP frame with the given ports and flags.
    fn ethernet_ipv4_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4 header (20 bytes, IHL=5).
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = IPPROTO_TCP;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        // TCP header (20 bytes, data offset = 5).
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        frame.extend(ip);
        frame.extend(tcp);
        frame
    }

    #[test]
    fn parses_ethernet_ipv4_tcp() {
        let frame = ethernet_ipv4_tcp([10, 0, 0, 5], [93, 184, 216, 34], 51324, 443, TCP_FLAG_SYN);
        let parsed = parse(DLT_EN10MB, &frame).expect("frame should parse");
        assert_eq!(parsed.src_ip.to_string(), "10.0.0.5");
        assert_eq!(parsed.dst_ip.to_string(), "93.184.216.34");
        match parsed.transport {
            Transport::Tcp {
                src_port,
                dst_port,
                flags,
                ..
            } => {
                assert_eq!(src_port, 51324);
                assert_eq!(dst_port, 443);
                assert_eq!(flags, TCP_FLAG_SYN);
            }
            other => panic!("unexpected transport: {}", transport_kind(&other)),
        }
    }

    fn transport_kind(transport: &Transport) -> &'static str {
        match transport {
            Transport::Tcp { .. } => "tcp",
            Transport::Udp { .. } => "udp",
        }
    }

    /// Build an Ethernet + IPv4 + UDP frame carrying `udp_payload`.
    fn ethernet_ipv4_udp(dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&[10, 0, 0, 5]);
        ip[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let mut udp = vec![0u8; 8];
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        frame.extend(ip);
        frame.extend(udp);
        frame.extend_from_slice(udp_payload);
        frame
    }

    #[test]
    fn parses_ethernet_ipv4_udp() {
        let frame = ethernet_ipv4_udp(53, &[0xab, 0xcd]);
        let parsed = parse(DLT_EN10MB, &frame).expect("udp frame should parse");
        match parsed.transport {
            Transport::Udp { dst_port, payload } => {
                assert_eq!(dst_port, 53);
                assert_eq!(payload, &[0xab, 0xcd]);
            }
            other => panic!("unexpected transport: {}", transport_kind(&other)),
        }
    }

    #[test]
    fn parses_null_link_layer() {
        let mut frame = vec![0u8; 4]; // 4-byte address family prefix
        frame[0] = 2; // AF_INET, ignored by the parser
        let tcp_frame = ethernet_ipv4_tcp([127, 0, 0, 1], [127, 0, 0, 1], 1, 53, TCP_FLAG_SYN);
        frame.extend_from_slice(&tcp_frame[14..]); // IP + TCP, no ethernet header
        let parsed = parse(DLT_NULL, &frame).expect("null frame should parse");
        assert_eq!(parsed.dst_ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn rejects_non_ip_ethertype() {
        let mut frame = vec![0u8; 60];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP
        assert!(parse(DLT_EN10MB, &frame).is_none());
    }

    #[test]
    fn rejects_truncated_ip_header() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&[0x45, 0, 0]); // partial IPv4 header
        assert!(parse(DLT_EN10MB, &frame).is_none());
    }
}
