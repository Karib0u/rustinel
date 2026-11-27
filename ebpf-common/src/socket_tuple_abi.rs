//! Runtime socket layout shared by the loader and kernel programs.

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SocketOffsets {
    pub socket_sk: u32,
    pub family: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u32,
    pub dport: u32,
    pub saddr6: u32,
    pub daddr6: u32,
    pub protocol: u32,
    pub protocol_width: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpOffsets {
    pub state: u32,
    pub msg_name: u32,
}

pub const TUPLE_MEASURED: u8 = 1;
pub const INBOUND: u8 = 2;
pub const NETWORK_LISTEN: u8 = 4;
pub const NETWORK_UDP_SEND: u8 = 8;
pub const NETWORK_RAW_SOCKET: u8 = 16;
pub const NETWORK_KIND_MASK: u8 = NETWORK_LISTEN | NETWORK_UDP_SEND | NETWORK_RAW_SOCKET;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_PACKET: u16 = 17;
pub const UDP_DEDUP_NS: u64 = 10_000_000_000;
pub const UDP_BUDGET_NS: u64 = 1_000_000_000;
pub const UDP_EVENTS_PER_WINDOW: u64 = 128;

#[inline(always)]
pub fn raw_socket(family: u16, socket_type: i32) -> bool {
    // The bottom four bits hold the type, above them are SOCK_* flags.
    family == AF_PACKET || socket_type & 0xf == 3
}

#[inline(always)]
pub fn udp_dedup_window(now: u64) -> u64 {
    now / UDP_DEDUP_NS
}

#[inline(always)]
pub fn udp_budget_window(now: u64) -> u64 {
    now / UDP_BUDGET_NS
}

#[inline(always)]
pub fn udp_budget_update(previous: u64, window: u64) -> Option<u64> {
    let previous_window = previous >> 8;
    if window > previous_window {
        return Some((window << 8) | 1);
    }
    if window == previous_window && (previous & 0xff) < UDP_EVENTS_PER_WINDOW {
        return Some(previous + 1);
    }
    None
}

#[inline(always)]
pub fn loopback(family: u16, addr: &[u8; 16]) -> bool {
    (family == AF_INET && addr[0] == 127)
        || (family == AF_INET6 && *addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_and_raw_socket_filters_ignore_socket_flags() {
        assert!(raw_socket(AF_PACKET, 2 | 0x80000));
        assert!(raw_socket(AF_INET, 3 | 0x80800));
        assert!(raw_socket(AF_INET6, 3));
        assert!(!raw_socket(AF_INET, 2 | 0x80000));
        assert!(!raw_socket(AF_INET6, 1));
    }

    #[test]
    fn udp_budget_bounds_churn_and_dedup_window_expires() {
        assert_eq!(udp_dedup_window(0), udp_dedup_window(UDP_DEDUP_NS - 1));
        assert_ne!(udp_dedup_window(0), udp_dedup_window(UDP_DEDUP_NS));
        assert_eq!(udp_budget_window(0), udp_budget_window(UDP_BUDGET_NS - 1));
        assert_ne!(udp_budget_window(0), udp_budget_window(UDP_BUDGET_NS));
        let mut budget = 0;
        let mut admitted = 0;
        for _ in 0..100_000 {
            if let Some(next) = udp_budget_update(budget, 3) {
                budget = next;
                admitted += 1;
            }
        }
        assert_eq!(admitted, UDP_EVENTS_PER_WINDOW);
        assert_eq!(udp_budget_update(budget, 4), Some((4 << 8) | 1));
        assert_eq!(udp_budget_update(budget, 2), None);
    }

    #[test]
    fn loopback_filter_covers_v4_subnet_and_v6_localhost() {
        let mut addr = [0; 16];
        addr[0] = 127;
        addr[3] = 42;
        assert!(loopback(2, &addr));
        addr[0] = 10;
        assert!(!loopback(2, &addr));
        addr = [0; 16];
        addr[15] = 1;
        assert!(loopback(10, &addr));
        addr[15] = 2;
        assert!(!loopback(10, &addr));
    }
}

#[cfg(feature = "aya")]
crate::impl_pod!(SocketOffsets, UdpOffsets);
