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

pub const TUPLE_MEASURED: u8 = 1;
pub const INBOUND: u8 = 2;

#[inline(always)]
pub fn loopback(family: u16, addr: &[u8; 16]) -> bool {
    (family == 2 && addr[0] == 127)
        || (family == 10 && *addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

#[cfg(test)]
mod tests {
    use super::*;

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
