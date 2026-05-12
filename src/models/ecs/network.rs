use std::net::IpAddr;

pub(super) fn network_transport_from_opcode(opcode: u8) -> Option<String> {
    match opcode {
        12 => Some("tcp".to_string()),
        15 => Some("udp".to_string()),
        _ => None,
    }
}

pub(super) fn network_type_from_ip(ip: &str) -> Option<String> {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Some("ipv4".to_string()),
        Ok(IpAddr::V6(_)) => Some("ipv6".to_string()),
        Err(_) => None,
    }
}

pub(super) fn extract_ips(value: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for token in value.split(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':') {
        if token.is_empty() {
            continue;
        }
        if let Ok(addr) = token.parse::<IpAddr>() {
            ips.push(addr.to_string());
        }
    }
    ips.sort();
    ips.dedup();
    ips
}
