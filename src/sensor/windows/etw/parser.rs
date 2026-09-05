//! ETW property parsing and timestamp conversion.

use crate::sensor::network_events::{decode_etw_ipv4, decode_etw_port, NetworkAddressFamily};
use ferrisetw::parser::Parser;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) const WINDOWS_EPOCH_DELTA_100NS: i64 = 116444736000000000;

pub(super) fn filetime_to_system_time(filetime: i64) -> SystemTime {
    let unix_100ns = filetime.saturating_sub(WINDOWS_EPOCH_DELTA_100NS).max(0) as u64;
    let secs = unix_100ns / 10_000_000;
    let nanos = (unix_100ns % 10_000_000) * 100;
    UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(nanos)
}

pub(super) fn try_get_string(parser: &Parser, property_name: &str) -> Option<String> {
    match parser.try_parse::<String>(property_name) {
        Ok(value) => {
            let trimmed = value.trim_end_matches('\0').to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(_) => None,
    }
}

pub(super) fn try_get_string_any(parser: &Parser, property_names: &[&str]) -> Option<String> {
    for property_name in property_names {
        if let Some(value) = try_get_string(parser, property_name) {
            return Some(value);
        }
    }
    None
}

pub(super) fn try_get_uint(parser: &Parser, property_name: &str) -> Option<String> {
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(value.to_string());
    }
    if let Ok(value) = parser.try_parse::<u64>(property_name) {
        return Some(value.to_string());
    }
    if let Ok(value) = parser.try_parse::<u16>(property_name) {
        return Some(value.to_string());
    }
    if let Ok(value) = parser.try_parse::<u8>(property_name) {
        return Some(value.to_string());
    }
    None
}

pub(super) fn try_get_uint_as_u64(parser: &Parser, property_name: &str) -> Option<u64> {
    if let Ok(value) = parser.try_parse::<u64>(property_name) {
        return Some(value);
    }
    if let Ok(value) = parser.try_parse::<i64>(property_name) {
        return Some(value as u64);
    }
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(value as u64);
    }
    None
}

pub(super) fn try_get_port(parser: &Parser, property_name: &str) -> Option<String> {
    if let Ok(value) = parser.try_parse::<u16>(property_name) {
        return Some(decode_etw_port(value).to_string());
    }
    if let Ok(value) = parser.try_parse::<u32>(property_name) {
        return Some(decode_etw_port(value as u16).to_string());
    }
    None
}

pub(super) fn try_get_ip(
    parser: &Parser,
    property_name: &str,
    address_family: NetworkAddressFamily,
) -> Option<String> {
    match address_family {
        NetworkAddressFamily::Ipv4 => {
            if let Ok(addr) = parser.try_parse::<u32>(property_name) {
                return Some(decode_etw_ipv4(addr).to_string());
            }
        }
        NetworkAddressFamily::Ipv6 => {
            if let Ok(IpAddr::V6(addr)) = parser.try_parse::<IpAddr>(property_name) {
                return Some(addr.to_string());
            }
        }
        NetworkAddressFamily::Unspecified => {
            if let Ok(ip) = parser.try_parse::<IpAddr>(property_name) {
                return Some(ip.to_string());
            }
        }
    }
    try_get_string(parser, property_name)
}

pub(super) fn parse_optional_u32(value: Option<&str>) -> Option<u32> {
    value.and_then(|value| value.parse::<u32>().ok())
}
