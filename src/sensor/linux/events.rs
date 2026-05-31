//! Userspace mirror of the eBPF ring-buffer event types.
//!
//! **These structs must match `ebpf/src/events.rs` exactly** — same field
//! order, same sizes, same `#[repr(C)]` layout. The userspace loader reads raw
//! bytes from a ring buffer and transmutes them into these types. Any
//! divergence silently produces garbage.
//!
//! When modifying either side, update both files together and run the
//! cross-platform golden tests to verify byte-level compatibility.

/// Process lifecycle event.
///
/// - kind 1 = exec (`sched_process_exec`)
/// - kind 2 = exit (`sched_process_exit`)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub comm: [u8; 16],
    pub image: [u8; 128],
}

/// Outbound connection event. Produced by `handle_connect`
/// (`syscalls/sys_enter_connect`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    /// Connected socket file descriptor.
    pub fd: i32,
    pub _pad0: u32,
    /// Destination port in host byte order.
    pub dport: u16,
    /// Source port (may be 0).
    pub sport: u16,
    /// Address family: 2 = IPv4, 10 = IPv6.
    pub af: u16,
    pub _pad1: u16,
    pub daddr: [u8; 16],
    pub saddr: [u8; 16],
}

/// File event. Produced by `handle_openat_exit` / `handle_unlinkat_exit`.
///
/// `kind`: 1 = create, 2 = delete, 3 = rename, 4 = change.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad0: u32,
    pub path: [u8; 96],
    pub aux_path: [u8; 96],
    pub comm: [u8; 16],
}

/// DNS event. Produced by send/receive DNS syscall hooks.
///
/// `kind`: 1 = query, 2 = response.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub payload_len: u16,
    pub _pad0: u16,
    pub query_name: [u8; 96],
    pub query_results: [u8; 96],
    pub record_type: [u8; 16],
    pub payload: [u8; 256],
}

// ── Size assertions ──────────────────────────────────────────────────────────
// These catch accidental struct layout divergence at compile time.

const _: () = assert!(
    core::mem::size_of::<ProcessEvent>() == 160,
    "ProcessEvent layout changed — update ebpf/src/events.rs to match"
);
const _: () = assert!(
    core::mem::size_of::<NetworkEvent>() == 56,
    "NetworkEvent layout changed — update ebpf/src/events.rs to match"
);
const _: () = assert!(
    core::mem::size_of::<FileEvent>() == 224,
    "FileEvent layout changed — update ebpf/src/events.rs to match"
);
const _: () = assert!(
    core::mem::size_of::<DnsEvent>() == 484,
    "DnsEvent layout changed — update ebpf/src/events.rs to match"
);

/// Safely interpret a ring-buffer byte slice as a typed event.
///
/// Returns `None` if `bytes` is too short to hold `T`.
pub fn parse_event<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < core::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: `T` is `#[repr(C)]` and any bit pattern is valid for the integer
    // and array fields it contains. We verify the slice is large enough above.
    let val = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const T) };
    Some(val)
}

/// Convert a null-terminated fixed-length byte array to a `String`.
///
/// Stops at the first null byte; strips trailing null bytes for display.
pub fn bytes_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod mapping {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;

    use crate::models::{
        DnsQueryFields, FileEventFields, NetworkConnectionFields, ProcessCreationFields,
    };
    use crate::sensor::{
        Platform, ProcessStartKey, SensorAction, SensorEvent, SensorNormalization, SensorPayload,
    };

    use super::{bytes_to_string, DnsEvent, FileEvent, NetworkEvent, ProcessEvent};

    const PROVIDER: &str = "ebpf";

    pub fn process_event_to_sensor(event: &ProcessEvent) -> SensorEvent {
        let action = match event.kind {
            2 => SensorAction::Stop,
            _ => SensorAction::Start,
        };
        SensorEvent {
            platform: Platform::Linux,
            provider: PROVIDER,
            action,
            normalization: SensorNormalization {
                event_id: if action == SensorAction::Start { 1 } else { 5 },
                action_code: event.kind as u8,
            },
            pid: Some(event.pid),
            timestamp: SystemTime::now(),
            process_start_key: Some(ProcessStartKey {
                pid: event.pid,
                start_time: 0,
            }),
            payload: SensorPayload::Process(ProcessCreationFields {
                image: Some(bytes_to_string(&event.image)),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some(event.pid.to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some(event.uid.to_string()),
                logon_id: None,
                logon_guid: None,
            }),
        }
    }

    pub fn network_event_to_sensor(event: &NetworkEvent) -> SensorEvent {
        SensorEvent {
            platform: Platform::Linux,
            provider: PROVIDER,
            action: SensorAction::Connect,
            normalization: SensorNormalization {
                event_id: 3,
                action_code: 12,
            },
            pid: Some(event.pid),
            timestamp: SystemTime::now(),
            process_start_key: None,
            payload: SensorPayload::Network(NetworkConnectionFields {
                destination_ip: Some(ip_to_string(event.af, &event.daddr)),
                source_ip: Some(ip_to_string(event.af, &event.saddr)),
                destination_port: Some(event.dport.to_string()),
                source_port: Some(event.sport.to_string()),
                process_id: Some(event.pid.to_string()),
                image: None,
                user: Some(event.uid.to_string()),
                destination_hostname: None,
                protocol: Some("tcp".to_string()),
            }),
        }
    }

    pub fn file_event_to_sensor(event: &FileEvent) -> SensorEvent {
        let (action, event_id, action_code) = match event.kind {
            2 => (SensorAction::Delete, 23, 70),
            3 => (SensorAction::Rename, 71, 71),
            4 => (SensorAction::Modify, 11, 65),
            _ => (SensorAction::Create, 11, 64),
        };
        SensorEvent {
            platform: Platform::Linux,
            provider: PROVIDER,
            action,
            normalization: SensorNormalization {
                event_id,
                action_code,
            },
            pid: Some(event.pid),
            timestamp: SystemTime::now(),
            process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                source_filename: (action == SensorAction::Rename)
                    .then(|| bytes_to_string(&event.aux_path)),
                target_filename: Some(bytes_to_string(&event.path)),
                process_id: Some(event.pid.to_string()),
                image: Some(bytes_to_string(&event.comm)),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: Some(event.uid.to_string()),
            }),
        }
    }

    pub fn dns_event_to_sensor(event: &DnsEvent) -> SensorEvent {
        SensorEvent {
            platform: Platform::Linux,
            provider: PROVIDER,
            action: SensorAction::Query,
            normalization: SensorNormalization {
                event_id: 22,
                action_code: event.kind as u8,
            },
            pid: Some(event.pid),
            timestamp: SystemTime::now(),
            process_start_key: None,
            payload: SensorPayload::Dns(DnsQueryFields {
                query_name: Some(bytes_to_string(&event.query_name)),
                query_results: Some(bytes_to_string(&event.query_results)),
                record_type: Some(bytes_to_string(&event.record_type)),
                query_status: None,
                process_id: Some(event.pid.to_string()),
                image: None,
            }),
        }
    }

    fn ip_to_string(af: u16, bytes: &[u8; 16]) -> String {
        match af {
            10 => Ipv6Addr::from(*bytes).to_string(),
            _ => Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_rejects_short_reads() {
        let raw = [0u8; 12];
        assert!(parse_event::<FileEvent>(&raw).is_none());
        assert!(parse_event::<DnsEvent>(&raw).is_none());
    }

    #[test]
    fn bytes_to_string_stops_at_first_nul() {
        let raw = b"/usr/bin/bash\0ignored";
        assert_eq!(bytes_to_string(raw), "/usr/bin/bash");
    }

    #[test]
    fn bytes_to_string_uses_full_buffer_when_not_nul_terminated() {
        let raw = b"/tmp/file.txt";
        assert_eq!(bytes_to_string(raw), "/tmp/file.txt");
    }
}
