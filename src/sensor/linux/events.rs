//! Userspace mirror of the eBPF ring-buffer event types.
//!
//! **These structs must match `ebpf/src/events.rs` exactly** — same field
//! order, same sizes, same `#[repr(C)]` layout. The userspace loader reads raw
//! bytes from a ring buffer and transmutes them into these types. Any
//! divergence silently produces garbage.
//!
//! When modifying either side, update both files together and run the
//! cross-platform golden tests to verify byte-level compatibility.

/// Maximum bytes of argv the eBPF exec path captures. Mirrors
/// `ARGV_CAPACITY` in `ebpf/src/events.rs`.
pub const ARGV_CAPACITY: usize = 512;

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
    /// Valid bytes in `args`; 0 when the kernel captured no argv.
    pub args_len: u16,
    /// Number of argv entries in `args`.
    pub args_count: u16,
    /// 1 when argv exceeded the kernel capture limits.
    pub args_truncated: u8,
    pub _pad1: [u8; 3],
    /// NUL-separated argv captured at `execve` entry.
    pub args: [u8; ARGV_CAPACITY],
}

impl ProcessEvent {
    /// Command line reconstructed from the kernel argv capture.
    ///
    /// Returns `None` when the kernel captured nothing, so callers can fall
    /// back to `/proc/<pid>/cmdline`. Arguments are joined with a single
    /// space, matching how the `/proc` reader renders them.
    pub fn kernel_command_line(&self) -> Option<String> {
        let len = (self.args_len as usize).min(self.args.len());
        if self.args_count == 0 || len == 0 {
            return None;
        }

        let parts: Vec<String> = self.args[..len]
            .split(|byte| *byte == 0)
            .filter(|segment| !segment.is_empty())
            .map(|segment| String::from_utf8_lossy(segment).into_owned())
            .collect();

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
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

/// Bytes captured for one file path, including the NUL terminator.
///
/// Mirrors `FILE_PATH_LEN` in `ebpf/src/events.rs`.
pub const FILE_PATH_LEN: usize = 512;

/// `path` did not fit in [`FILE_PATH_LEN`] and was cut short.
pub const FILE_FLAG_PATH_TRUNCATED: u32 = 1 << 0;

/// `aux_path` did not fit in [`FILE_PATH_LEN`] and was cut short.
pub const FILE_FLAG_AUX_PATH_TRUNCATED: u32 = 1 << 1;

/// File event. Produced by `handle_openat_exit` / `handle_unlinkat_exit` /
/// `handle_renameat*_exit`.
///
/// `kind`: 1 = create, 2 = delete, 3 = rename, 4 = change.
///
/// `path` and `aux_path` are raw `*at` pathname arguments and may be relative;
/// `dfd` and `aux_dfd` are the directory descriptors they resolve against. See
/// [`super::paths`] for the reconstruction rules.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    /// Bitmask of `FILE_FLAG_*` — currently path truncation.
    pub flags: u32,
    /// Directory descriptor `path` is relative to, or `AT_FDCWD`.
    pub dfd: i32,
    /// Directory descriptor `aux_path` is relative to, or `AT_FDCWD`.
    pub aux_dfd: i32,
    /// Kernel token for the indexed directory currently held in `dfd`.
    /// Zero means the index must not be used.
    pub dfd_token: u64,
    /// Kernel token for the indexed directory currently held in `aux_dfd`.
    /// Zero means the index must not be used.
    pub aux_dfd_token: u64,
    pub path: [u8; FILE_PATH_LEN],
    pub aux_path: [u8; FILE_PATH_LEN],
    pub comm: [u8; 16],
}

/// Common prefix shared by full file events and compact index events.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEventHeader {
    pub kind: u32,
    pub pid: u32,
}

/// Compact directory-index maintenance event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileIndexEvent {
    pub kind: u32,
    pub pid: u32,
    pub fd: i32,
    pub _pad: u32,
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
    core::mem::size_of::<ProcessEvent>() == 680,
    "ProcessEvent layout changed — update ebpf/src/events.rs to match"
);
// The argv fields were appended after `image`; pin their offsets so a
// reordering on either side fails the build instead of decoding garbage.
const _: () = assert!(
    core::mem::offset_of!(ProcessEvent, args_len) == 160
        && core::mem::offset_of!(ProcessEvent, args_count) == 162
        && core::mem::offset_of!(ProcessEvent, args_truncated) == 164
        && core::mem::offset_of!(ProcessEvent, args) == 168,
    "ProcessEvent argv fields moved — update ebpf/src/events.rs to match"
);
const _: () = assert!(
    core::mem::size_of::<NetworkEvent>() == 56,
    "NetworkEvent layout changed — update ebpf/src/events.rs to match"
);
const _: () = assert!(
    core::mem::size_of::<FileEvent>() == 1080,
    "FileEvent layout changed — update ebpf/src/events.rs to match"
);
const _: () = assert!(core::mem::size_of::<FileEventHeader>() == 8);
const _: () = assert!(core::mem::size_of::<FileIndexEvent>() == 16);
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

    use super::super::paths::{resolve_at_path, truncation_marker, DirFdIndex};
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
                company: None,
                file_version: None,
                target_image: None,
                // Exit events carry no argv; only exec fills the buffer.
                command_line: (action == SensorAction::Start)
                    .then(|| event.kernel_command_line())
                    .flatten(),
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

    /// Map a raw file event, rebuilding both paths from their directory
    /// descriptors.
    ///
    /// `None` when the target path cannot be resolved — see
    /// [`resolve_at_path`] for when that happens and why a raw relative name is
    /// not an acceptable substitute.
    pub fn file_event_to_sensor(index: &DirFdIndex, event: &FileEvent) -> Option<SensorEvent> {
        let action = match event.kind {
            2 => SensorAction::Delete,
            3 => SensorAction::Rename,
            4 => SensorAction::Modify,
            _ => SensorAction::Create,
        };
        let normalization = SensorNormalization::for_file_action(action)
            .expect("file actions are covered by the shared file normalization table");

        let target_filename = resolve_at_path(
            index,
            event.pid,
            event.dfd,
            event.dfd_token,
            &bytes_to_string(&event.path),
        )?;
        let source_filename = (action == SensorAction::Rename)
            .then(|| bytes_to_string(&event.aux_path))
            .filter(|value| !value.is_empty())
            .and_then(|value| {
                resolve_at_path(index, event.pid, event.aux_dfd, event.aux_dfd_token, &value)
            });

        Some(SensorEvent {
            platform: Platform::Linux,
            provider: PROVIDER,
            action,
            normalization,
            pid: Some(event.pid),
            timestamp: SystemTime::now(),
            process_start_key: None,
            payload: SensorPayload::File(FileEventFields {
                path_truncated: truncation_marker(event.flags, source_filename.is_some())
                    .map(str::to_string),
                source_filename,
                target_filename: Some(target_filename),
                process_id: Some(event.pid.to_string()),
                image: Some(bytes_to_string(&event.comm)),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: Some(event.uid.to_string()),
            }),
        })
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
    fn process_event_round_trips_kernel_argv_through_raw_bytes() {
        let mut event = ProcessEvent {
            kind: 1,
            pid: 4242,
            uid: 1000,
            _pad: 0,
            comm: [0u8; 16],
            image: [0u8; 128],
            args_len: 0,
            args_count: 0,
            args_truncated: 0,
            _pad1: [0u8; 3],
            args: [0u8; ARGV_CAPACITY],
        };
        let argv = b"/bin/true\0--quiet\0";
        event.args[..argv.len()].copy_from_slice(argv);
        event.args_len = argv.len() as u16;
        event.args_count = 2;

        // Same path the ring-buffer drain takes: raw bytes in, struct out.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&event as *const ProcessEvent).cast::<u8>(),
                core::mem::size_of::<ProcessEvent>(),
            )
        };
        let decoded = parse_event::<ProcessEvent>(bytes).expect("process event should decode");

        assert_eq!(
            decoded.kernel_command_line().as_deref(),
            Some("/bin/true --quiet")
        );
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
