//! Userspace decoding of the eBPF ring-buffer events.
//!
//! The `repr(C)` event types are declared once in `rustinel-ebpf-common`,
//! shared with the kernel programs, and re-exported here. This module adds the
//! decoding that only userspace needs.

pub use rustinel_ebpf_common::events::{
    connect_result_is_connection, DnsEvent, FileEvent, FileEventHeader, FileIndexEvent,
    NetworkEvent, ProcessEvent, ARGV_CAPACITY, AT_FDCWD, CONNECT_RESULT_EINPROGRESS,
    CONNECT_RESULT_EINTR, CONNECT_RESULT_OK, DNS_EVENT_QUERY, DNS_EVENT_RESPONSE,
    DNS_PAYLOAD_CAPACITY, FILE_FLAG_AUX_PATH_TRUNCATED, FILE_FLAG_PATH_TRUNCATED, FILE_PATH_LEN,
    PROCESS_IMAGE_CAPACITY,
};
pub use rustinel_ebpf_common::task_identity_abi;

#[cfg(target_os = "linux")]
use std::time::{Duration, SystemTime};

/// Converts kernel `CLOCK_BOOTTIME` timestamps using a sampled wall-clock
/// offset.
///
/// The offset is deliberately owned by the ring-buffer poller instead of being
/// process-global: realtime can be stepped by NTP or an administrator while
/// Rustinel is running. The poller refreshes this value once per second and
/// uses one snapshot for each drained batch.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub struct BootTimeConverter {
    boot_epoch: SystemTime,
}

#[cfg(target_os = "linux")]
impl BootTimeConverter {
    pub fn capture() -> Self {
        let (realtime, boottime) = clock_samples();
        Self::from_clock_samples(realtime, boottime)
    }

    pub fn refresh(&mut self) {
        let (realtime, boottime) = clock_samples();
        self.refresh_from_clock_samples(realtime, boottime);
    }

    fn refresh_from_clock_samples(&mut self, realtime: SystemTime, boottime: Duration) {
        *self = Self::from_clock_samples(realtime, boottime);
    }

    fn from_clock_samples(realtime: SystemTime, boottime: Duration) -> Self {
        Self {
            boot_epoch: realtime
                .checked_sub(boottime)
                .unwrap_or(SystemTime::UNIX_EPOCH),
        }
    }

    pub fn system_time(&self, event_time_ns: u64) -> SystemTime {
        self.boot_epoch
            .checked_add(Duration::from_nanos(event_time_ns))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

#[cfg(target_os = "linux")]
fn clock_samples() -> (SystemTime, Duration) {
    let mut current = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `current` is a valid out-pointer for a timespec.
    let uptime = if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut current) } == 0 {
        Duration::new(current.tv_sec.max(0) as u64, current.tv_nsec.max(0) as u32)
    } else {
        Duration::ZERO
    };
    (SystemTime::now(), uptime)
}

/// Userspace-only accessors for [`ProcessEvent`], which is declared in the
/// shared ABI crate and so cannot carry inherent methods here.
pub trait ProcessEventExt {
    fn raw_effective_uid(&self) -> Option<u32>;
    fn raw_linux_identity(&self) -> crate::sensor::RawLinuxProcessIdentity;
    fn exec_metadata(&self) -> Option<Box<crate::models::ExecMetadata>>;
    fn effective_uid(&self) -> Option<String>;
    fn linux_identity(&self) -> Box<crate::models::LinuxProcessIdentity>;
    /// Command line reconstructed from the kernel argv capture.
    ///
    /// Returns `None` when the kernel captured nothing, so callers can fall
    /// back to `/proc/<pid>/cmdline`. Arguments are joined with a single
    /// space, matching how the `/proc` reader renders them.
    fn kernel_command_line(&self) -> Option<String>;
}

impl ProcessEventExt for ProcessEvent {
    fn raw_effective_uid(&self) -> Option<u32> {
        identity_value(self, task_identity_abi::EUID).and_then(|uid| u32::try_from(uid).ok())
    }

    fn raw_linux_identity(&self) -> crate::sensor::RawLinuxProcessIdentity {
        use task_identity_abi::*;
        let value = |field| identity_value(self, field);
        crate::sensor::RawLinuxProcessIdentity {
            real_group_id: Some(self.identity.real_gid),
            effective_user_id: value(EUID).and_then(|value| u32::try_from(value).ok()),
            effective_group_id: value(EGID).and_then(|value| u32::try_from(value).ok()),
            mount_namespace: value(MOUNT_NS),
            pid_namespace: value(PID_NS),
            network_namespace: value(NET_NS),
            session_id: value(SESSION_ID),
            controlling_tty: value(TTY_MAJOR)
                .zip(value(TTY_MINOR))
                .zip(value(TTY_INDEX))
                .map(|((major, minor), index)| (major, minor, index)),
            kernel_start_boottime: value(START_BOOTTIME),
        }
    }

    fn exec_metadata(&self) -> Option<Box<crate::models::ExecMetadata>> {
        Some(Box::new(crate::models::ExecMetadata {
            real_user_id: Some(self.uid.to_string()),
            ..Default::default()
        }))
    }

    fn effective_uid(&self) -> Option<String> {
        identity_value(self, task_identity_abi::EUID).map(|uid| uid.to_string())
    }

    fn linux_identity(&self) -> Box<crate::models::LinuxProcessIdentity> {
        use task_identity_abi::*;
        let text = |field| identity_value(self, field).map(|value| value.to_string());
        let controlling_tty = identity_value(self, TTY_MAJOR)
            .zip(identity_value(self, TTY_MINOR))
            .zip(identity_value(self, TTY_INDEX))
            .and_then(|((major, minor), index)| {
                minor
                    .checked_add(index)
                    .map(|minor| format!("{major}:{minor}"))
            });
        Box::new(crate::models::LinuxProcessIdentity {
            real_group_id: Some(self.identity.real_gid.to_string()),
            effective_user_id: text(EUID),
            effective_group_id: text(EGID),
            mount_namespace: text(MOUNT_NS),
            pid_namespace: text(PID_NS),
            network_namespace: text(NET_NS),
            session_id: text(SESSION_ID),
            controlling_tty,
            kernel_start_boottime: identity_value(self, START_BOOTTIME),
        })
    }

    fn kernel_command_line(&self) -> Option<String> {
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

fn identity_value(event: &ProcessEvent, field: usize) -> Option<u64> {
    (event.identity.valid & (1 << field) != 0).then_some(event.identity.values[field])
}

/// Userspace-only accessors for [`NetworkEvent`].
pub trait NetworkEventExt {
    /// IP transport name measured from sk_protocol. Unknown protocols and the
    /// syscall fallback remain absent.
    fn transport(&self) -> Option<&'static str>;
}

impl NetworkEventExt for NetworkEvent {
    fn transport(&self) -> Option<&'static str> {
        match self.protocol {
            6 => Some("tcp"),
            17 => Some("udp"),
            _ => None,
        }
    }
}

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
    use crate::models::{FileEventFields, NetworkConnectionFields, ProcessCreationFields};
    use crate::sensor::{
        Platform, ProcessStartKey, RawEvent, RawPayload, RawProcessEvent, SensorAction,
        SensorNormalization,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::super::paths::{resolve_at_path, truncation_marker, DirFdIndex};
    use super::{
        bytes_to_string, BootTimeConverter, DnsEvent, FileEvent, NetworkEvent, NetworkEventExt,
        ProcessEvent, ProcessEventExt,
    };

    const PROVIDER: &str = "ebpf";

    pub fn process_event_to_sensor(event: &ProcessEvent) -> RawEvent {
        let action = match event.kind {
            2 => SensorAction::Stop,
            3 => SensorAction::Fork,
            _ => SensorAction::Start,
        };
        RawEvent {
            process_name: (action == SensorAction::Start)
                .then(|| bytes_to_string(&event.comm))
                .filter(|name| !name.is_empty()),
            provenance: {
                let mut provenance = crate::models::Provenance::default();
                if event.args_truncated != 0 && event.kernel_command_line().is_some() {
                    provenance.mark("CommandLine", crate::models::Fidelity::Truncated);
                }
                provenance
            },
            platform: Platform::Linux,
            provider: PROVIDER,
            action,
            normalization: SensorNormalization {
                event_id: match action {
                    SensorAction::Start => 1,
                    SensorAction::Stop => 5,
                    SensorAction::Fork => 0,
                    _ => unreachable!("process lifecycle action"),
                },
                action_code: event.kind as u8,
            },
            pid: Some(event.pid),
            timestamp: current_timestamp(event.event_time_ns),
            source_seq: Some(event.source_seq),
            process_start_key: process_start_key(event.pid, event.process_start_time),
            parent_process_start_key: process_start_key(
                event.parent_pid,
                event.parent_process_start_time,
            ),
            payload: RawPayload::Process(RawProcessEvent::from_compatibility(
                ProcessCreationFields {
                    hashes: None,
                    imphash: None,
                    container: Default::default(),
                    linux_identity: event.linux_identity(),
                    cgroup_id: (event.cgroup_id != 0).then(|| event.cgroup_id.to_string()),
                    exec: event.exec_metadata(),
                    parent_process_id_derived: event.parent_pid_derived != 0,
                    windows: Default::default(),
                    image: (action == SensorAction::Start).then(|| bytes_to_string(&event.image)),
                    image_source: None,
                    image_truncated: (event.image_truncated != 0).then_some(true),
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
                    parent_process_id: (event.parent_pid != 0)
                        .then(|| event.parent_pid.to_string()),
                    parent_image: None,
                    parent_command_line: None,
                    parent_user: None,
                    current_directory: None,
                    integrity_level: None,
                    user: event.effective_uid(),
                },
                Platform::Linux,
                Some(event.pid),
            )),
        }
    }

    pub fn network_event_to_sensor(event: &NetworkEvent) -> RawEvent {
        RawEvent {
            process_name: None,
            provenance: Default::default(),
            platform: Platform::Linux,
            provider: PROVIDER,
            action: SensorAction::Connect,
            normalization: SensorNormalization {
                event_id: 3,
                action_code: 12,
            },
            pid: Some(event.pid),
            timestamp: current_timestamp(event.event_time_ns),
            source_seq: Some(event.source_seq),
            process_start_key: process_start_key(event.pid, event.process_start_time),
            parent_process_start_key: None,
            payload: RawPayload::Network(NetworkConnectionFields {
                destination_ip: Some(ip_to_string(event.af, &event.daddr)),
                source_ip: (event.tuple_flags & super::super::socket_tuple_abi::TUPLE_MEASURED
                    != 0)
                    .then(|| ip_to_string(event.af, &event.saddr)),
                destination_port: Some(event.dport.to_string()),
                source_port: (event.tuple_flags & super::super::socket_tuple_abi::TUPLE_MEASURED
                    != 0)
                    .then(|| event.sport.to_string()),
                process_id: Some(event.pid.to_string()),
                image: None,
                user: (event.uid != u32::MAX).then(|| event.uid.to_string()),
                destination_hostname: None,
                protocol: event.transport().map(str::to_string),
                initiated: Some(event.tuple_flags & super::super::socket_tuple_abi::INBOUND == 0),
            }),
        }
    }

    /// Map a raw file event, rebuilding both paths from their directory
    /// descriptors.
    ///
    /// `None` when the target path cannot be resolved — see
    /// [`resolve_at_path`] for when that happens and why a raw relative name is
    /// not an acceptable substitute.
    pub fn file_event_to_sensor(index: &DirFdIndex, event: &FileEvent) -> Option<RawEvent> {
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

        Some(RawEvent {
            process_name: Some(bytes_to_string(&event.comm)).filter(|name| !name.is_empty()),
            provenance: {
                let mut provenance = crate::models::Provenance::default();
                if !bytes_to_string(&event.path).starts_with('/') {
                    provenance.mark_derived("TargetFilename");
                }
                if source_filename.is_some() && !bytes_to_string(&event.aux_path).starts_with('/') {
                    provenance.mark_derived("SourceFilename");
                }
                provenance
            },
            platform: Platform::Linux,
            provider: PROVIDER,
            action,
            normalization,
            pid: Some(event.pid),
            timestamp: current_timestamp(event.event_time_ns),
            source_seq: Some(event.source_seq),
            process_start_key: process_start_key(event.pid, event.process_start_time),
            parent_process_start_key: None,
            payload: RawPayload::File(FileEventFields {
                path_truncated: truncation_marker(event.flags, source_filename.is_some())
                    .map(str::to_string),
                source_filename,
                target_filename: Some(target_filename),
                process_id: Some(event.pid.to_string()),
                // `comm` is a short process name, not an executable path.
                image: None,
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: (event.uid != u32::MAX).then(|| event.uid.to_string()),
                file_identity: crate::utils::file_identity::from_linux_event(
                    event.device,
                    event.inode,
                ),
            }),
        })
    }

    /// Decode a raw DNS message. `None` when the question does not parse.
    pub fn dns_event_to_sensor(event: &DnsEvent) -> Option<RawEvent> {
        super::super::ebpf::build_dns_event(event)
    }

    fn ip_to_string(af: u16, bytes: &[u8; 16]) -> String {
        match af {
            10 => Ipv6Addr::from(*bytes).to_string(),
            _ => Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        }
    }

    fn process_start_key(pid: u32, start_time: u64) -> Option<ProcessStartKey> {
        (start_time != 0).then_some(ProcessStartKey { pid, start_time })
    }

    fn current_timestamp(event_time_ns: u64) -> std::time::SystemTime {
        BootTimeConverter::capture().system_time(event_time_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::sensor::SensorAction;

    #[test]
    fn parse_event_rejects_short_reads() {
        let raw = [0u8; 12];
        assert!(parse_event::<FileEvent>(&raw).is_none());
        assert!(parse_event::<DnsEvent>(&raw).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn boot_clock_conversion_preserves_kernel_event_deltas() {
        let converter = BootTimeConverter::capture();
        let earlier = converter.system_time(1_000_000_000);
        let later = converter.system_time(1_123_456_789);

        assert_eq!(
            later.duration_since(earlier).expect("time moves forward"),
            std::time::Duration::from_nanos(123_456_789)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refreshed_boot_clock_conversion_tracks_realtime_steps() {
        let boottime = std::time::Duration::from_secs(2 * 60 * 60);
        let event_boottime_ns = 2 * 60 * 60 * 1_000_000_000;
        let mut converter = BootTimeConverter::from_clock_samples(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10 * 60 * 60),
            boottime,
        );
        let before_step = converter.system_time(event_boottime_ns);

        converter.refresh_from_clock_samples(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(11 * 60 * 60),
            boottime,
        );

        assert_eq!(
            converter
                .system_time(event_boottime_ns)
                .duration_since(before_step)
                .expect("a forward clock step moves converted event time forward"),
            std::time::Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn process_event_round_trips_kernel_argv_through_raw_bytes() {
        let mut event = ProcessEvent {
            identity: Default::default(),
            event_time_ns: 0,
            source_seq: 0,
            cgroup_id: 55,
            process_start_time: 123_456,
            parent_process_start_time: 111_222,
            kind: 1,
            pid: 4242,
            uid: 1000,
            parent_pid: 4000,
            creator_tid: 4001,
            creator_tgid: 4000,
            comm: [0u8; 16],
            image: [0u8; PROCESS_IMAGE_CAPACITY],
            args_len: 0,
            args_count: 0,
            args_truncated: 0,
            image_truncated: 0,
            parent_pid_derived: 0,
            _pad1: 0,
            args: [0u8; ARGV_CAPACITY],
        };
        let argv = b"/bin/true\0--quiet\0";
        event.args[..argv.len()].copy_from_slice(argv);
        event.args_len = argv.len() as u16;
        event.args_count = 2;

        // Same path the ring-buffer drain takes: raw bytes in, struct out.
        // SAFETY: `event` is a live, fully initialized repr(C) ProcessEvent, so
        // viewing its `size_of` bytes is in bounds. The layout carries explicit
        // padding fields, so no byte is uninitialized.
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

    #[cfg(target_os = "linux")]
    #[test]
    fn process_exit_mapping_does_not_allocate_an_unobservable_name() {
        let mut event = ProcessEvent {
            identity: Default::default(),
            event_time_ns: 0,
            source_seq: 0,
            cgroup_id: 0,
            process_start_time: 123_456,
            parent_process_start_time: 0,
            kind: 2,
            pid: 4242,
            uid: 1000,
            parent_pid: 0,
            creator_tid: 0,
            creator_tgid: 0,
            comm: [0u8; 16],
            image: [0u8; PROCESS_IMAGE_CAPACITY],
            args_len: 0,
            args_count: 0,
            args_truncated: 0,
            image_truncated: 0,
            parent_pid_derived: 0,
            _pad1: 0,
            args: [0u8; ARGV_CAPACITY],
        };
        event.comm[..4].copy_from_slice(b"bash");

        let mapped = mapping::process_event_to_sensor(&event);
        assert_eq!(mapped.action, SensorAction::Stop);
        assert!(mapped.process_name.is_none());
    }

    #[test]
    fn transport_names_only_known_ip_protocols() {
        let mut event = NetworkEvent {
            event_time_ns: 0,
            source_seq: 0,
            pid: 42,
            uid: 1000,
            fd: 3,
            ret: 0,
            dport: 53,
            sport: 0,
            af: 2,
            protocol: 17,
            tuple_flags: 0,
            daddr: [0u8; 16],
            saddr: [0u8; 16],
            process_start_time: 123_456,
        };
        assert_eq!(event.transport(), Some("udp"));

        event.protocol = 6;
        assert_eq!(event.transport(), Some("tcp"));

        // An unmeasured protocol, and a protocol with no name here,
        // are both absent rather than guessed as `tcp`.
        event.protocol = 0;
        assert_eq!(event.transport(), None);
        event.protocol = 132; // SCTP
        assert_eq!(event.transport(), None);
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
