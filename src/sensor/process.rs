//! Platform-native process facts carried across the raw sensor boundary.
//!
//! Process is the first migrated category.  Values which the source reports as
//! numbers remain numbers here; conversion to the string-valued compatibility
//! view happens only after [`HostState`](crate::state::HostState) has accepted
//! the event.

use crate::models::{
    ExecMetadata, LinuxProcessIdentity, ProcessCreationFields, WindowsProcessMetadata,
};

/// Identity reported for the process subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawUserId {
    /// Numeric Unix user ID.
    Unix(u32),
    /// Authoritative Windows SID.
    WindowsSid(String),
    /// A source-provided account name.
    Name(String),
}

impl RawUserId {
    pub(crate) fn compatibility_value(&self) -> String {
        match self {
            Self::Unix(uid) => uid.to_string(),
            Self::WindowsSid(sid) | Self::Name(sid) => sid.clone(),
        }
    }
}

/// Numeric Linux task identity captured with the event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawLinuxProcessIdentity {
    pub real_group_id: Option<u32>,
    pub effective_user_id: Option<u32>,
    pub effective_group_id: Option<u32>,
    pub mount_namespace: Option<u64>,
    pub pid_namespace: Option<u64>,
    pub network_namespace: Option<u64>,
    pub session_id: Option<u64>,
    /// `(major, minor, index)` as supplied by the kernel task identity plan.
    pub controlling_tty: Option<(u64, u64, u64)>,
    pub kernel_start_boottime: Option<u64>,
}

/// Linux-only facts attached to a raw process event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLinuxProcess {
    pub real_user_id: Option<u32>,
    pub identity: RawLinuxProcessIdentity,
    pub cgroup_id: Option<u64>,
    pub image_source: Option<String>,
    pub image_truncated: Option<bool>,
    pub parent_process_id_derived: bool,
}

/// Native macOS exec metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawMacOsExec {
    pub signed: Option<bool>,
    pub pre_exec_image: Option<String>,
    pub real_user_id: Option<u32>,
    pub script: Option<String>,
    pub signature_status: Option<String>,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub cdhash: Option<String>,
    pub codesigning_flags: Option<u32>,
    pub is_platform_binary: Option<bool>,
    pub(crate) file_identity: Option<crate::utils::file_identity::FileIdentity>,
}

/// macOS-only facts attached to a raw process event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawMacOsProcess {
    pub exec: Option<Box<RawMacOsExec>>,
    pub parent_process_id_derived: bool,
}

/// Windows creation-source evidence before host enrichment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawWindowsProcess {
    pub correlation_pending: bool,
    pub command_line_source: Option<String>,
    pub conflicting_live_command_line: Option<String>,
    pub classic_command_line: Option<String>,
    pub command_line_may_be_truncated: bool,
    pub user_sid: Option<String>,
    pub session_id: Option<u32>,
}

/// Platform-specific portion of a raw process record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawProcessPlatform {
    Linux(RawLinuxProcess),
    Windows(RawWindowsProcess),
    MacOS(RawMacOsProcess),
}

/// Process facts emitted by sensors.
///
/// Field names describe their meaning rather than a compatibility schema.  In
/// particular process IDs, user IDs, namespace IDs, cgroup IDs, session IDs,
/// and code-signing flags do not pass through `Option<String>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProcessEvent {
    pub process_id: u32,
    pub parent_process_id: Option<u32>,
    pub process_start_time: Option<u64>,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub parent_image: Option<String>,
    pub parent_command_line: Option<String>,
    pub current_directory: Option<String>,
    pub integrity_level: Option<String>,
    pub user: Option<RawUserId>,
    /// Source-populated compatibility metadata. Sensors leave these absent
    /// unless the native source itself supplied them; host enrichment may add
    /// them only after this raw value has crossed the channel.
    pub original_file_name: Option<String>,
    pub product: Option<String>,
    pub description: Option<String>,
    pub company: Option<String>,
    pub file_version: Option<String>,
    pub target_image: Option<String>,
    pub platform: Box<RawProcessPlatform>,
}

impl RawProcessEvent {
    /// Convert raw facts into the existing Sysmon-shaped generated view input.
    pub fn compatibility_fields(&self) -> ProcessCreationFields {
        let (
            linux_identity,
            cgroup_id,
            exec,
            image_source,
            image_truncated,
            parent_derived,
            windows,
        ) = match self.platform.as_ref() {
            RawProcessPlatform::Linux(source) => {
                let tty = source
                    .identity
                    .controlling_tty
                    .and_then(|(major, minor, index)| {
                        minor
                            .checked_add(index)
                            .map(|minor| format!("{major}:{minor}"))
                    });
                (
                    Box::new(LinuxProcessIdentity {
                        real_group_id: source.identity.real_group_id.map(|value| value.to_string()),
                        effective_user_id: source
                            .identity
                            .effective_user_id
                            .map(|value| value.to_string()),
                        effective_group_id: source
                            .identity
                            .effective_group_id
                            .map(|value| value.to_string()),
                        mount_namespace: source
                            .identity
                            .mount_namespace
                            .map(|value| value.to_string()),
                        pid_namespace: source.identity.pid_namespace.map(|value| value.to_string()),
                        network_namespace: source
                            .identity
                            .network_namespace
                            .map(|value| value.to_string()),
                        session_id: source.identity.session_id.map(|value| value.to_string()),
                        controlling_tty: tty,
                        kernel_start_boottime: source.identity.kernel_start_boottime,
                    }),
                    source.cgroup_id.map(|value| value.to_string()),
                    source.real_user_id.map(|value| {
                        Box::new(ExecMetadata {
                            real_user_id: Some(value.to_string()),
                            ..Default::default()
                        })
                    }),
                    source.image_source.clone(),
                    source.image_truncated,
                    source.parent_process_id_derived,
                    None,
                )
            }
            RawProcessPlatform::Windows(source) => (
                Default::default(),
                None,
                None,
                None,
                None,
                false,
                Some(Box::new(WindowsProcessMetadata {
                    command_line_source: source.command_line_source.clone(),
                    conflicting_live_command_line: source.conflicting_live_command_line.clone(),
                    classic_command_line: source.classic_command_line.clone(),
                    command_line_may_be_truncated: source.command_line_may_be_truncated,
                    user_sid: source.user_sid.clone(),
                    session_id: source.session_id,
                })),
            ),
            RawProcessPlatform::MacOS(source) => (
                Default::default(),
                None,
                source.exec.as_ref().map(|metadata| {
                    Box::new(ExecMetadata {
                        signed: metadata.signed.map(|value| value.to_string()),
                        pre_exec_image: metadata.pre_exec_image.clone(),
                        real_user_id: metadata.real_user_id.map(|value| value.to_string()),
                        script: metadata.script.clone(),
                        signature_status: metadata.signature_status.clone(),
                        signing_id: metadata.signing_id.clone(),
                        team_id: metadata.team_id.clone(),
                        cdhash: metadata.cdhash.clone(),
                        codesigning_flags: metadata
                            .codesigning_flags
                            .map(|value| value.to_string()),
                        is_platform_binary: metadata.is_platform_binary,
                        file_identity: metadata.file_identity.clone(),
                    })
                }),
                None,
                None,
                source.parent_process_id_derived,
                None,
            ),
        };

        ProcessCreationFields {
            linux_identity,
            cgroup_id,
            exec,
            parent_process_id_derived: parent_derived,
            windows,
            image: self.image.clone(),
            image_source,
            image_truncated,
            original_file_name: self.original_file_name.clone(),
            product: self.product.clone(),
            description: self.description.clone(),
            company: self.company.clone(),
            file_version: self.file_version.clone(),
            target_image: self.target_image.clone(),
            command_line: self.command_line.clone(),
            process_id: Some(self.process_id.to_string()),
            process_start_time: self.process_start_time,
            parent_process_id: self.parent_process_id.map(|value| value.to_string()),
            parent_image: self.parent_image.clone(),
            parent_command_line: self.parent_command_line.clone(),
            current_directory: self.current_directory.clone(),
            integrity_level: self.integrity_level.clone(),
            user: self.user.as_ref().map(RawUserId::compatibility_value),
        }
    }

    /// Compatibility constructor for synthetic and not-yet-migrated producers.
    /// Platform sensors use the typed constructors at their decode sites.
    pub fn from_compatibility(
        fields: ProcessCreationFields,
        platform: crate::sensor::Platform,
        fallback_pid: Option<u32>,
    ) -> Self {
        let process_id = fields
            .process_id
            .as_deref()
            .and_then(|value| value.parse().ok())
            .or(fallback_pid)
            .unwrap_or(0);
        let parent_process_id = fields
            .parent_process_id
            .as_deref()
            .and_then(|value| value.parse().ok());
        let user = fields.user.as_ref().map(|value| match platform {
            crate::sensor::Platform::Linux | crate::sensor::Platform::MacOS => value
                .parse()
                .map(RawUserId::Unix)
                .unwrap_or_else(|_| RawUserId::Name(value.clone())),
            crate::sensor::Platform::Windows if value.starts_with("S-1-") => {
                RawUserId::WindowsSid(value.clone())
            }
            crate::sensor::Platform::Windows => RawUserId::Name(value.clone()),
        });

        let raw_platform = match platform {
            crate::sensor::Platform::Linux => {
                let parse_u32 = |value: Option<&String>| value.and_then(|value| value.parse().ok());
                let parse_u64 = |value: Option<&String>| value.and_then(|value| value.parse().ok());
                RawProcessPlatform::Linux(RawLinuxProcess {
                    real_user_id: fields
                        .exec
                        .as_ref()
                        .and_then(|metadata| metadata.real_user_id.as_deref())
                        .and_then(|value| value.parse().ok()),
                    identity: RawLinuxProcessIdentity {
                        real_group_id: fields
                            .linux_identity
                            .real_group_id
                            .as_deref()
                            .and_then(|value| value.parse().ok()),
                        effective_user_id: parse_u32(
                            fields.linux_identity.effective_user_id.as_ref(),
                        ),
                        effective_group_id: parse_u32(
                            fields.linux_identity.effective_group_id.as_ref(),
                        ),
                        mount_namespace: parse_u64(fields.linux_identity.mount_namespace.as_ref()),
                        pid_namespace: parse_u64(fields.linux_identity.pid_namespace.as_ref()),
                        network_namespace: parse_u64(
                            fields.linux_identity.network_namespace.as_ref(),
                        ),
                        session_id: parse_u64(fields.linux_identity.session_id.as_ref()),
                        // Compatibility-only input has already combined minor and index;
                        // retaining the rendered minor with a zero index round-trips it.
                        controlling_tty: fields
                            .linux_identity
                            .controlling_tty
                            .as_deref()
                            .and_then(|value| value.split_once(':'))
                            .and_then(|(major, minor)| {
                                Some((major.parse().ok()?, minor.parse().ok()?, 0))
                            }),
                        kernel_start_boottime: fields.linux_identity.kernel_start_boottime,
                    },
                    cgroup_id: fields
                        .cgroup_id
                        .as_deref()
                        .and_then(|value| value.parse().ok()),
                    image_source: fields.image_source.clone(),
                    image_truncated: fields.image_truncated,
                    parent_process_id_derived: fields.parent_process_id_derived,
                })
            }
            crate::sensor::Platform::Windows => {
                let source = fields.windows.as_deref().cloned().unwrap_or_default();
                RawProcessPlatform::Windows(RawWindowsProcess {
                    correlation_pending: false,
                    command_line_source: source.command_line_source,
                    conflicting_live_command_line: source.conflicting_live_command_line,
                    classic_command_line: source.classic_command_line,
                    command_line_may_be_truncated: source.command_line_may_be_truncated,
                    user_sid: source.user_sid,
                    session_id: source.session_id,
                })
            }
            crate::sensor::Platform::MacOS => {
                let exec = fields.exec.as_ref().map(|metadata| {
                    Box::new(RawMacOsExec {
                        signed: metadata
                            .signed
                            .as_deref()
                            .and_then(|value| value.parse().ok()),
                        pre_exec_image: metadata.pre_exec_image.clone(),
                        real_user_id: metadata
                            .real_user_id
                            .as_deref()
                            .and_then(|value| value.parse().ok()),
                        script: metadata.script.clone(),
                        signature_status: metadata.signature_status.clone(),
                        signing_id: metadata.signing_id.clone(),
                        team_id: metadata.team_id.clone(),
                        cdhash: metadata.cdhash.clone(),
                        codesigning_flags: metadata
                            .codesigning_flags
                            .as_deref()
                            .and_then(|value| value.parse().ok()),
                        is_platform_binary: metadata.is_platform_binary,
                        file_identity: metadata.file_identity.clone(),
                    })
                });
                RawProcessPlatform::MacOS(RawMacOsProcess {
                    exec,
                    parent_process_id_derived: fields.parent_process_id_derived,
                })
            }
        };

        Self {
            process_id,
            parent_process_id,
            process_start_time: fields.process_start_time,
            image: fields.image,
            command_line: fields.command_line,
            parent_image: fields.parent_image,
            parent_command_line: fields.parent_command_line,
            current_directory: fields.current_directory,
            integrity_level: fields.integrity_level,
            user,
            original_file_name: fields.original_file_name,
            product: fields.product,
            description: fields.description,
            company: fields.company,
            file_version: fields.file_version,
            target_image: fields.target_image,
            platform: Box::new(raw_platform),
        }
    }

    #[cfg(all(test, windows))]
    pub(crate) fn windows(&self) -> Option<&RawWindowsProcess> {
        match self.platform.as_ref() {
            RawProcessPlatform::Windows(source) => Some(source),
            _ => None,
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn windows_mut(&mut self) -> Option<&mut RawWindowsProcess> {
        match self.platform.as_mut() {
            RawProcessPlatform::Windows(source) => Some(source),
            _ => None,
        }
    }
}
