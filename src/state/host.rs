//! Shared ownership, entry limits, and raw-to-canonical host enrichment.
use super::{DnsCache, ProcessCache, SidCache};
use crate::models::{CanonicalEvent, NormalizedEvent};
use crate::normalizer::Normalizer;
use crate::sensor::{RawEvent, RawPayload};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// Entry ceilings, including auxiliary indexes. Variable-sized metadata is
/// bounded by the collectors; these ceilings bound retained rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateLimits {
    pub processes: usize,
    pub users: usize,
    pub dns: usize,
    pub paths: usize,
}
impl Default for StateLimits {
    fn default() -> Self {
        Self {
            processes: 65_536,
            users: 4096,
            dns: 10_000,
            paths: 8192,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySnapshot {
    pub scanned: usize,
    pub seeded: usize,
    pub skipped: usize,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostStateSnapshot {
    pub limits: StateLimits,
    pub processes: usize,
    pub retired_processes: usize,
    pub process_identities: usize,
    pub users: usize,
    pub dns: usize,
    pub paths: usize,
    pub attribution_loss: u64,
    pub inventory: Option<InventorySnapshot>,
}

pub struct HostState {
    pub processes: Arc<ProcessCache>,
    pub users: Arc<SidCache>,
    pub dns: Arc<DnsCache>,
    #[cfg(target_os = "linux")]
    pub(crate) dir_fds: Mutex<crate::sensor::linux::paths::DirFdIndex>,
    /// Built on the first Linux process event, so hosts and tests that never
    /// see one never read mountinfo.
    #[cfg(target_os = "linux")]
    pub(crate) containers: std::sync::OnceLock<Mutex<super::container::ContainerResolver>>,
    #[cfg(windows)]
    pub(crate) file_paths: Mutex<crate::sensor::windows::file_paths::FilePathCache>,
    #[cfg(windows)]
    pub(crate) registry_paths: Mutex<crate::sensor::windows::registry_paths::RegistryPathCache>,
    #[cfg(windows)]
    pub(crate) process_identities: Mutex<crate::sensor::windows::etw::state::ProcessIdentityIndex>,
    limits: StateLimits,
    inventory: Mutex<Option<InventorySnapshot>>,
    attribution_loss: AtomicU64,
    pub(crate) ingest_seq: AtomicU64,
}
static ACTIVE: LazyLock<Mutex<Weak<HostState>>> = LazyLock::new(|| Mutex::new(Weak::new()));
pub fn active_snapshot() -> Option<HostStateSnapshot> {
    ACTIVE
        .lock()
        .unwrap()
        .upgrade()
        .map(|state| state.snapshot())
}
impl HostState {
    pub fn new(mut limits: StateLimits) -> Self {
        limits.users = limits.users.max(3);
        limits.paths = limits.paths.max(1);
        Self {
            processes: Arc::new(ProcessCache::with_max_entries(limits.processes)),
            users: Arc::new(SidCache::with_max_entries(limits.users)),
            dns: Arc::new(DnsCache::with_limits(limits.dns, 15 * 60)),
            #[cfg(target_os = "linux")]
            dir_fds: Mutex::new(crate::sensor::linux::paths::DirFdIndex::with_capacity(
                limits.paths,
            )),
            #[cfg(target_os = "linux")]
            containers: std::sync::OnceLock::new(),
            #[cfg(windows)]
            file_paths: Mutex::new(
                crate::sensor::windows::file_paths::FilePathCache::with_capacity(limits.paths),
            ),
            #[cfg(windows)]
            registry_paths: Mutex::new(
                crate::sensor::windows::registry_paths::RegistryPathCache::with_capacity(
                    limits.paths,
                ),
            ),
            #[cfg(windows)]
            process_identities: Mutex::new(
                crate::sensor::windows::etw::state::ProcessIdentityIndex::with_max_entries(
                    limits.processes,
                ),
            ),
            limits,
            inventory: Mutex::new(None),
            attribution_loss: AtomicU64::new(0),
            ingest_seq: AtomicU64::new(0),
        }
    }
    pub fn for_runtime(max_processes: usize) -> Arc<Self> {
        let state = Arc::new(Self::new(StateLimits {
            processes: max_processes,
            ..Default::default()
        }));
        *ACTIVE.lock().unwrap() = Arc::downgrade(&state);
        #[cfg(target_os = "macos")]
        state.inventory_macos();
        state
    }
    /// Resolve the cgroup path and container of a Linux process event.
    #[cfg(target_os = "linux")]
    pub(crate) fn resolve_container(
        &self,
        pid: u32,
        parent_pid: Option<u32>,
        cgroup_id: Option<u64>,
    ) -> super::container::ContainerResolution {
        self.containers
            .get_or_init(|| Mutex::new(super::container::ContainerResolver::for_host()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .resolve(pid, parent_pid, cgroup_id)
    }
    pub fn limits(&self) -> &StateLimits {
        &self.limits
    }
    pub fn record_attribution_loss(&self) {
        self.attribution_loss.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_inventory(&self, snapshot: InventorySnapshot) {
        tracing::info!(scanned=snapshot.scanned, seeded=snapshot.seeded, skipped=snapshot.skipped,
            duration_ms=snapshot.duration_ms, error=?snapshot.error, "Startup process inventory");
        *self.inventory.lock().unwrap() = Some(snapshot);
    }
    pub fn snapshot(&self) -> HostStateSnapshot {
        let paths = 0;
        #[cfg(target_os = "linux")]
        let paths = paths + self.dir_fds.lock().unwrap_or_else(|e| e.into_inner()).len();
        #[cfg(windows)]
        let paths = paths
            + self
                .file_paths
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retained_count()
            + self
                .registry_paths
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retained_count();
        let process_identities = 0;
        #[cfg(windows)]
        let process_identities = process_identities
            + self
                .process_identities
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .count();
        HostStateSnapshot {
            process_identities,
            limits: self.limits.clone(),
            processes: self.processes.count(),
            retired_processes: self.processes.retired_count(),
            users: self.users.count(),
            dns: self.dns.count(),
            paths,
            attribution_loss: self.attribution_loss.load(Ordering::Relaxed),
            inventory: self.inventory.lock().unwrap().clone(),
        }
    }
}
impl Default for HostState {
    fn default() -> Self {
        Self::new(StateLimits::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn linux_process(
        image: &str,
        command_line: &str,
        start_ticks: u64,
    ) -> crate::sensor::RawProcessEvent {
        use crate::sensor::{
            RawLinuxProcess, RawLinuxProcessIdentity, RawProcessEvent, RawProcessPlatform,
        };

        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        assert!(hz > 0);
        let hz = hz as u64;
        let start_ns =
            u64::try_from((u128::from(start_ticks) * 1_000_000_000_u128).div_ceil(u128::from(hz)))
                .unwrap();
        RawProcessEvent {
            process_id: 42,
            parent_process_id: None,
            process_start_time: None,
            image: Some(image.to_string()),
            command_line: Some(command_line.to_string()),
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            platform: Box::new(RawProcessPlatform::Linux(RawLinuxProcess {
                real_user_id: None,
                identity: RawLinuxProcessIdentity {
                    kernel_start_boottime: Some(start_ns),
                    ..Default::default()
                },
                cgroup_id: None,
                image_source: Some("execve".to_string()),
                image_truncated: None,
                parent_process_id_derived: false,
            })),
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_details(start_time: u64) -> crate::utils::process::ProcessDetails {
        crate::utils::process::ProcessDetails {
            image: Some("/tmp/payload".to_string()),
            command_line: Some("payload --probe".to_string()),
            current_directory: Some("/tmp".to_string()),
            start_time: Some(start_time),
            ..Default::default()
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_paths_are_derived_without_rewriting_command_line() {
        let mut process = linux_process("payload", "payload --probe", 100);
        let mut provenance = crate::models::Provenance::default();

        enrich_linux_process_from_details(
            &mut process,
            &mut provenance,
            linux_details(100),
            Some(crate::sensor::ProcessStartKey {
                pid: 42,
                start_time: 900,
            }),
        );

        assert_eq!(process.image.as_deref(), Some("/tmp/payload"));
        assert_eq!(process.current_directory.as_deref(), Some("/tmp"));
        assert_eq!(process.command_line.as_deref(), Some("payload --probe"));
        let crate::sensor::RawProcessPlatform::Linux(source) = process.platform.as_ref() else {
            unreachable!()
        };
        assert_eq!(source.image_source.as_deref(), Some("proc"));
        assert!(provenance.has("Image", crate::models::Fidelity::Derived));
        assert!(provenance.has("CurrentDirectory", crate::models::Fidelity::Derived));
        assert!(!provenance.has("CommandLine", crate::models::Fidelity::Derived));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_identity_mismatch_leaves_derived_paths_absent() {
        let mut process = linux_process("payload", "payload --probe", 100);
        let mut provenance = crate::models::Provenance::default();

        enrich_linux_process_from_details(
            &mut process,
            &mut provenance,
            linux_details(101),
            Some(crate::sensor::ProcessStartKey {
                pid: 42,
                start_time: 900,
            }),
        );

        assert_eq!(process.image.as_deref(), Some("payload"));
        assert!(process.current_directory.is_none());
        let crate::sensor::RawProcessPlatform::Linux(source) = process.platform.as_ref() else {
            unreachable!()
        };
        assert_eq!(source.image_source.as_deref(), Some("execve"));
        assert!(provenance.is_empty());
    }

    #[test]
    fn snapshot_reports_inventory_and_bounded_state() {
        let state = HostState::new(StateLimits {
            processes: 2,
            users: 5,
            dns: 1,
            paths: 1,
        });
        state
            .dns
            .update("192.0.2.1".parse().unwrap(), "one.test".into());
        state
            .dns
            .update("192.0.2.2".parse().unwrap(), "two.test".into());
        state.record_inventory(InventorySnapshot {
            scanned: 3,
            seeded: 2,
            skipped: 1,
            duration_ms: 10,
            error: None,
        });
        state.record_attribution_loss();
        #[cfg(target_os = "linux")]
        {
            let mut paths = state.dir_fds.lock().unwrap();
            paths.insert(42, 3, 100, "/tmp/one".into());
            paths.insert(42, 4, 101, "/tmp/two".into());
        }
        let snapshot = state.snapshot();
        assert!(snapshot.dns <= 1);
        assert_eq!(snapshot.attribution_loss, 1);
        assert_eq!(snapshot.inventory.unwrap().seeded, 2);
        #[cfg(target_os = "linux")]
        assert_eq!(snapshot.paths, 1);
    }
}

impl HostState {
    /// Enrich one raw event and create the semantic cross-platform boundary.
    pub fn canonicalize(&self, mut event: RawEvent) -> Option<CanonicalEvent> {
        self.enrich(&mut event);
        let normalized = Normalizer::new(self).normalize(&event)?;
        let pid = match &event.payload {
            RawPayload::Process(process) => Some(process.process_id),
            _ => event.pid,
        };
        Some(CanonicalEvent::new(
            normalized,
            event.action,
            pid,
            event.process_start_key,
            event.parent_process_start_key,
        ))
    }

    /// Attach live-only process context after a detector has selected an alert.
    pub fn enrich_process_context(
        &self,
        event: &mut NormalizedEvent,
        process_start_key: Option<crate::sensor::ProcessStartKey>,
    ) {
        Normalizer::new(self).enrich_process_context(event, process_start_key);
    }

    fn enrich(&self, event: &mut RawEvent) {
        #[cfg(target_os = "linux")]
        {
            enrich_linux_process(event);
        }

        #[cfg(windows)]
        {
            enrich_windows_process(event);
        }

        #[cfg(not(any(target_os = "linux", windows)))]
        let _ = event;
    }
}

#[cfg(target_os = "linux")]
fn enrich_linux_process(event: &mut RawEvent) {
    use crate::utils::query_process_details;

    if event.platform != crate::sensor::Platform::Linux
        || event.action != crate::sensor::SensorAction::Start
    {
        return;
    }
    let RawPayload::Process(process) = &mut event.payload else {
        return;
    };
    let Some(details) = query_process_details(process.process_id) else {
        return;
    };
    enrich_linux_process_from_details(
        process,
        &mut event.provenance,
        details,
        event.process_start_key,
    );
}

#[cfg(target_os = "linux")]
fn enrich_linux_process_from_details(
    process: &mut crate::sensor::RawProcessEvent,
    provenance: &mut crate::models::Provenance,
    details: crate::utils::process::ProcessDetails,
    process_start_key: Option<crate::sensor::ProcessStartKey>,
) {
    use crate::sensor::RawProcessPlatform;
    use crate::utils::{hash_command_line, ProcessIdentity};
    use std::path::{Path, PathBuf};

    let RawProcessPlatform::Linux(source) = process.platform.as_ref() else {
        return;
    };
    let Some(raw_image) = process.image.as_deref() else {
        return;
    };
    let Some(current_image) = details.image.as_deref() else {
        return;
    };
    let Some(expected_start) = source
        .identity
        .kernel_start_boottime
        .and_then(crate::utils::process::linux_boot_time_ns_to_start_ticks)
    else {
        return;
    };
    if process_start_key.is_none_or(|key| key.pid != process.process_id) {
        return;
    }

    let expected_image = if Path::new(raw_image).is_absolute() {
        PathBuf::from(raw_image)
    } else {
        let Some(cwd) = details.current_directory.as_deref() else {
            return;
        };
        if !Path::new(cwd).is_absolute() {
            return;
        }
        Path::new(cwd).join(raw_image)
    };
    let command_line_hash = if provenance.has("CommandLine", crate::models::Fidelity::Truncated) {
        None
    } else {
        process.command_line.as_deref().map(hash_command_line)
    };
    let expected = ProcessIdentity {
        pid: process.process_id,
        image: expected_image.to_string_lossy().into_owned(),
        start_time: Some(expected_start),
        command_line_hash,
    };
    let current = ProcessIdentity {
        pid: process.process_id,
        image: current_image.to_string(),
        start_time: details.start_time,
        command_line_hash: details.command_line.as_deref().map(hash_command_line),
    };
    if expected.matches(&current).is_err() {
        return;
    }

    if !Path::new(raw_image).is_absolute() {
        process.image = Some(current.image);
        if let RawProcessPlatform::Linux(source) = process.platform.as_mut() {
            source.image_source = Some("proc".to_string());
        }
        provenance.mark_derived("Image");
    }
    if process.current_directory.is_none() {
        process.current_directory = details.current_directory;
        if process.current_directory.is_some() {
            provenance.mark_derived("CurrentDirectory");
        }
    }
}

#[cfg(windows)]
fn enrich_windows_process(event: &mut RawEvent) {
    if event.platform != crate::sensor::Platform::Windows {
        return;
    }
    let RawPayload::Process(process) = &mut event.payload else {
        return;
    };
    for value in [&mut process.image, &mut process.parent_image]
        .into_iter()
        .flatten()
    {
        *value = crate::utils::convert_nt_to_dos(value);
    }
    if event.action != SensorAction::Start {
        return;
    }
    let live = event.process_start_key.and_then(|key| {
        crate::utils::query_process_command_line_at_start(process.process_id, key.start_time)
    });
    enrich_windows_command_line(process, live);
}

#[cfg(any(windows, test))]
pub(crate) fn enrich_windows_command_line(
    process: &mut crate::sensor::RawProcessEvent,
    live: Option<String>,
) {
    let crate::sensor::RawProcessPlatform::Windows(source) = process.platform.as_mut() else {
        return;
    };
    let correlated = std::mem::take(&mut source.correlation_pending);
    let mut conflicting = false;
    if let Some(live) = live {
        match process.command_line.as_ref() {
            None => {
                process.command_line = Some(live);
                source.command_line_source = Some("live_query".into());
            }
            Some(captured)
                if source.command_line_may_be_truncated
                    && live.len() > captured.len()
                    && live.starts_with(captured) =>
            {
                source.classic_command_line = Some(captured.clone());
                process.command_line = Some(live);
                source.command_line_source = Some("live_query".into());
            }
            Some(captured) if captured != &live => {
                source.conflicting_live_command_line = Some(live);
                conflicting = true;
            }
            Some(_) => {}
        }
    }
    if correlated {
        let metrics = &crate::telemetry::WINDOWS_PROCESS_CORRELATION;
        let counter = if conflicting {
            tracing::warn!(
                pid = process.process_id,
                "Classic command line differs from live-query value"
            );
            &metrics.conflicting
        } else {
            &metrics.matched
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod canonicalization_tests {
    use super::*;
    use crate::models::EventFields;
    use crate::sensor::{
        Platform, RawLinuxProcess, RawLinuxProcessIdentity, RawPayload, RawProcessEvent,
        RawProcessPlatform, RawUserId, SensorAction, SensorNormalization,
    };
    use std::time::SystemTime;

    fn state() -> Arc<HostState> {
        Arc::new(HostState::default())
    }

    #[test]
    fn windows_live_command_line_preserves_capture_and_recovers_only_truncated_prefixes() {
        for (captured, live, truncated, expected, conflict) in [
            ("captured", Some("changed"), false, "captured", true),
            ("captured", Some("captured"), false, "captured", false),
            ("captured", None, false, "captured", false),
            (
                "prefix",
                Some("prefix suffix"),
                true,
                "prefix suffix",
                false,
            ),
            ("prefix", Some("prefix suffix"), false, "prefix", true),
        ] {
            let mut process = RawProcessEvent::from_compatibility(
                serde_json::from_value(serde_json::json!({"ProcessId": "42"})).unwrap(),
                Platform::Windows,
                Some(42),
            );
            process.command_line = Some(captured.into());
            let source = process.windows_mut().unwrap();
            source.command_line_source = Some("classic".into());
            source.command_line_may_be_truncated = truncated;
            source.correlation_pending = true;
            enrich_windows_command_line(&mut process, live.map(String::from));
            assert_eq!(process.command_line.as_deref(), Some(expected));
            let source = process.windows_mut().unwrap();
            assert!(!source.correlation_pending);
            assert_eq!(source.conflicting_live_command_line.is_some(), conflict);
            assert_eq!(
                source.classic_command_line.as_deref(),
                (expected != captured).then_some(captured)
            );
        }
    }

    #[test]
    fn numeric_raw_process_facts_are_rendered_only_after_host_state() {
        let raw = RawEvent {
            process_name: None,
            provenance: Default::default(),
            platform: Platform::Linux,
            provider: "ebpf",
            action: SensorAction::Start,
            normalization: SensorNormalization {
                event_id: 1,
                action_code: 1,
            },
            pid: Some(42),
            timestamp: SystemTime::UNIX_EPOCH,
            source_seq: Some(7),
            process_start_key: None,
            parent_process_start_key: None,
            payload: RawPayload::Process(RawProcessEvent {
                process_id: 42,
                parent_process_id: Some(7),
                process_start_time: None,
                image: Some("/usr/bin/true".into()),
                command_line: Some("/usr/bin/true".into()),
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some(RawUserId::Unix(u32::MAX)),
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                platform: Box::new(RawProcessPlatform::Linux(RawLinuxProcess {
                    real_user_id: Some(u32::MAX),
                    identity: RawLinuxProcessIdentity {
                        real_group_id: Some(u32::MAX),
                        ..Default::default()
                    },
                    cgroup_id: Some(99),
                    image_source: Some("execve".into()),
                    image_truncated: None,
                    parent_process_id_derived: false,
                })),
            }),
        };

        let host = state();
        let first = host
            .canonicalize(raw.clone())
            .expect("process canonicalizes");
        let canonical = Arc::clone(&host)
            .canonicalize(raw)
            .expect("process canonicalizes");
        assert_eq!(first.normalized().ingest_seq, 1);
        assert_eq!(canonical.normalized().ingest_seq, 2);
        let EventFields::ProcessCreation(fields) = &canonical.normalized().fields else {
            panic!("expected process view")
        };
        assert_eq!(fields.process_id.as_deref(), Some("42"));
        assert_eq!(fields.parent_process_id.as_deref(), Some("7"));
        assert_eq!(fields.cgroup_id.as_deref(), Some("99"));
    }
}
