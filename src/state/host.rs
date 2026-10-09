//! Shared ownership, entry limits, and raw-to-canonical host enrichment.
use super::{DnsCache, ProcessCache, SidCache};
use crate::models::{CanonicalEvent, NormalizedEvent};
use crate::normalizer::Normalizer;
use crate::sensor::{RawEvent, RawPayload};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

/// Per-OS state a platform sensor keeps on the host.
///
/// The sensor defines the type and `HostState` only stores and reports it, so
/// the state module never names a sensor type.
pub trait HostExtension: Any + Send + Sync {
    /// Build the extension, sized from the host limits.
    fn from_limits(limits: &StateLimits) -> Self
    where
        Self: Sized;
    /// Path-index entries currently retained.
    fn retained_paths(&self) -> usize {
        0
    }
    /// Process-identity entries currently retained.
    fn process_identities(&self) -> usize {
        0
    }
    /// Fill in the sensor counters this platform owns.
    fn sensor_telemetry(&self, _out: &mut crate::telemetry::SensorTelemetry) {}
    fn as_any(&self) -> &dyn Any;
}

pub struct HostState {
    pub processes: Arc<ProcessCache>,
    pub users: Arc<SidCache>,
    pub dns: Arc<DnsCache>,
    /// Built on the first Linux process event, so hosts and tests that never
    /// see one never read mountinfo.
    #[cfg(target_os = "linux")]
    pub(crate) containers: std::sync::OnceLock<Mutex<super::container::ContainerResolver>>,
    /// Per-OS state owned by the platform sensor, built on first use.
    extension: std::sync::OnceLock<Box<dyn HostExtension>>,
    limits: StateLimits,
    inventory: Mutex<Option<InventorySnapshot>>,
    attribution_loss: AtomicU64,
    pub(crate) ingest_seq: AtomicU64,
    /// Windows classic/manifest process correlation outcomes for this runtime.
    pub(crate) process_correlation: Arc<crate::telemetry::ProcessCorrelationCounters>,
    /// Final command-line availability for accepted Windows process starts.
    pub(crate) command_line: crate::telemetry::ProcessCommandLineCounters,
    /// Fields with known fidelity limits that normalization has emitted.
    /// macOS ESF and BPF collector health for this runtime.
    pub(crate) macos_collectors: crate::telemetry::MacosCollectors,
    pub(crate) provenance: crate::telemetry::ProvenanceCounters,
    /// Canonical fields emitted despite being declared unavailable by the
    /// matching field contract. The detector accessor hides them, but the
    /// contradiction is still a decoder/contract defect operators must see.
    pub(crate) field_contract_violations: AtomicU64,
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
            containers: std::sync::OnceLock::new(),
            extension: std::sync::OnceLock::new(),
            limits,
            inventory: Mutex::new(None),
            attribution_loss: AtomicU64::new(0),
            ingest_seq: AtomicU64::new(0),
            process_correlation: Arc::default(),
            command_line: crate::telemetry::ProcessCommandLineCounters::new(),
            macos_collectors: Default::default(),
            provenance: Default::default(),
            field_contract_violations: AtomicU64::new(0),
        }
    }
    pub fn for_runtime(max_processes: usize) -> Arc<Self> {
        let state = Arc::new(Self::new(StateLimits {
            processes: max_processes,
            ..Default::default()
        }));
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
    /// The platform extension, built on first use.
    ///
    /// A host carries one extension type, the one its own platform sensor
    /// defines, so asking for a second type is a programming error.
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub(crate) fn extension<T: HostExtension>(&self) -> &T {
        self.extension
            .get_or_init(|| Box::new(T::from_limits(&self.limits)))
            .as_any()
            .downcast_ref::<T>()
            .expect("a host carries a single platform extension type")
    }
    /// The platform sensor's counters, or empty when no sensor has run here.
    pub fn sensor_telemetry(&self) -> crate::telemetry::SensorTelemetry {
        let mut out = crate::telemetry::SensorTelemetry::default();
        if let Some(extension) = self.extension.get() {
            extension.sensor_telemetry(&mut out);
        }
        out.process_correlation = self.process_correlation.snapshot();
        out.process_command_line = self.command_line.snapshot();
        out.macos_collectors = crate::telemetry::macos::snapshot(&self.macos_collectors);
        out.field_fidelity = self.provenance.snapshot();
        out.field_contract_violations = self.field_contract_violations.load(Ordering::Relaxed);
        out
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
        let (paths, process_identities) = self.extension.get().map_or((0, 0), |ext| {
            (ext.retained_paths(), ext.process_identities())
        });
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

        // SAFETY: sysconf takes an integer name and has no pointer arguments.
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
            Some(crate::vocab::ProcessStartKey {
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
            Some(crate::vocab::ProcessStartKey {
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
            let ext = state.extension::<crate::sensor::linux::LinuxHostExtension>();
            let mut paths = ext.dir_fds.lock().unwrap();
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
        if event.action == crate::vocab::SensorAction::Fork {
            let inherited = match &event.payload {
                RawPayload::Process(process) => event
                    .process_start_key
                    .filter(|child| child.pid == process.process_id)
                    .zip(event.parent_process_start_key)
                    .filter(|(_, parent)| process.parent_process_id == Some(parent.pid))
                    .is_some_and(|(child, parent)| {
                        self.processes.inherit(
                            child.pid,
                            child.start_time,
                            parent.pid,
                            parent.start_time,
                        )
                    }),
                _ => false,
            };
            if !inherited {
                self.record_attribution_loss();
            }
            return None;
        }
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
        process_start_key: Option<crate::vocab::ProcessStartKey>,
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
            enrich_windows_process(event, &self.process_correlation);
        }

        #[cfg(not(any(target_os = "linux", windows)))]
        let _ = event;
    }
}

#[cfg(target_os = "linux")]
fn enrich_linux_process(event: &mut RawEvent) {
    use crate::utils::process::{query_process_details_with, ProcessReads};

    if event.platform != crate::vocab::Platform::Linux
        || event.action != crate::vocab::SensorAction::Start
    {
        return;
    }
    let RawPayload::Process(process) = &mut event.payload else {
        return;
    };
    // Enrichment never uses the parent, and an absolute image from the sensor
    // needs no `exe` read to be resolved.
    let reads = ProcessReads {
        image: process
            .image
            .as_deref()
            .is_some_and(|image| !std::path::Path::new(image).is_absolute()),
        parent: false,
    };
    let Some(details) = query_process_details_with(process.process_id, reads) else {
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
    process_start_key: Option<crate::vocab::ProcessStartKey>,
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
    // A lean query skips `exe` for an absolute raw image, which then stands in
    // for it: start time and command line still guard the identity.
    let current_image = match details.image.as_deref() {
        Some(image) => image,
        None if Path::new(raw_image).is_absolute() => raw_image,
        None => return,
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
fn enrich_windows_process(
    event: &mut RawEvent,
    counters: &crate::telemetry::ProcessCorrelationCounters,
) {
    if event.platform != crate::vocab::Platform::Windows {
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
    if event.action != crate::vocab::SensorAction::Start {
        return;
    }
    let live = event.process_start_key.and_then(|key| {
        crate::utils::query_process_command_line_at_start(process.process_id, key.start_time)
    });
    enrich_windows_command_line(process, live, counters);
}

#[cfg(any(windows, test))]
pub(crate) fn enrich_windows_command_line(
    process: &mut crate::sensor::RawProcessEvent,
    live: Option<String>,
    metrics: &crate::telemetry::ProcessCorrelationCounters,
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
        let counter = if conflicting {
            tracing::debug!(
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
        Platform, ProcessStartKey, RawLinuxProcess, RawLinuxProcessIdentity, RawPayload,
        RawProcessEvent, RawProcessPlatform, RawUserId, SensorAction, SensorNormalization,
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
            enrich_windows_command_line(&mut process, live.map(String::from), &Default::default());
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

    fn linux_process_event(
        action: SensorAction,
        pid: u32,
        start_time: u64,
        parent: Option<ProcessStartKey>,
        image: Option<&str>,
    ) -> RawEvent {
        RawEvent {
            process_name: None,
            provenance: Default::default(),
            platform: Platform::Linux,
            provider: "ebpf",
            action,
            normalization: SensorNormalization {
                event_id: u16::from(action == SensorAction::Start),
                action_code: match action {
                    SensorAction::Start => 1,
                    SensorAction::Fork => 3,
                    _ => 0,
                },
            },
            pid: Some(pid),
            timestamp: SystemTime::UNIX_EPOCH,
            source_seq: None,
            process_start_key: Some(ProcessStartKey { pid, start_time }),
            parent_process_start_key: parent,
            payload: RawPayload::Process(RawProcessEvent {
                process_id: pid,
                parent_process_id: parent.map(|key| key.pid),
                process_start_time: None,
                image: image.map(str::to_string),
                command_line: image.map(str::to_string),
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some(RawUserId::Unix(1000)),
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                platform: Box::new(RawProcessPlatform::Linux(RawLinuxProcess {
                    real_user_id: Some(1000),
                    identity: RawLinuxProcessIdentity {
                        real_group_id: Some(1000),
                        ..Default::default()
                    },
                    cgroup_id: None,
                    image_source: image.map(|_| "execve".into()),
                    image_truncated: None,
                    parent_process_id_derived: false,
                })),
            }),
        }
    }

    #[test]
    fn forked_workers_preserve_parent_image_and_exec_replaces_it() {
        let host = state();
        let server = ProcessStartKey {
            pid: 10,
            start_time: 100,
        };
        // Model a server discovered by startup inventory before the sensor
        // observes its prefork worker.
        host.processes.add(
            server.pid,
            server.start_time,
            "/usr/bin/server".into(),
            Some("server --prefork".into()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let worker = ProcessStartKey {
            pid: 20,
            start_time: 200,
        };
        assert!(host
            .canonicalize(linux_process_event(
                SensorAction::Fork,
                worker.pid,
                worker.start_time,
                Some(server),
                None,
            ))
            .is_none());

        let command = host
            .canonicalize(linux_process_event(
                SensorAction::Start,
                30,
                300,
                Some(worker),
                Some("/usr/bin/command"),
            ))
            .expect("exec should remain visible");
        assert_eq!(
            command.normalized().get_field("ParentImage"),
            Some("/usr/bin/server")
        );
        assert_eq!(
            command.normalized().get_field("ParentProcessId"),
            Some("20")
        );

        let worker_exec = ProcessStartKey {
            pid: worker.pid,
            start_time: 250,
        };
        host.canonicalize(linux_process_event(
            SensorAction::Start,
            worker_exec.pid,
            worker_exec.start_time,
            Some(server),
            Some("/usr/bin/new-worker"),
        ))
        .expect("worker exec should remain visible");

        let later = host
            .canonicalize(linux_process_event(
                SensorAction::Start,
                31,
                310,
                Some(worker_exec),
                Some("/usr/bin/later"),
            ))
            .expect("later exec should remain visible");
        assert_eq!(
            later.normalized().get_field("ParentImage"),
            Some("/usr/bin/new-worker")
        );
    }
}
