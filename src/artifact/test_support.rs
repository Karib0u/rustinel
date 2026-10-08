//! Fixtures shared by the artifact tests: event builders, a controllable
//! opener, and a harness that wires ingress to the running stages exactly as
//! the live pipeline does.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::alerts::AlertSink;
use crate::artifact::ingress::*;
use crate::artifact::job::*;
use crate::artifact::snapshot::*;
use crate::artifact::target::*;
use crate::artifact::written_file::*;
use crate::artifact::*;
use crate::config::AppConfig;
use crate::engine::{DetectionPass, DetectorStore, Engine, EventDetectors};
use crate::models::{
    CanonicalEvent, EventFields, FileObjectIdentity, ImageLoadFields, LinuxProcessIdentity,
    MatchDebugLevel, NormalizedEvent, ProcessCreationFields,
};
use crate::scanner::Scanner;
use crate::sensor::{CanonicalEventHandler, Platform, SensorEventRouter};
use crate::state::HostState;

impl ArtifactTarget {
    /// Test convenience for the two admission stages: selection, then capture.
    pub(super) fn from_event(
        event: &CanonicalEvent,
        written_files: Option<&WrittenFileSelector>,
    ) -> Option<Self> {
        let mut target = Self::select_event(event, written_files)?;
        target.capture_process_context(event);
        Some(target)
    }
}

pub(crate) fn process_event(path: &Path, platform: Platform) -> CanonicalEvent {
    #[allow(unused_mut)]
    let mut linux_identity = Box::<LinuxProcessIdentity>::default();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        linux_identity.mount_namespace = Some(
            std::fs::metadata("/proc/self/ns/mnt")
                .unwrap()
                .ino()
                .to_string(),
        );
    }
    CanonicalEvent::from_normalized(NormalizedEvent {
        timestamp: "2026-01-01T00:00:00Z".into(),
        source_seq: None,
        ingest_seq: 1,
        platform,
        provider: "test".into(),
        category: crate::models::EventCategory::Process,
        event_id: 1,
        event_id_string: "1".into(),
        opcode: 1,
        fields: EventFields::ProcessCreation(ProcessCreationFields {
            hashes: None,
            imphash: None,
            container: Default::default(),
            exec: Default::default(),
            linux_identity,
            image: Some(path.to_string_lossy().into_owned()),
            image_source: None,
            image_truncated: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: None,
            process_id: Some("42".into()),
            process_start_time: None,
            cgroup_id: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            parent_user: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            parent_process_id_derived: false,
            windows: Default::default(),
        }),
        process_name: None,
        provenance: Default::default(),
        process_context: None,
    })
}

pub(super) fn image_event(path: &Path) -> CanonicalEvent {
    CanonicalEvent::from_normalized(NormalizedEvent {
        timestamp: "2026-01-01T00:00:00Z".into(),
        source_seq: None,
        ingest_seq: 1,
        platform: Platform::Windows,
        provider: "test".into(),
        category: crate::models::EventCategory::ImageLoad,
        event_id: 7,
        event_id_string: "7".into(),
        opcode: 3,
        fields: EventFields::ImageLoad(ImageLoadFields {
            hashes: None,
            imphash: None,
            image_loaded: Some(path.to_string_lossy().into_owned()),
            process_id: Some("42".into()),
            image: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            signed: None,
            signature: None,
            user: None,
        }),
        process_name: None,
        provenance: Default::default(),
        process_context: None,
    })
}

pub(super) fn runtime_with_consumers(root: &Path, bytes: &[u8]) -> ArtifactRuntime {
    use sha2::Digest;

    let rules = root.join("yara");
    std::fs::create_dir(&rules).unwrap();
    std::fs::write(
        rules.join("marker.yar"),
        r#"rule Marker { strings: $marker = "evil!!" condition: $marker }"#,
    )
    .unwrap();
    let scanner = Scanner::new(&rules).unwrap();

    let mut cfg = AppConfig::default();
    cfg.ioc.enabled = true;
    cfg.ioc.hashes_path = root.join("hashes.txt");
    cfg.ioc.ips_path = root.join("ips.txt");
    cfg.ioc.domains_path = root.join("domains.txt");
    cfg.ioc.paths_regex_path = root.join("paths.txt");
    cfg.ioc.max_file_size_mb = 1;
    std::fs::write(
        &cfg.ioc.hashes_path,
        hex::encode(sha2::Sha256::digest(bytes)),
    )
    .unwrap();
    for path in [
        &cfg.ioc.ips_path,
        &cfg.ioc.domains_path,
        &cfg.ioc.paths_regex_path,
    ] {
        std::fs::write(path, "").unwrap();
    }
    let detectors = DetectorStore::new(
        Arc::new(Engine::new_for_platform(Platform::Linux)),
        Arc::new(scanner),
        Arc::new(crate::ioc::IocEngine::load(&cfg.ioc)),
    );
    ArtifactRuntime {
        detectors: Some(detectors),
        alert_sink: None,
        response_engine: None,
        match_debug: MatchDebugLevel::Off,
        yara_allowlist_paths: Vec::new(),
        pe_metadata: false,
        written_files: None,
    }
}

/// Records what downstream saw, in the order it saw it.
#[derive(Clone, Default)]
pub(super) struct Seen(pub(super) Arc<Mutex<Vec<(u64, Instant)>>>);

impl Seen {
    pub(super) fn ingest_seqs(&self) -> Vec<u64> {
        self.0.lock().unwrap().iter().map(|(seq, _)| *seq).collect()
    }

    pub(super) fn wait_for(&self, count: usize) {
        let give_up = Instant::now() + Duration::from_secs(10);
        while self.0.lock().unwrap().len() < count {
            assert!(
                Instant::now() < give_up,
                "downstream never saw {count} events"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl CanonicalEventHandler for Seen {
    fn handle_event(&self, event: &CanonicalEvent) {
        self.0
            .lock()
            .unwrap()
            .push((event.normalized().ingest_seq, Instant::now()));
    }
}

pub(super) fn router_with(handler: impl CanonicalEventHandler + 'static) -> Arc<SensorEventRouter> {
    let mut router = SensorEventRouter::new();
    router.register_handler(Box::new(handler));
    Arc::new(router)
}

/// An opener that blocks every caller until the gate is released.
#[derive(Clone)]
pub(super) struct Gate(pub(super) Arc<(Mutex<bool>, std::sync::Condvar)>);

impl Gate {
    pub(super) fn new() -> Self {
        Self(Arc::new((Mutex::new(false), std::sync::Condvar::new())))
    }

    pub(super) fn opener(&self, entered: Option<std::sync::mpsc::Sender<()>>) -> ArtifactOpener {
        let gate = self.clone();
        Arc::new(move |path| {
            if let Some(entered) = &entered {
                let _ = entered.send(());
            }
            let (released, wake) = &*gate.0;
            let released = released.lock().unwrap();
            let _released = wake.wait_while(released, |released| !*released).unwrap();
            File::open(path)
        })
    }

    pub(super) fn release(&self) {
        let (released, wake) = &*self.0;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
}

/// Ingress plus both running stages, wired exactly as
/// [`spawn_artifact_resolver`] wires them but with a controllable opener.
pub(super) struct Harness {
    pub(super) ingress: ArtifactEventHandler,
    pub(super) stages: std::thread::JoinHandle<()>,
    pub(super) state: Arc<ResolverState>,
}

impl Harness {
    pub(super) fn start(
        downstream: Arc<SensorEventRouter>,
        runtime: ArtifactRuntime,
        open: ArtifactOpener,
        resolve_capacity: usize,
    ) -> Self {
        Self::from_parts(
            ResolverParts::new(
                downstream,
                Arc::new(HostState::default()),
                runtime,
                Arc::new(ResolverState::new()),
                resolve_capacity,
                WRITTEN_FILE_QUEUE_CAPACITY,
            ),
            open,
        )
    }

    pub(super) fn from_parts(parts: ResolverParts, open: ArtifactOpener) -> Self {
        let state = Arc::clone(&parts.ingress.state);
        let ResolverParts {
            ingress,
            admission,
            deferred,
            resolver,
            resolve_rx,
            written_rx,
        } = parts;
        let stages = std::thread::spawn(move || {
            run_resolver_stages(admission, deferred, resolver, resolve_rx, written_rx, open)
        });
        Self {
            ingress,
            stages,
            state,
        }
    }

    pub(super) fn finish(self) -> Arc<ResolverState> {
        drop(self.ingress);
        self.stages.join().unwrap();
        self.state
    }
}

pub(super) fn with_ingest_seq(event: CanonicalEvent, ingest_seq: u64) -> CanonicalEvent {
    let mut normalized = event.into_normalized();
    normalized.ingest_seq = ingest_seq;
    CanonicalEvent::from_normalized(normalized)
}

pub(super) fn windows_file_event(ingest_seq: u64) -> CanonicalEvent {
    CanonicalEvent::from_normalized(NormalizedEvent {
        timestamp: "2026-01-01T00:00:00Z".into(),
        source_seq: None,
        ingest_seq,
        platform: Platform::Windows,
        provider: "test".into(),
        category: crate::models::EventCategory::File,
        event_id: 11,
        event_id_string: "11".into(),
        opcode: 64,
        fields: EventFields::FileEvent(crate::models::FileEventFields {
            source_filename: None,
            target_filename: Some(r"C:\Temp\later.txt".into()),
            process_id: Some("43".into()),
            image: None,
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: None,
            file_identity: None,
            path_truncated: None,
        }),
        process_name: None,
        provenance: Default::default(),
        process_context: None,
    })
}

pub(super) fn state_of(harness: &Harness) -> ArtifactResolverSnapshot {
    harness.state.snapshot()
}

pub(super) const FILE_CREATE_OPCODE: u8 = 64;

pub(super) const FILE_DELETE_OPCODE: u8 = 70;

pub(super) const WRITER_IMAGE: &str = "/usr/bin/curl";

pub(super) fn file_event(
    path: &Path,
    opcode: u8,
    identity: Option<FileObjectIdentity>,
) -> CanonicalEvent {
    let mut normalized = windows_file_event(1).into_normalized();
    normalized.platform = Platform::Linux;
    normalized.provider = "ebpf".into();
    normalized.opcode = opcode;
    normalized.fields = EventFields::FileEvent(crate::models::FileEventFields {
        source_filename: None,
        target_filename: Some(path.to_string_lossy().into_owned()),
        process_id: Some("43".into()),
        image: Some(WRITER_IMAGE.into()),
        creation_utc_time: None,
        previous_creation_utc_time: None,
        user: None,
        file_identity: identity,
        path_truncated: None,
    });
    CanonicalEvent::from_normalized(normalized)
}

pub(super) fn select_all() -> WrittenFileSelector {
    Arc::new(|_, _| true)
}

pub(super) fn settling_job(path: &str, inode: u64, enqueued_at: Instant) -> ArtifactJob {
    let runtime = ArtifactRuntime::capture(Platform::Windows);
    let event = process_event(Path::new(path), Platform::Windows);
    let mut target = ArtifactTarget::from_event(&event, None).unwrap();
    target.kind = ArtifactKind::WrittenFile;
    target.expected = Some(ExpectedIdentity::Object(FileObjectIdentity {
        device: 1,
        inode,
    }));
    ArtifactJob {
        plan: ResolvePlan::snapshot(&runtime, &event, &target),
        target,
        enqueued_at,
        pe_ready: None,
        deferred_ready: None,
        resolved_pe: None,
        resolved_hashes: None,
        process_start_key: None,
        provenance: Default::default(),
        platform: Platform::Windows,
        provider: "test".into(),
        written_file: None,
    }
}

#[cfg(unix)]
pub(super) fn object_identity(path: &Path) -> FileObjectIdentity {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).unwrap();
    FileObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
pub(super) fn windows_written_file_event(path: &Path) -> CanonicalEvent {
    let mut normalized = file_event(path, FILE_CREATE_OPCODE, None).into_normalized();
    normalized.platform = Platform::Windows;
    normalized.provider = "etw".into();
    CanonicalEvent::from_normalized(normalized)
}

#[cfg(target_os = "linux")]
pub(super) fn live_process_event(pid: u32, image: &Path) -> CanonicalEvent {
    let mut event = process_event(image, Platform::Linux).into_normalized();
    let EventFields::ProcessCreation(fields) = &mut event.fields else {
        unreachable!()
    };
    fields.process_id = Some(pid.to_string());
    CanonicalEvent::from_normalized(event)
}

#[cfg(target_os = "linux")]
pub(super) struct FileProcessFixture {
    pub(super) child: std::process::Child,
    pub(super) root: tempfile::TempDir,
    pub(super) bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl FileProcessFixture {
    pub(super) fn start(script: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};

        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("sleep");
        let mut bytes = if script {
            b"#!/bin/sh\n# evil!!\nread ignored\n".to_vec()
        } else {
            std::fs::read("/bin/sh").unwrap()
        };
        if !script {
            bytes.extend_from_slice(b"evil!!");
        }
        std::fs::write(&image, &bytes).unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
        let child = Command::new("./sleep")
            .args(["-c", "read ignored"])
            .current_dir(root.path())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let fixture = Self { child, root, bytes };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let ready =
                crate::utils::query_process_identity(fixture.child.id()).is_some_and(|identity| {
                    if script {
                        identity.image.ends_with("/dash") || identity.image.ends_with("/sh")
                    } else {
                        Path::new(&identity.image) == image
                    }
                });
            if ready {
                return fixture;
            }
            assert!(Instant::now() < deadline, "child did not exec the fixture");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for FileProcessFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
pub(super) struct MemfdFixture {
    pub(super) child: std::process::Child,
    pub(super) bytes: Vec<u8>,
    pub(super) descriptor_path: String,
}

#[cfg(target_os = "linux")]
impl MemfdFixture {
    pub(super) fn start() -> Self {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd};
        // SAFETY: the name is a NUL-terminated C string literal and the flag is a
        // valid memfd_create flag.
        let fd = unsafe { libc::memfd_create(c"payload".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create: {}", io::Error::last_os_error());
        // SAFETY: memfd_create returned a new descriptor (checked non-negative
        // above) that nothing else owns.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut bytes = std::fs::read("/bin/sh").unwrap();
        bytes.extend_from_slice(b"evil!!");
        file.write_all(&bytes).unwrap();
        let descriptor_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let child = std::process::Command::new(&descriptor_path)
            .args(["-c", "read ignored"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        drop(file);
        let fixture = Self {
            child,
            bytes,
            descriptor_path,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if crate::utils::query_process_identity(fixture.child.id())
                .is_some_and(|identity| crate::utils::process::is_memfd_image(&identity.image))
            {
                break;
            }
            assert!(Instant::now() < deadline, "child did not exec the memfd");
            std::thread::sleep(Duration::from_millis(10));
        }
        fixture
    }

    pub(super) fn event(&self, image: &str) -> CanonicalEvent {
        let mut event = process_event(Path::new(image), Platform::Linux).into_normalized();
        let EventFields::ProcessCreation(fields) = &mut event.fields else {
            unreachable!()
        };
        fields.process_id = Some(self.child.id().to_string());
        CanonicalEvent::from_normalized(event)
    }
}

#[cfg(target_os = "linux")]
impl Drop for MemfdFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) fn windows_rule(title: &str, category: &str, detection: &str) -> String {
    format!(
        "title: {title}\nlevel: high\nlogsource:\n  product: windows\n  category: {category}\ndetection:\n{detection}"
    )
}

/// A detecting runtime over the given Sigma rules, with alerts written to
/// `alerts.ndjson` under `root`. No IOC or YARA consumer is loaded, so any
/// hashing comes from the deferred pass alone.
pub(crate) fn detecting_runtime(
    root: &Path,
    rules: &[String],
) -> (
    ArtifactRuntime,
    Arc<DetectorStore>,
    PathBuf,
    tracing_appender::non_blocking::WorkerGuard,
) {
    let rules_dir = root.join("sigma");
    std::fs::create_dir(&rules_dir).unwrap();
    for (index, rule) in rules.iter().enumerate() {
        std::fs::write(rules_dir.join(format!("rule{index}.yml")), rule).unwrap();
    }
    let mut engine = Engine::new_for_platform(Platform::Windows);
    engine.load_rules(&rules_dir).unwrap();
    assert!(engine.stats().failed_rules.is_empty());
    let detectors = DetectorStore::new(
        Arc::new(engine),
        Arc::new(Scanner::empty()),
        Arc::new(crate::ioc::IocEngine::disabled()),
    );
    let alerts_path = root.join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
    let runtime = ArtifactRuntime {
        detectors: Some(Arc::clone(&detectors)),
        alert_sink: Some(AlertSink::new(writer)),
        response_engine: None,
        match_debug: MatchDebugLevel::Off,
        yara_allowlist_paths: Vec::new(),
        pe_metadata: false,
        written_files: None,
    };
    (runtime, detectors, alerts_path, guard)
}

/// Admission-side detection exactly as the live pipeline runs it.
pub(super) struct AdmissionDetection {
    pub(super) detectors: Arc<DetectorStore>,
    pub(super) sink: AlertSink,
}

impl CanonicalEventHandler for AdmissionDetection {
    fn handle_event(&self, event: &CanonicalEvent) {
        let pass = if event.deferred_pass_pending() {
            DetectionPass::Admission
        } else {
            DetectionPass::All
        };
        for alert in EventDetectors::snapshot(&self.detectors).evaluate_pass(event, pass) {
            self.sink.write_alert(&alert);
        }
    }
}

pub(crate) fn read_alerts(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

pub(crate) fn rule_names(alerts: &[serde_json::Value]) -> Vec<String> {
    let mut names: Vec<String> = alerts
        .iter()
        .map(|alert| alert["rule.name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}
