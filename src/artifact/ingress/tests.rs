use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::alerts::AlertSink;
use crate::artifact::ingress::*;
use crate::artifact::job::*;
use crate::artifact::resolver::*;
use crate::artifact::stores::*;
use crate::artifact::target::*;
use crate::artifact::test_support::*;
use crate::artifact::written_file::*;
use crate::artifact::*;
#[cfg(target_os = "linux")]
use crate::config::AppConfig;
use crate::engine::Engine;
use crate::models::{CanonicalEvent, EventFields, FileObjectIdentity};
use crate::sensor::{CanonicalEventHandler, Platform, SensorEventRouter};
use crate::stages::admission::*;
use crate::stages::deferred::*;
use crate::state::HostState;
use crate::utils::file_identity;

#[test]
fn successful_hash_and_yara_scan_emits_each_alert_once() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let path = temp.path().join("sample.bin");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    let alerts_path = temp.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
    runtime.alert_sink = Some(AlertSink::new(writer));
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness
        .ingress
        .handle_event(&process_event(&path, Platform::Linux));
    let state = harness.finish();
    drop(guard);

    let alerts = read_alerts(&alerts_path);
    let engines: Vec<&str> = alerts
        .iter()
        .map(|alert| alert["edr.rule.engine"].as_str().unwrap())
        .collect();
    assert_eq!(engines.len(), 2);
    assert_eq!(engines.iter().filter(|engine| **engine == "Ioc").count(), 1);
    assert_eq!(
        engines.iter().filter(|engine| **engine == "Yara").count(),
        1
    );
    let snapshot = state.snapshot();
    assert_eq!(snapshot.resolved, 1);
    assert_eq!(snapshot.deadline_exceeded, 0);
}

/// A process start waiting on artifact I/O must not let a later event
/// reach the recording first: replay rejects a payload whose `ingest_seq`
/// goes backwards, so the whole Windows capture would be unreplayable.
#[tokio::test(flavor = "multi_thread")]
async fn held_artifact_event_keeps_the_recording_replayable() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("held.exe");
    std::fs::write(&image, b"not really a PE").unwrap();
    let payload = temp.path().join("captures").join("session.ndjson");
    let recorder = crate::capture::CaptureRecorder::start(payload.clone(), Platform::Windows)
        .expect("capture starts");
    let downstream = router_with(crate::engine::CanonicalEventDispatcher::recording(
        Arc::new(HostState::default()),
        recorder.sink(),
    ));

    let gate = Gate::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let harness = Harness::start(
        downstream,
        ArtifactRuntime::capture(Platform::Windows),
        gate.opener(Some(entered_tx)),
        ARTIFACT_QUEUE_CAPACITY,
    );

    let producer = tokio::task::spawn_blocking(move || {
        harness.ingress.handle_event(&with_ingest_seq(
            process_event(&image, Platform::Windows),
            1,
        ));
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        harness.ingress.handle_event(&windows_file_event(2));
        gate.release();
        harness.finish();
    });
    producer.await.unwrap();
    recorder.finish().await.expect("capture finalizes");

    let recording = crate::replay::Recording::open(&payload).expect("recording opens");
    let replayed: Vec<u64> = recording
        .events()
        .unwrap()
        .map(|event| {
            event
                .expect("replay accepts every event")
                .normalized()
                .ingest_seq
        })
        .collect();
    assert_eq!(replayed, vec![1, 2]);
}

#[test]
fn blocked_artifact_io_delays_later_events_by_at_most_the_budget() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("blocked.exe");
    std::fs::write(&image, b"artifact").unwrap();
    let seen = Seen::default();
    let gate = Gate::new();
    let harness = Harness::start(
        router_with(seen.clone()),
        ArtifactRuntime::capture(Platform::Windows),
        gate.opener(None),
        ARTIFACT_QUEUE_CAPACITY,
    );

    let submitted = Instant::now();
    harness
        .ingress
        .handle_event(&with_ingest_seq(image_event(&image), 1));
    harness.ingress.handle_event(&windows_file_event(2));
    seen.wait_for(2);

    assert_eq!(seen.ingest_seqs(), vec![1, 2]);
    let routed = seen.0.lock().unwrap()[1].1;
    let waited = routed.duration_since(submitted);
    assert!(
        waited >= ADMISSION_BUDGET,
        "admission released early: {waited:?}"
    );
    assert!(
        waited < ADMISSION_BUDGET + Duration::from_secs(2),
        "admission exceeded its budget: {waited:?}"
    );
    assert_eq!(state_of(&harness).admission_budget_exceeded, 1);

    gate.release();
    harness.finish();
}

#[test]
fn saturated_resolver_queue_still_admits_in_order_within_one_budget() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("burst.exe");
    std::fs::write(&image, b"artifact").unwrap();
    let seen = Seen::default();
    let gate = Gate::new();
    let harness = Harness::start(
        router_with(seen.clone()),
        ArtifactRuntime::capture(Platform::Windows),
        gate.opener(None),
        1,
    );

    let total = 64;
    let submitted = Instant::now();
    for seq in 1..=total {
        harness
            .ingress
            .handle_event(&with_ingest_seq(image_event(&image), seq));
    }
    seen.wait_for(total as usize);

    assert_eq!(seen.ingest_seqs(), (1..=total).collect::<Vec<_>>());
    let last = seen.0.lock().unwrap().last().unwrap().1;
    assert!(
        last.duration_since(submitted) < ADMISSION_BUDGET + Duration::from_secs(2),
        "queued budgets must not stack"
    );
    let snapshot = state_of(&harness);
    assert!(snapshot.queue_saturated > 0);
    assert_eq!(
        snapshot.queued + snapshot.queue_saturated,
        total,
        "every artifact event is either queued or counted as shed"
    );

    gate.release();
    harness.finish();
}

#[test]
fn image_load_burst_with_slow_enrichment_keeps_order_and_bounded_delay() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("burst.dll");
    std::fs::write(&image, b"artifact").unwrap();
    let seen = Seen::default();
    let open: ArtifactOpener = Arc::new(|path| {
        std::thread::sleep(Duration::from_millis(2));
        File::open(path)
    });
    let harness = Harness::start(
        router_with(seen.clone()),
        ArtifactRuntime::capture(Platform::Windows),
        open,
        ARTIFACT_QUEUE_CAPACITY,
    );

    let total = 2_000u64;
    let mut submitted = Vec::with_capacity(total as usize);
    for seq in 1..=total {
        submitted.push(Instant::now());
        let event = if seq % 2 == 0 {
            with_ingest_seq(image_event(&image), seq)
        } else {
            windows_file_event(seq)
        };
        harness.ingress.handle_event(&event);
    }
    let state = harness.finish();

    let seen = seen.0.lock().unwrap();
    let order: Vec<u64> = seen.iter().map(|(seq, _)| *seq).collect();
    assert_eq!(order, (1..=total).collect::<Vec<_>>());
    let worst = seen
        .iter()
        .map(|(seq, routed)| routed.duration_since(submitted[*seq as usize - 1]))
        .max()
        .unwrap();
    assert!(
        worst < ADMISSION_BUDGET + Duration::from_secs(2),
        "an event waited {worst:?}"
    );
    let snapshot = state.snapshot();
    assert_eq!(snapshot.queued + snapshot.queue_saturated, total / 2);
}

#[test]
fn pe_field_rule_fires_exactly_once_after_admission() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("signed.exe");
    std::fs::write(&image, b"artifact").unwrap();
    let rules = temp.path().join("rules");
    std::fs::create_dir(&rules).unwrap();
    std::fs::write(
        rules.join("company.yml"),
        r#"
title: Company from PE metadata
id: 3d9c8e57-5a0f-4c1e-9b8f-4270000000a1
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Company: Rustinel Test Company
  condition: selection
level: high
"#,
    )
    .unwrap();
    let mut engine = Engine::new_for_platform(Platform::Windows);
    engine.load_rules(&rules).unwrap();

    struct Detect(Engine, Arc<Mutex<Vec<String>>>);
    impl CanonicalEventHandler for Detect {
        fn handle_event(&self, event: &CanonicalEvent) {
            for alert in self.0.evaluate_event(event.normalized()) {
                self.1.lock().unwrap().push(alert.rule_name);
            }
        }
    }
    let alerts = Arc::new(Mutex::new(Vec::new()));
    let runtime = ArtifactRuntime::capture(Platform::Windows);
    let event = process_event(&image, Platform::Windows);
    let harness = Harness::start(
        router_with(Detect(engine, Arc::clone(&alerts))),
        runtime.clone(),
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );
    // Seed the PE store so the rule does not depend on a Windows parser.
    let target = ArtifactTarget::from_event(&event, None).unwrap();
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    harness.state.stores.lock().unwrap().insert(
        file_identity::from_path(&image).unwrap(),
        &plan,
        &Artifact {
            pe_metadata: Some(PeMetadata {
                original_filename: None,
                product: None,
                description: None,
                company: Some("Rustinel Test Company".into()),
                file_version: None,
            }),
            ..Artifact::default()
        },
        StoredParts {
            pe: true,
            imphash: false,
        },
    );

    harness.ingress.handle_event(&event);
    let state = harness.finish();

    assert_eq!(
        *alerts.lock().unwrap(),
        vec!["Company from PE metadata".to_string()]
    );
    assert_eq!(state.snapshot().cache_hits, 1);
    assert_eq!(state.snapshot().admission_budget_exceeded, 0);
}

/// Scan alerts are built on another thread from the job, not the event,
/// so the job must carry the fidelity of the image and PID it reports.
#[test]
fn queued_jobs_carry_the_scan_subject_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("derived.exe");
    std::fs::write(&image, b"artifact").unwrap();
    let ResolverParts {
        ingress,
        admission,
        mut resolve_rx,
        ..
    } = ResolverParts::new(
        Arc::new(SensorEventRouter::new()),
        Arc::new(HostState::default()),
        ArtifactRuntime::capture(Platform::Windows),
        Arc::new(ResolverState::new()),
        ARTIFACT_QUEUE_CAPACITY,
        WRITTEN_FILE_QUEUE_CAPACITY,
    );
    let admitted = std::thread::spawn(move || admission.run());

    let mut normalized = process_event(&image, Platform::Windows).into_normalized();
    normalized.provenance.mark_derived("Image");
    normalized
        .provenance
        .mark("ProcessId", crate::models::Fidelity::BestEffort);
    normalized.provenance.mark_derived("OriginalFileName");
    ingress.handle_event(&CanonicalEvent::from_normalized(normalized));

    let job = resolve_rx.try_recv().expect("artifact job queued");
    let mut expected = crate::models::Provenance::default();
    expected.mark_derived("Image");
    expected.mark("ProcessId", crate::models::Fidelity::BestEffort);
    assert_eq!(job.provenance, expected);
    drop(job);
    drop(ingress);
    admitted.join().unwrap();
}

#[cfg(any(unix, windows))]
#[test]
fn persistent_scripts_after_a_churn_burst_receive_yara_and_hash_ioc_alerts() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let alerts_path = temp.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    runtime.written_files = Some(written_file_scan_selector());
    runtime.alert_sink = Some(AlertSink::new(writer));
    let seen = Seen::default();
    let state = Arc::new(ResolverState::new());
    let mut parts = ResolverParts::new(
        router_with(seen.clone()),
        Arc::new(HostState::default()),
        runtime,
        Arc::clone(&state),
        ARTIFACT_QUEUE_CAPACITY,
        WRITTEN_FILE_QUEUE_CAPACITY,
    );
    let identity = |path: &Path| {
        file_identity::from_file(&File::open(path).unwrap())
            .unwrap()
            .object()
    };
    // Buffer the entire burst before running the worker. This makes the
    // regression independent of filesystem speed and thread scheduling.
    for index in 0..2000 {
        let original = temp.path().join(format!("churn-{index}.py"));
        let renamed = temp.path().join(format!("renamed-{index}.py"));
        std::fs::write(&original, b"throwaway").unwrap();
        let object = Some(identity(&original));
        parts
            .ingress
            .handle_event(&file_event(&original, FILE_CREATE_OPCODE, object));
        std::fs::rename(&original, &renamed).unwrap();
        parts
            .ingress
            .handle_event(&file_event(&renamed, 71, object));
        std::fs::remove_file(&renamed).unwrap();
        parts
            .ingress
            .handle_event(&file_event(&renamed, FILE_DELETE_OPCODE, object));
    }
    for index in 0..500 {
        let path = temp.path().join(format!("payload-{index}.py"));
        std::fs::write(&path, bytes).unwrap();
        parts.ingress.handle_event(&file_event(
            &path,
            FILE_CREATE_OPCODE,
            Some(identity(&path)),
        ));
    }
    assert_eq!(
        seen.ingest_seqs().len(),
        6500,
        "base events still reach detection"
    );
    // Treat these buffered events as one arrival burst. Constructing the
    // fixture must not consume scan deadlines on slower filesystems.
    let mut jobs = Vec::new();
    while let Ok(job) = parts.written_rx.try_recv() {
        jobs.push(job);
    }
    let arrived_at = Instant::now();
    for mut job in jobs {
        job.enqueued_at = arrived_at;
        assert!(parts.ingress.written_tx.try_send(job).is_ok());
    }
    drop(parts.ingress);
    run_resolver_stages(
        parts.admission,
        parts.deferred,
        parts.resolver,
        parts.resolve_rx,
        parts.written_rx,
        Arc::new(open_artifact),
    );
    drop(guard);

    let snapshot = state.snapshot();
    assert_eq!(snapshot.queued, 4500);
    assert_eq!(snapshot.resolved, 500);
    assert_eq!(snapshot.open_failed, 4000);
    assert_eq!(snapshot.written_file_dropped, 0);
    assert_eq!(snapshot.queue_saturated, 0);
    let mut engines_by_path: HashMap<String, Vec<String>> = HashMap::new();
    for line in std::fs::read_to_string(&alerts_path).unwrap().lines() {
        let alert: serde_json::Value = serde_json::from_str(line).unwrap();
        engines_by_path
            .entry(alert["file.path"].as_str().unwrap().to_string())
            .or_default()
            .push(alert["edr.rule.engine"].as_str().unwrap().to_string());
    }
    assert_eq!(engines_by_path.len(), 500);
    for engines in engines_by_path.values_mut() {
        engines.sort();
        assert_eq!(engines, &["Ioc", "Yara"]);
    }
}

#[test]
fn file_queue_saturation_does_not_displace_either_image_kind() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let image = temp.path().join("image.exe");
    std::fs::write(&image, bytes).unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    runtime.pe_metadata = true;
    runtime.written_files = Some(written_file_scan_selector());
    let seen = Seen::default();
    let state = Arc::new(ResolverState::new());
    let parts = ResolverParts::new(
        router_with(seen.clone()),
        Arc::new(HostState::default()),
        runtime,
        Arc::clone(&state),
        2,
        2,
    );
    for _ in 0..1000 {
        parts.ingress.handle_event(&file_event(
            &image,
            FILE_CREATE_OPCODE,
            Some(FileObjectIdentity {
                device: 1,
                inode: 1,
            }),
        ));
    }
    parts
        .ingress
        .handle_event(&process_event(&image, Platform::Windows));
    parts.ingress.handle_event(&image_event(&image));
    let snapshot = state.snapshot();
    assert_eq!(snapshot.written_file_dropped, 998);
    assert_eq!(snapshot.process_image_dropped, 0);
    assert_eq!(snapshot.loaded_image_dropped, 0);
    assert_eq!(snapshot.queued, 4);
    // The image queue has its own bound and reports drops by image kind.
    parts
        .ingress
        .handle_event(&process_event(&image, Platform::Windows));
    parts.ingress.handle_event(&image_event(&image));
    assert_eq!(state.snapshot().process_image_dropped, 1);
    assert_eq!(state.snapshot().loaded_image_dropped, 1);
    assert_eq!(state.snapshot().queue_saturated, 1000);
    drop(parts.ingress);
    drop(parts.resolve_rx);
    drop(parts.written_rx);
    parts.admission.run();
    assert_eq!(seen.ingest_seqs().len(), 1004);
}

#[test]
fn blocked_written_file_slots_do_not_delay_process_or_loaded_images() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let image = temp.path().join("image.exe");
    std::fs::write(&image, bytes).unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    runtime.pe_metadata = true;
    runtime.written_files = Some(written_file_scan_selector());
    let gate = Gate::new();
    let (written_tx, written_rx) = std::sync::mpsc::channel();
    let blocked = gate.opener(Some(written_tx));
    let (image_tx, image_rx) = std::sync::mpsc::channel();
    let image_path = image.clone();
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(move |path| {
            if path == image_path {
                let file = open_artifact(path)?;
                image_tx.send(()).unwrap();
                Ok(file)
            } else {
                blocked(path)
            }
        }),
        ARTIFACT_QUEUE_CAPACITY,
    );
    for inode in 0..ARTIFACT_IO_ISOLATION_LIMIT as u64 {
        harness.ingress.handle_event(&file_event(
            &temp.path().join(format!("written-{inode}.exe")),
            FILE_CREATE_OPCODE,
            Some(FileObjectIdentity { device: 1, inode }),
        ));
    }
    for _ in 0..ARTIFACT_IO_ISOLATION_LIMIT {
        written_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    // Let a fifth job settle while all four slots are blocked. The worker
    // then waits for a slot instead of reclaiming vanished burst paths.
    harness.ingress.handle_event(&file_event(
        &temp.path().join("waiting.exe"),
        FILE_CREATE_OPCODE,
        Some(FileObjectIdentity {
            device: 1,
            inode: 99,
        }),
    ));
    std::thread::sleep(WRITTEN_FILE_SETTLE_DELAY);
    // The written-file worker will wait for a slot with its queue full.
    for inode in 0..WRITTEN_FILE_QUEUE_CAPACITY as u64 + 1000 {
        harness.ingress.handle_event(&file_event(
            &temp.path().join(format!("burst-{inode}.exe")),
            FILE_CREATE_OPCODE,
            Some(FileObjectIdentity { device: 1, inode }),
        ));
    }
    harness
        .ingress
        .handle_event(&process_event(&image, Platform::Windows));
    harness.ingress.handle_event(&image_event(&image));
    let first = image_rx.recv_timeout(Duration::from_secs(2));
    let second = image_rx.recv_timeout(Duration::from_secs(2));
    gate.release();
    let state = harness.finish();
    assert!(
        first.is_ok() && second.is_ok(),
        "image resolution waited for written-file I/O"
    );
    assert!(state.snapshot().written_file_dropped > 0);
    assert_eq!(state.snapshot().process_image_dropped, 0);
    assert_eq!(state.snapshot().loaded_image_dropped, 0);
    assert_eq!(state.snapshot().resolved, 2);
}

#[test]
fn unusable_written_paths_are_rejected_before_queueing_and_counted() {
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), b"evil!!");
    runtime.written_files = Some(written_file_scan_selector());
    let seen = Seen::default();
    let harness = Harness::start(
        router_with(seen.clone()),
        runtime,
        Arc::new(|_| panic!("rejected file was opened")),
        1,
    );
    let mut truncated =
        file_event(Path::new("/tmp/payload.exe"), FILE_CREATE_OPCODE, None).into_normalized();
    if let EventFields::FileEvent(fields) = &mut truncated.fields {
        fields.path_truncated = Some("target".into());
    }
    harness
        .ingress
        .handle_event(&CanonicalEvent::from_normalized(truncated));
    harness
        .ingress
        .handle_event(&file_event(Path::new(""), FILE_CREATE_OPCODE, None));
    let state = harness.finish();
    assert_eq!(state.snapshot().written_file_rejected, 2);
    assert_eq!(state.snapshot().queued, 0);
    assert_eq!(seen.ingest_seqs().len(), 2);
}

#[test]
fn selected_written_file_without_event_identity_is_skipped_and_counted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("dropped.bin");
    std::fs::write(&path, b"evil!!").unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), b"evil!!");
    runtime.written_files = Some(select_all());
    let seen = Seen::default();
    let opens = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&opens);
    let harness = Harness::start(
        router_with(seen.clone()),
        runtime,
        Arc::new(move |path| {
            counted.fetch_add(1, Ordering::Relaxed);
            File::open(path)
        }),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness
        .ingress
        .handle_event(&file_event(&path, FILE_CREATE_OPCODE, None));
    let state = harness.finish();

    assert_eq!(seen.ingest_seqs(), vec![1], "the event is still admitted");
    assert_eq!(opens.load(Ordering::Relaxed), 0);
    let snapshot = state.snapshot();
    assert_eq!(snapshot.identity_unavailable, 1);
    assert_eq!(snapshot.queued, 0);
}

#[cfg(windows)]
#[test]
fn windows_written_file_is_bound_on_arrival_and_scanned() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let path = temp.path().join("dropped.py");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    runtime.written_files = Some(select_all());
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness
        .ingress
        .handle_event(&windows_written_file_event(&path));
    let state = harness.finish();

    let snapshot = state.snapshot();
    assert_eq!(snapshot.identity_unavailable, 0);
    assert_eq!(snapshot.identity_mismatch, 0);
    assert_eq!(snapshot.queued, 1);
    assert_eq!(snapshot.resolved, 1);
}

#[cfg(windows)]
#[test]
fn windows_written_file_gone_before_arrival_is_an_open_failure() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("already-removed.py");
    let mut runtime = runtime_with_consumers(temp.path(), b"evil!!");
    runtime.written_files = Some(select_all());
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness
        .ingress
        .handle_event(&windows_written_file_event(&path));
    let state = harness.finish();

    let snapshot = state.snapshot();
    assert_eq!(snapshot.open_failed, 1);
    assert_eq!(snapshot.identity_unavailable, 0);
    assert_eq!(snapshot.resolved, 0);
}

#[cfg(windows)]
#[test]
fn windows_replacement_after_arrival_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let path = temp.path().join("dropped.exe");
    std::fs::write(&path, bytes).unwrap();
    let ArrivalIdentity::Measured(object) = arrival_identity(&path) else {
        panic!("a file on the local temp volume must be measurable");
    };
    assert!(
        on_local_volume(Path::new(r"\\?\C:\Windows")),
        "the verbatim drive form is local"
    );
    assert!(!on_local_volume(Path::new(r"\\server\share\x.exe")));
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    runtime.written_files = Some(select_all());
    let event = windows_written_file_event(&path);
    let mut target = ArtifactTarget::from_event(&event, runtime.written_files.as_ref()).unwrap();
    target.expected = Some(ExpectedIdentity::Object(object));
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    let state = Arc::new(ResolverState::new());
    let worker = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime.clone(),
        Arc::clone(&state),
    );
    assert_eq!(
        worker
            .resolve_with_opener(&target, &plan, open_artifact)
            .unwrap()
            .yara
            .unwrap()
            .len(),
        1
    );

    let replacement = temp.path().join("replacement.bin");
    std::fs::write(&replacement, bytes).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    let error = worker
        .resolve_with_opener(&target, &plan, open_artifact)
        .expect_err("a replacement must not be scanned as the written file");
    assert!(matches!(error, ResolveError::Identity));
    assert_eq!(state.snapshot().identity_mismatch, 1);
}

#[cfg(unix)]
#[test]
fn repeated_written_file_events_debounce_to_one_resolution() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let path = temp.path().join("dropped.exe");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    runtime.written_files = Some(select_all());
    let opens = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&opens);
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(move |path| {
            counted.fetch_add(1, Ordering::Relaxed);
            open_artifact(path)
        }),
        ARTIFACT_QUEUE_CAPACITY,
    );
    let identity = Some(object_identity(&path));

    harness
        .ingress
        .handle_event(&file_event(&path, FILE_CREATE_OPCODE, identity));
    harness
        .ingress
        .handle_event(&file_event(&path, FILE_CREATE_OPCODE, identity));
    let state = harness.finish();

    assert_eq!(opens.load(Ordering::Relaxed), 1);
    let snapshot = state.snapshot();
    assert_eq!(snapshot.queued, 2);
    assert_eq!(snapshot.resolved, 1);
}

#[cfg(unix)]
#[test]
fn written_file_settle_delay_does_not_consume_scan_timeout() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let path = temp.path().join("dropped.exe");
    std::fs::write(&path, bytes).unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    let scanner = crate::scanner::Scanner::new(temp.path().join("yara"))
        .unwrap()
        .with_limits(crate::scanner::ScanLimits {
            // Stay below the 250 ms settle delay while leaving enough
            // headroom for thread scheduling on loaded CI runners.
            timeout: Duration::from_millis(200),
            max_file_bytes: 1024,
        });
    runtime
        .detectors
        .as_ref()
        .unwrap()
        .swap_yara(Arc::new(scanner));
    runtime.written_files = Some(select_all());
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness.ingress.handle_event(&file_event(
        &path,
        FILE_CREATE_OPCODE,
        Some(object_identity(&path)),
    ));
    let state = harness.finish();

    let snapshot = state.snapshot();
    assert_eq!(snapshot.deadline_exceeded, 0);
    assert_eq!(snapshot.resolved, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_empty_consumer_plan_skips_process_and_filesystem_capture() {
    let fixture = FileProcessFixture::start(false);
    let image = fixture.root.path().join("sleep");
    let event = live_process_event(fixture.child.id(), &image);
    let target = ArtifactTarget::select_event(&event, None).unwrap();
    assert_eq!(target.path, image);
    assert!(target.process_identity.is_none());
    assert!(target.expected.is_none());
    assert!(target.linux_process_path.is_none());

    let seen = Seen::default();
    let mut parts = ResolverParts::new(
        router_with(seen.clone()),
        Arc::new(HostState::default()),
        ArtifactRuntime::capture(Platform::Linux),
        Arc::new(ResolverState::new()),
        ARTIFACT_QUEUE_CAPACITY,
        WRITTEN_FILE_QUEUE_CAPACITY,
    );
    parts.resolver.process_path_opener = Arc::new(|_| panic!("no consumer needs this path"));
    parts.ingress.handle_event(&event);
    assert_eq!(seen.ingest_seqs(), vec![1]);
    assert!(parts.resolve_rx.try_recv().is_err());
    assert_eq!(parts.ingress.state.snapshot().queued, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn blocked_linux_context_resolution_is_isolated_and_does_not_hold_admission() {
    let fixture = FileProcessFixture::start(true);
    let image = fixture.root.path().join("sleep");
    let event = live_process_event(fixture.child.id(), &image);
    let captured = ArtifactTarget::from_event(&event, None).unwrap();
    assert!(
        captured.expected.is_none(),
        "script path must not be traversed at admission"
    );
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    runtime.detectors.as_ref().unwrap().swap_yara(Arc::new(
        crate::scanner::Scanner::new(temp.path().join("yara"))
            .unwrap()
            .with_limits(crate::scanner::ScanLimits {
                timeout: Duration::from_millis(40),
                max_file_bytes: 1024,
            }),
    ));
    let seen = Seen::default();
    let mut parts = ResolverParts::new(
        router_with(seen.clone()),
        Arc::new(HostState::default()),
        runtime,
        Arc::new(ResolverState::new()),
        ARTIFACT_QUEUE_CAPACITY,
        WRITTEN_FILE_QUEUE_CAPACITY,
    );
    let gate = Gate::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let blocked = gate.opener(Some(entered_tx));
    parts.resolver.process_path_opener = Arc::new(move |path| {
        assert_eq!(std::thread::current().name(), Some("artifact-io"));
        blocked(path)
    });
    let reads = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::clone(&reads);
    let harness = Harness::from_parts(
        parts,
        Arc::new(move |path| {
            read_count.fetch_add(1, Ordering::Relaxed);
            open_artifact(path)
        }),
    );
    harness.ingress.handle_event(&event);
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    harness.ingress.handle_event(&windows_file_event(2));
    assert_eq!(seen.ingest_seqs(), vec![1, 2]);
    // An OS call keeps its slot but cannot hold admission or shutdown forever.
    let state = harness.finish();
    gate.release();
    let deadline = Instant::now() + Duration::from_secs(5);
    while state.snapshot().deadline_exceeded == 0 {
        assert!(
            Instant::now() < deadline,
            "late contextual I/O was not expired"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(state.snapshot().resolved, 0);
    assert_eq!(state.snapshot().identity_mismatch, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_queued_host_binaries_keep_absolute_and_relative_coverage_after_exit() {
    use sha2::Digest;

    let mut fixture = FileProcessFixture::start(false);
    let image = fixture.root.path().join("sleep");
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime.clone(),
        Arc::new(ResolverState::new()),
    );
    let jobs: Vec<_> = [image.as_path(), Path::new("./sleep")]
        .into_iter()
        .map(|path| {
            let event = live_process_event(fixture.child.id(), path);
            let target = ArtifactTarget::from_event(&event, None).unwrap();
            assert!(target.expected.is_some());
            let plan = ResolvePlan::snapshot(&runtime, &event, &target);
            (target, plan)
        })
        .collect();
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    for (target, plan) in jobs {
        let artifact = resolver
            .resolve_with_opener(&target, &plan, |path| {
                assert_eq!(path, image);
                assert!(path.is_absolute(), "never use the agent's cwd for fallback");
                open_artifact(path)
            })
            .unwrap();
        assert_eq!(artifact.yara.unwrap().len(), 1);
        assert_eq!(
            artifact.hashes.unwrap().sha256.as_deref(),
            Some(hex::encode(sha2::Sha256::digest(&fixture.bytes)).as_str())
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_queued_scripts_with_sensor_identity_can_use_the_host_fallback() {
    let mut fixture = FileProcessFixture::start(true);
    let image = fixture.root.path().join("sleep");
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let mut normalized = live_process_event(fixture.child.id(), &image).into_normalized();
    let EventFields::ProcessCreation(fields) = &mut normalized.fields else {
        unreachable!()
    };
    fields.exec = Some(Box::new(crate::models::ExecMetadata {
        file_identity: file_identity::from_path(&image),
        ..Default::default()
    }));
    let event = CanonicalEvent::from_normalized(normalized);
    let target = ArtifactTarget::from_event(&event, None).unwrap();
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    let mut resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime,
        Arc::new(ResolverState::new()),
    );
    resolver.process_path_opener = Arc::new(|_| panic!("sensor already supplied script identity"));
    let artifact = resolver
        .resolve_with_opener(&target, &plan, open_artifact)
        .unwrap();
    assert_eq!(artifact.yara.unwrap().len(), 1);
    assert!(artifact.hashes.unwrap().sha256.is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_descriptor_preflight_defers_allowlisting_until_executable_capture() {
    let fixture = MemfdFixture::start();
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = ArtifactRuntime::capture(Platform::Linux);
    let consumers = runtime_with_consumers(temp.path(), &fixture.bytes);
    runtime.detectors = Some(DetectorStore::new(
        Arc::new(Engine::new_for_platform(Platform::Linux)),
        consumers
            .detectors
            .as_ref()
            .unwrap()
            .yara_with_generation()
            .1,
        Arc::new(crate::ioc::IocEngine::disabled()),
    ));
    runtime.yara_allowlist_paths = vec!["/proc/".into()];
    let event = fixture.event(&fixture.descriptor_path);
    let selected = ArtifactTarget::select_event(&event, None).unwrap();
    assert!(
        ResolvePlan::snapshot(&runtime, &event, &selected)
            .needs
            .yara
    );
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime.clone(),
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );
    harness.ingress.handle_event(&event);
    assert_eq!(harness.finish().snapshot().resolved, 1);

    runtime.yara_allowlist_paths = vec!["/memfd:".into()];
    assert!(
        ResolvePlan::snapshot(&runtime, &event, &selected)
            .needs
            .yara
    );
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(|_| panic!("measured executable is allowlisted")),
        ARTIFACT_QUEUE_CAPACITY,
    );
    harness.ingress.handle_event(&event);
    assert_eq!(harness.finish().snapshot().queued, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_queued_host_fallback_rejects_a_replaced_file() {
    let mut fixture = FileProcessFixture::start(false);
    let image = fixture.root.path().join("sleep");
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let event = live_process_event(fixture.child.id(), &image);
    let target = ArtifactTarget::from_event(&event, None).unwrap();
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    let replacement = fixture.root.path().join("replacement");
    std::fs::write(&replacement, &fixture.bytes).unwrap();
    std::fs::rename(replacement, &image).unwrap();
    let resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime,
        Arc::new(ResolverState::new()),
    );
    assert!(matches!(
        resolver.resolve_with_opener(&target, &plan, open_artifact),
        Err(ResolveError::Identity)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_queued_fallback_requires_confirmed_namespace_and_captured_lifetime() {
    let mut fixture = FileProcessFixture::start(false);
    let image = fixture.root.path().join("sleep");
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime.clone(),
        Arc::new(ResolverState::new()),
    );
    let mut events = Vec::new();
    for namespace in [None, Some("0".into())] {
        let mut event = live_process_event(fixture.child.id(), &image).into_normalized();
        let EventFields::ProcessCreation(fields) = &mut event.fields else {
            unreachable!()
        };
        fields.linux_identity.mount_namespace = namespace;
        events.push(CanonicalEvent::from_normalized(event));
    }
    let mut stale = live_process_event(fixture.child.id(), &image);
    stale.process_start_key = Some(crate::sensor::ProcessStartKey {
        pid: fixture.child.id(),
        start_time: u64::MAX,
    });
    events.push(stale);
    let jobs: Vec<_> = events
        .iter()
        .map(|event| {
            let target = ArtifactTarget::from_event(event, None).unwrap();
            let plan = ResolvePlan::snapshot(&runtime, event, &target);
            (target, plan)
        })
        .collect();
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    for (target, plan) in jobs {
        assert!(matches!(
            resolver.resolve_with_opener(&target, &plan, |_| {
                panic!("must not open an unrelated host file or a reused PID's image")
            }),
            Err(ResolveError::Identity)
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_binary_artifacts_use_exe_for_absolute_relative_symlink_and_deleted_paths() {
    use sha2::Digest;
    use std::os::unix::fs::symlink;

    let fixture = FileProcessFixture::start(false);
    let image = fixture.root.path().join("sleep");
    let link = fixture.root.path().join("linked");
    symlink(&image, &link).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let state = Arc::new(ResolverState::new());
    let resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime.clone(),
        Arc::clone(&state),
    );
    for path in [image.as_path(), Path::new("./sleep"), link.as_path()] {
        let event = live_process_event(fixture.child.id(), path);
        let mut target = ArtifactTarget::from_event(&event, None).unwrap();
        // Symlink identity is resolved in the I/O worker, never at admission.
        resolver.prepare_process_target(&mut target).unwrap();
        assert_eq!(
            target.path,
            PathBuf::from(format!("/proc/{}/exe", fixture.child.id()))
        );
        assert_eq!(target.display_path, path.to_string_lossy());
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let artifact = resolver
            .resolve_with_opener(&target, &plan, open_artifact)
            .unwrap();
        assert_eq!(artifact.yara.unwrap().len(), 1);
        assert_eq!(
            artifact.hashes.unwrap().sha256.as_deref(),
            Some(hex::encode(sha2::Sha256::digest(&fixture.bytes)).as_str())
        );
    }
    // Snapshot after unlinking, so exe is the only remaining path to the bytes.
    std::fs::remove_file(&image).unwrap();
    let event = live_process_event(fixture.child.id(), &image);
    let target = ArtifactTarget::from_event(&event, None).unwrap();
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    assert!(resolver
        .resolve_with_opener(&target, &plan, open_artifact)
        .is_ok());
    assert_eq!(state.snapshot().identity_mismatch, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_scripts_scan_script_bytes_and_allowlist_the_original_path() {
    use sha2::Digest;
    let fixture = FileProcessFixture::start(true);
    let image = fixture.root.path().join("sleep");
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    runtime.yara_allowlist_paths = vec!["/bin/".into(), "/usr/bin/".into()];
    let state = Arc::new(ResolverState::new());
    let resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime.clone(),
        Arc::clone(&state),
    );
    for path in [image.as_path(), Path::new("./sleep")] {
        let event = live_process_event(fixture.child.id(), path);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        assert!(target
            .path
            .to_string_lossy()
            .contains(if path.is_absolute() {
                "/root/"
            } else {
                "/cwd/"
            }));
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        assert!(
            plan.needs.yara,
            "allowlisting the interpreter must not allowlist the script"
        );
        let artifact = resolver
            .resolve_with_opener(&target, &plan, open_artifact)
            .unwrap();
        assert_eq!(artifact.yara.unwrap().len(), 1);
        assert_eq!(
            artifact.hashes.unwrap().sha256.as_deref(),
            Some(hex::encode(sha2::Sha256::digest(&fixture.bytes)).as_str())
        );
    }
    runtime
        .yara_allowlist_paths
        .push(image.to_string_lossy().into_owned());
    let event = live_process_event(fixture.child.id(), &image);
    let mut target = ArtifactTarget::from_event(&event, None).unwrap();
    assert!(!ResolvePlan::snapshot(&runtime, &event, &target).needs.yara);
    // Without sensor-provided identity a script is bound in the worker.
    // Changing it after that snapshot must still be rejected at the open.
    resolver.prepare_process_target(&mut target).unwrap();
    std::fs::write(&image, b"changed script").unwrap();
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    assert!(matches!(
        resolver.resolve_with_opener(&target, &plan, open_artifact),
        Err(ResolveError::Identity)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_process_artifacts_reject_changed_lifetimes_before_opening() {
    let mut fixture = FileProcessFixture::start(false);
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let event = live_process_event(fixture.child.id(), &fixture.root.path().join("sleep"));
    let target = ArtifactTarget::from_event(&event, None).unwrap();
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    let resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime,
        Arc::new(ResolverState::new()),
    );
    let mut stale = target.clone();
    stale.process_identity.as_mut().unwrap().start_time = Some(u64::MAX);
    assert!(matches!(
        resolver.resolve_with_opener(&stale, &plan, |_| panic!(
            "must reject stale lifetime before open"
        )),
        Err(ResolveError::Identity)
    ));
    let mut unconfirmed_namespace = target.clone();
    unconfirmed_namespace
        .linux_process_path
        .as_mut()
        .unwrap()
        .host_fallback = None;
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    assert!(matches!(
        resolver.resolve_with_opener(&unconfirmed_namespace, &plan, |_| panic!(
            "must reject exited process without a safe fallback before open"
        )),
        Err(ResolveError::Identity)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_exited_processes_only_fall_back_in_the_confirmed_host_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("same-name-on-host");
    let bytes = b"evil!!";
    std::fs::write(&path, bytes).unwrap();
    let runtime = runtime_with_consumers(temp.path(), bytes);
    let resolver = ArtifactResolver::new(
        Arc::new(HostState::default()),
        runtime.clone(),
        Arc::new(ResolverState::new()),
    );
    for namespace in [None, Some("0".to_string())] {
        let mut event = process_event(&path, Platform::Linux).into_normalized();
        let EventFields::ProcessCreation(fields) = &mut event.fields else {
            unreachable!()
        };
        fields.process_id = Some(u32::MAX.to_string());
        fields.linux_identity.mount_namespace = namespace;
        let event = CanonicalEvent::from_normalized(event);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        assert!(matches!(
            resolver.resolve_with_opener(&target, &plan, |_| panic!(
                "must not open a same-named host file"
            )),
            Err(ResolveError::Identity)
        ));
    }
    let event = live_process_event(u32::MAX, &path);
    let target = ArtifactTarget::from_event(&event, None).unwrap();
    assert_eq!(target.path, path);
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    assert!(resolver
        .resolve_with_opener(&target, &plan, open_artifact)
        .is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn memfd_exec_scans_its_own_bytes_and_emits_yara_and_hash_alerts() {
    let fixture = MemfdFixture::start();
    let fd = fixture.descriptor_path.rsplit('/').next().unwrap();
    assert!(
        !std::fs::read_link(format!("/proc/{}/fd/{fd}", fixture.child.id()))
            .is_ok_and(|path| crate::utils::process::is_memfd_image(&path.to_string_lossy())),
        "close-on-exec descriptor must not reference the memfd"
    );
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let alerts_path = temp.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
    runtime.alert_sink = Some(AlertSink::new(writer));
    let expected_path = PathBuf::from(format!("/proc/{}/exe", fixture.child.id()));
    let opens = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&opens);
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(move |path| {
            assert_eq!(
                path, expected_path,
                "never open the agent's descriptor table"
            );
            counted.fetch_add(1, Ordering::Relaxed);
            open_artifact(path)
        }),
        ARTIFACT_QUEUE_CAPACITY,
    );
    for image in [
        fixture.descriptor_path.as_str(),
        "/dev/fd/3",
        "/memfd:payload (deleted)",
    ] {
        harness.ingress.handle_event(&fixture.event(image));
    }
    let state = harness.finish();
    drop(guard);
    let alerts = read_alerts(&alerts_path);
    assert_eq!(opens.load(Ordering::Relaxed), 3);
    assert_eq!(state.snapshot().resolved, 3);
    assert_eq!(state.snapshot().identity_mismatch, 0);
    assert_eq!(
        alerts
            .iter()
            .filter(|alert| alert["edr.rule.engine"] == "Yara")
            .count(),
        3
    );
    assert_eq!(
        alerts
            .iter()
            .filter(|alert| alert["edr.rule.engine"] == "Ioc")
            .count(),
        3
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn memfd_memory_worker_scans_image_with_default_region_filters() {
    let fixture = MemfdFixture::start();
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    std::fs::write(
        temp.path().join("yara/marker.yar"),
        r#"rule ElfImage { strings: $elf = { 7F 45 4C 46 } condition: $elf at 0 }"#,
    )
    .unwrap();
    let detectors = runtime.detectors.unwrap();
    detectors.swap_yara(Arc::new(
        crate::scanner::Scanner::new(temp.path().join("yara")).unwrap(),
    ));
    let alerts_path = temp.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
    let (response, response_worker) = ResponseEngine::new(Arc::new(
        arc_swap::ArcSwap::from_pointee(AppConfig::default().response),
    ));
    let (tx, rx) = mpsc::channel(1);
    let handler = scanner::YaraMemoryEventHandler {
        tx,
        allowlist_paths: Vec::new(),
        scan_all_processes: false,
    };
    let worker = crate::runtime::yara::spawn_yara_memory_worker(
        detectors,
        AlertSink::new(writer),
        response,
        crate::memory::MemoryScanConfig {
            max_process_bytes: 64 * 1024 * 1024,
            max_region_bytes: 8 * 1024 * 1024,
            include_private: true,
            include_image: false,
            include_mapped: false,
            delay_ms: 0,
        },
        MatchDebugLevel::Off,
        rx,
        Platform::Linux,
        "yara-memory",
    );
    handler.handle_event(&fixture.event(&fixture.descriptor_path));
    drop(handler);
    worker.await.unwrap();
    response_worker.await.unwrap();
    drop(guard);
    let alerts = read_alerts(&alerts_path);
    assert!(
        alerts.iter().any(|alert| alert["rule.name"] == "ElfImage"
            && alert["edr.yara.scan_source"] == "process_memory"),
        "memfd image must be scanned with mapped-file scanning disabled: {alerts:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn memfd_exec_rejects_changed_process_and_file_identities() {
    let fixture = MemfdFixture::start();
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime_with_consumers(temp.path(), &fixture.bytes);
    let event = fixture.event(&fixture.descriptor_path);
    let target = ArtifactTarget::from_event(&event, None).unwrap();
    let plan = ResolvePlan::snapshot(&runtime, &event, &target);
    let state = Arc::new(ResolverState::new());
    let resolver =
        ArtifactResolver::new(Arc::new(HostState::default()), runtime, Arc::clone(&state));
    let mut recycled_event = event;
    recycled_event.process_start_key = Some(crate::sensor::ProcessStartKey {
        pid: fixture.child.id(),
        start_time: u64::MAX,
    });
    let recycled = ArtifactTarget::from_event(&recycled_event, None).unwrap();
    assert!(matches!(
        resolver.resolve_with_opener(&recycled, &plan, |_| {
            panic!("must reject a different lifetime before opening")
        }),
        Err(ResolveError::Identity)
    ));
    let wrong_file = tempfile::NamedTempFile::new().unwrap();
    assert!(matches!(
        resolver.resolve_with_opener(&target, &plan, |_| { File::open(wrong_file.path()) }),
        Err(ResolveError::Identity)
    ));
    assert_eq!(state.snapshot().identity_mismatch, 2);
}

#[cfg(target_os = "linux")]
#[test]
fn memfd_exec_queues_memory_with_broad_scanning_disabled() {
    let fixture = MemfdFixture::start();
    let (tx, mut rx) = mpsc::channel(4);
    let handler = scanner::YaraMemoryEventHandler {
        tx,
        allowlist_paths: Vec::new(),
        scan_all_processes: false,
    };
    handler.handle_event(&fixture.event("/bin/sleep"));
    assert!(rx.try_recv().is_err());
    for image in [
        fixture.descriptor_path.as_str(),
        "/dev/fd/3",
        "/memfd:payload (deleted)",
    ] {
        handler.handle_event(&fixture.event(image));
        let job = rx
            .try_recv()
            .expect("fileless exec must queue a memory scan");
        assert!(job.memfd_backed);
        assert_eq!(job.expected_identity.pid, fixture.child.id());
        assert_eq!(job.expected_identity.image, "/memfd:payload");
        crate::utils::validate_process_identity(&job.expected_identity).unwrap();
    }
}

/// A written file is reported as the file its event named, with the
/// writing process, never as a process image of that path.
#[cfg(unix)]
#[test]
fn written_file_alerts_describe_the_file_and_its_writer() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = b"evil!!";
    let path = temp.path().join("dropped.exe");
    std::fs::write(&path, bytes).unwrap();
    let alerts_path = temp.path().join("alerts.ndjson");
    let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
    let mut runtime = runtime_with_consumers(temp.path(), bytes);
    runtime.written_files = Some(select_all());
    runtime.alert_sink = Some(AlertSink::new(writer));
    let harness = Harness::start(
        Arc::new(SensorEventRouter::new()),
        runtime,
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness.ingress.handle_event(&file_event(
        &path,
        FILE_CREATE_OPCODE,
        Some(object_identity(&path)),
    ));
    let state = harness.finish();
    drop(guard);

    assert_eq!(state.snapshot().resolved, 1);
    let alerts: Vec<serde_json::Value> = std::fs::read_to_string(&alerts_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let engines: Vec<&str> = alerts
        .iter()
        .map(|alert| alert["edr.rule.engine"].as_str().unwrap())
        .collect();
    assert_eq!(
        engines.len(),
        2,
        "one IOC hash and one YARA alert: {alerts:?}"
    );
    assert!(engines.contains(&"Ioc") && engines.contains(&"Yara"));
    for alert in &alerts {
        assert_eq!(alert["file.path"], path.to_string_lossy().as_ref());
        assert_eq!(alert["process.executable"], WRITER_IMAGE);
        assert_eq!(alert["process.pid"], 43);
    }
}

#[test]
fn a_hash_rule_fires_once_in_the_deferred_pass_and_never_at_admission() {
    use sha2::Digest;

    let temp = tempfile::tempdir().unwrap();
    let bytes = b"deferred sample image";
    let image = temp.path().join("sample.exe");
    std::fs::write(&image, bytes).unwrap();
    let sha256 = hex::encode(sha2::Sha256::digest(bytes));
    let (runtime, detectors, alerts_path, guard) = detecting_runtime(
        temp.path(),
        &[
            windows_rule(
                "By image",
                "process_creation",
                "  selection:\n    Image|endswith: sample.exe\n  condition: selection\n",
            ),
            windows_rule(
                "By hash",
                "process_creation",
                &format!(
                    "  selection:\n    Hashes|contains: SHA256={}\n  condition: selection\n",
                    sha256.to_ascii_uppercase()
                ),
            ),
        ],
    );
    let sink = runtime.alert_sink.clone().unwrap();
    let harness = Harness::start(
        router_with(AdmissionDetection { detectors, sink }),
        runtime,
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness
        .ingress
        .handle_event(&process_event(&image, Platform::Windows));
    let state = harness.finish();
    drop(guard);

    let alerts = read_alerts(&alerts_path);
    assert_eq!(rule_names(&alerts), vec!["By hash", "By image"]);
    let by_hash = alerts
        .iter()
        .find(|alert| alert["rule.name"] == "By hash")
        .unwrap();
    assert_eq!(by_hash["process.hash.sha256"], sha256.as_str());
    assert!(
        by_hash.get("process.hash.md5").is_none(),
        "only SHA256 was requested"
    );
    let snapshot = state.snapshot();
    assert_eq!(snapshot.deferred_queued, 1);
    assert_eq!(snapshot.deferred_enriched, 1);
    assert_eq!(snapshot.deferred_unenriched, 0);
    assert_eq!(
        snapshot.correlation_lateness_ms,
        DEFERRED_DETECTION_BUDGET.as_millis() as u64
    );
    assert_eq!(snapshot.hash_entries, 1);
}

#[test]
fn deferred_rules_evaluate_once_without_hashes_when_the_image_cannot_be_read() {
    let temp = tempfile::tempdir().unwrap();
    let (runtime, detectors, alerts_path, guard) = detecting_runtime(
        temp.path(),
        &[windows_rule(
            "Hash or image",
            "process_creation",
            "  hash:\n    Hashes|contains: IMPHASH=00\n  image:\n    Image|endswith: gone.exe\n  condition: hash or image\n",
        )],
    );
    let sink = runtime.alert_sink.clone().unwrap();
    let harness = Harness::start(
        router_with(AdmissionDetection { detectors, sink }),
        runtime,
        Arc::new(open_artifact),
        ARTIFACT_QUEUE_CAPACITY,
    );

    harness.ingress.handle_event(&process_event(
        &temp.path().join("gone.exe"),
        Platform::Windows,
    ));
    let state = harness.finish();
    drop(guard);

    assert_eq!(
        rule_names(&read_alerts(&alerts_path)),
        vec!["Hash or image"]
    );
    let snapshot = state.snapshot();
    assert_eq!(snapshot.open_failed, 1);
    assert_eq!(snapshot.deferred_unenriched, 1);
    assert_eq!(
        snapshot.deferred_budget_exceeded, 0,
        "a failed read releases the pass at once"
    );
}

#[test]
fn a_blocked_resolution_releases_the_deferred_pass_at_its_budget() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("blocked.exe");
    std::fs::write(&image, b"artifact").unwrap();
    let (runtime, detectors, alerts_path, guard) = detecting_runtime(
        temp.path(),
        &[windows_rule(
            "Hash or image",
            "process_creation",
            "  hash:\n    Hashes|contains: MD5=00\n  image:\n    Image|endswith: blocked.exe\n  condition: hash or image\n",
        )],
    );
    let sink = runtime.alert_sink.clone().unwrap();
    let gate = Gate::new();
    let harness = Harness::start(
        router_with(AdmissionDetection { detectors, sink }),
        runtime,
        gate.opener(None),
        ARTIFACT_QUEUE_CAPACITY,
    );

    let submitted = Instant::now();
    harness
        .ingress
        .handle_event(&process_event(&image, Platform::Windows));
    let give_up = submitted + DEFERRED_DETECTION_BUDGET + Duration::from_secs(5);
    while state_of(&harness).deferred_budget_exceeded == 0 {
        assert!(
            Instant::now() < give_up,
            "the deferred pass was never released"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let waited = submitted.elapsed();
    assert!(
        waited >= DEFERRED_DETECTION_BUDGET,
        "released early: {waited:?}"
    );
    gate.release();
    harness.finish();
    drop(guard);

    assert_eq!(
        rule_names(&read_alerts(&alerts_path)),
        vec!["Hash or image"]
    );
}
