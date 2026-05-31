//! Active response integration tests.
//!
//! Run CI-safe tests:
//! ```sh
//! cargo test --test active_response
//! ```
//!
//! Run ignored live process tests manually after building the target binary:
//! ```sh
//! cargo build --example memory_target
//! cargo test --test active_response -- --include-ignored
//! ```

use rustinel::{
    config::ResponseConfig,
    models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
        ProcessCreationFields,
    },
    response::{ResponseDecision, ResponseEngine},
    sensor::Platform,
};
use std::{process::Stdio, time::Duration};

fn memory_target_exe() -> &'static str {
    if cfg!(windows) {
        "target\\debug\\examples\\memory_target.exe"
    } else {
        "target/debug/examples/memory_target"
    }
}

fn build_yara_alert(pid: u32, image: &str) -> Alert {
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: "ExampleMarkerString".to_string(),
        rule_description: None,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image.to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some(pid.to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        },
        match_details: None,
    }
}

fn response_config(
    enabled: bool,
    prevention_enabled: bool,
    min_severity: &str,
    allowlist_images: Vec<String>,
    allowlist_paths: Vec<String>,
) -> ResponseConfig {
    ResponseConfig {
        enabled,
        prevention_enabled,
        min_severity: min_severity.to_string(),
        channel_capacity: 128,
        allowlist_images,
        allowlist_paths,
    }
}

fn decision_for(cfg: ResponseConfig, alert: &Alert) -> ResponseDecision {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let (engine, worker) = ResponseEngine::new(&cfg);
        let decision = engine.decision_for_alert(alert);
        drop(engine);
        worker.abort();
        let _ = worker.await;
        decision
    })
}

#[test]
fn response_dry_run_no_panic() {
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: false,
        min_severity: "critical".to_string(),
        channel_capacity: 128,
        allowlist_images: vec![],
        allowlist_paths: vec![],
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let (engine, worker) = ResponseEngine::new(&cfg);
        let alert = build_yara_alert(99_999_999, "C:\\test\\fake.exe");
        engine.handle_alert(&alert);

        tokio::time::sleep(Duration::from_millis(300)).await;

        drop(engine);
        worker.abort();
        let _ = worker.await;
    });
}

#[test]
fn response_engine_skips_below_min_severity() {
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        min_severity: "critical".to_string(),
        channel_capacity: 128,
        allowlist_images: vec![],
        allowlist_paths: vec![],
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let (engine, worker) = ResponseEngine::new(&cfg);
        let mut alert = build_yara_alert(99_999_999, "C:\\test\\fake.exe");
        alert.severity = AlertSeverity::Low;
        alert.engine = DetectionEngine::Sigma;
        engine.handle_alert(&alert);
        tokio::time::sleep(Duration::from_millis(200)).await;

        drop(engine);
        worker.abort();
        let _ = worker.await;
    });
}

#[test]
fn response_decision_outcomes_are_testable() {
    let alert = build_yara_alert(4242, "C:\\test\\fake.exe");
    assert_eq!(
        decision_for(
            response_config(false, false, "critical", vec![], vec![]),
            &alert
        ),
        ResponseDecision::Disabled
    );

    let mut low_sigma = alert.clone();
    low_sigma.engine = DetectionEngine::Sigma;
    low_sigma.severity = AlertSeverity::Low;
    assert_eq!(
        decision_for(
            response_config(true, false, "critical", vec![], vec![]),
            &low_sigma
        ),
        ResponseDecision::BelowSeverity {
            severity: AlertSeverity::Low,
            min_severity: AlertSeverity::Critical,
        }
    );

    assert_eq!(
        decision_for(
            response_config(true, false, "critical", vec![], vec![]),
            &build_yara_alert(4, "C:\\test\\fake.exe")
        ),
        ResponseDecision::ProtectedPid { pid: 4 }
    );

    let mut missing_pid = build_yara_alert(4242, "C:\\test\\fake.exe");
    if let EventFields::ProcessCreation(fields) = &mut missing_pid.event.fields {
        fields.process_id = None;
    }
    assert_eq!(
        decision_for(
            response_config(true, false, "critical", vec![], vec![]),
            &missing_pid
        ),
        ResponseDecision::MissingPid
    );

    let mut missing_image = build_yara_alert(4242, "C:\\test\\fake.exe");
    if let EventFields::ProcessCreation(fields) = &mut missing_image.event.fields {
        fields.image = None;
    }
    assert_eq!(
        decision_for(
            response_config(true, false, "critical", vec![], vec![]),
            &missing_image
        ),
        ResponseDecision::MissingImage { pid: 4242 }
    );
}

#[test]
fn response_decision_respects_allowlists_and_mode() {
    let image = if cfg!(windows) {
        r"C:\Trusted\fake.exe"
    } else {
        "/trusted/fake"
    };
    let alert = build_yara_alert(4242, image);

    assert!(matches!(
        decision_for(
            response_config(
                true,
                false,
                "critical",
                vec![if cfg!(windows) {
                    "fake.exe".to_string()
                } else {
                    "fake".to_string()
                }],
                vec![]
            ),
            &alert
        ),
        ResponseDecision::Allowlisted { pid: 4242, .. }
    ));

    let allowlist_path = if cfg!(windows) {
        r"C:\Trusted".to_string()
    } else {
        "/trusted".to_string()
    };
    assert!(matches!(
        decision_for(
            response_config(true, false, "critical", vec![], vec![allowlist_path]),
            &alert
        ),
        ResponseDecision::Allowlisted { pid: 4242, .. }
    ));

    assert!(matches!(
        decision_for(
            response_config(true, false, "critical", vec![], vec![]),
            &alert
        ),
        ResponseDecision::DryRun { pid: 4242, .. }
    ));

    assert!(matches!(
        decision_for(
            response_config(true, true, "critical", vec![], vec![]),
            &alert
        ),
        ResponseDecision::Terminate { pid: 4242, .. }
    ));
}

#[test]
fn response_decision_uses_detector_pipeline_severity_rules() {
    let mut yara = build_yara_alert(4242, "C:\\test\\fake.exe");
    yara.severity = AlertSeverity::Low;
    assert!(matches!(
        decision_for(
            response_config(true, true, "critical", vec![], vec![]),
            &yara
        ),
        ResponseDecision::Terminate { pid: 4242, .. }
    ));

    let mut sigma = yara.clone();
    sigma.engine = DetectionEngine::Sigma;
    sigma.severity = AlertSeverity::High;
    assert!(matches!(
        decision_for(response_config(true, true, "high", vec![], vec![]), &sigma),
        ResponseDecision::Terminate { pid: 4242, .. }
    ));
    assert!(matches!(
        decision_for(
            response_config(true, true, "critical", vec![], vec![]),
            &sigma
        ),
        ResponseDecision::BelowSeverity { .. }
    ));

    let mut ioc = sigma.clone();
    ioc.engine = DetectionEngine::Ioc;
    assert!(matches!(
        decision_for(
            response_config(true, true, "high", vec!["fake.exe".to_string()], vec![]),
            &ioc
        ),
        ResponseDecision::Allowlisted { .. }
    ));
}

#[test]
#[ignore = "needs memory_target: cargo build --example memory_target"]
fn response_dry_run_does_not_kill_child() {
    let exe = memory_target_exe();
    if !std::path::Path::new(exe).exists() {
        panic!("binary not found at {exe}. Run: cargo build --example memory_target");
    }

    let mut child = std::process::Command::new(exe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn memory_target");
    let pid = child.id();

    std::thread::sleep(Duration::from_millis(200));

    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: false,
        min_severity: "critical".to_string(),
        channel_capacity: 128,
        allowlist_images: vec![],
        allowlist_paths: vec![],
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let (engine, worker) = ResponseEngine::new(&cfg);
        let alert = build_yara_alert(pid, exe);
        engine.handle_alert(&alert);

        tokio::time::sleep(Duration::from_millis(400)).await;

        let still_running = child.try_wait().expect("try_wait failed").is_none();
        assert!(
            still_running,
            "dry-run must not terminate the child process"
        );

        child.kill().ok();
        let _ = child.wait();
        drop(engine);
        worker.abort();
        let _ = worker.await;
    });
}

#[test]
#[ignore = "spawns memory_target and kills it; build first: cargo build --example memory_target"]
fn response_reaction_terminates_child_process() {
    let exe = memory_target_exe();
    if !std::path::Path::new(exe).exists() {
        panic!("binary not found at {exe}. Run: cargo build --example memory_target");
    }

    let mut child = std::process::Command::new(exe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn memory_target");
    let pid = child.id();

    std::thread::sleep(Duration::from_millis(300));

    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        min_severity: "critical".to_string(),
        channel_capacity: 128,
        allowlist_images: vec![],
        allowlist_paths: vec![],
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let (engine, worker) = ResponseEngine::new(&cfg);
        let alert = build_yara_alert(pid, exe);
        engine.handle_alert(&alert);

        tokio::time::sleep(Duration::from_millis(600)).await;

        let status = child.try_wait().expect("try_wait failed");
        assert!(
            status.is_some(),
            "response engine should have terminated the child process (pid {})",
            pid
        );

        drop(engine);
        worker.abort();
        let _ = worker.await;
    });
}
