//! Cross-module contracts for existing path allowlist behavior.

mod common;

use std::sync::Arc;

use rustinel::{
    config::AppConfig,
    ioc::IocEngine,
    models::{Alert, AlertSeverity, DetectionEngine, EventFields},
    response::{ResponseDecision, ResponseEngine},
    scanner::{is_path_allowlisted, normalize_allowlist_paths},
    sensor::Platform,
};

async fn check(prefix: &str, path: &str, expected: [bool; 3]) {
    let fixture = common::IocFixture::new();
    let mut ioc_cfg = fixture.config();
    ioc_cfg.hash_allowlist_paths = vec![prefix.into()];
    let ioc = IocEngine::load(&ioc_cfg);
    let yara_paths = normalize_allowlist_paths(&[prefix.into()]);

    let mut response_cfg = AppConfig::default().response;
    response_cfg.enabled = true;
    response_cfg.prevention_enabled = false;
    response_cfg.min_severity = "low".into();
    response_cfg.allowlist_images.clear();
    response_cfg.allowlist_paths = vec![prefix.into()];
    let (response, worker) =
        ResponseEngine::new(Arc::new(arc_swap::ArcSwap::from_pointee(response_cfg)));
    let mut event = common::TestNormalizer::new(false)
        .normalizer
        .normalize(&common::process_start_event(Platform::Linux))
        .unwrap();
    let EventFields::ProcessCreation(fields) = &mut event.fields else {
        panic!("process fixture");
    };
    fields.image = Some(path.into());
    fields.process_id = Some(u32::MAX.to_string());
    let decision = response.decision_for_alert(&Alert {
        severity: AlertSeverity::Critical,
        rule_name: "allowlist contract".into(),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Sigma,
        event,
        match_details: None,
    });
    assert!(matches!(
        decision,
        ResponseDecision::Allowlisted { .. } | ResponseDecision::DryRun { .. }
    ));
    assert_eq!(
        [
            is_path_allowlisted(path, &yara_paths),
            ioc.is_hash_allowlisted(path),
            matches!(decision, ResponseDecision::Allowlisted { .. }),
        ],
        expected,
        "YARA, IOC, response: prefix {prefix:?}, path {path:?}",
    );
    drop(response);
    worker.await.unwrap();
}

#[tokio::test]
async fn directory_boundaries_and_raw_ioc_prefixes_remain_distinct() {
    let root = if cfg!(windows) {
        "C:\\trusted"
    } else {
        "/trusted"
    };
    let sep = if cfg!(windows) { '\\' } else { '/' };
    check(root, &format!("{root}{sep}app"), [true, true, true]).await;
    check(root, &format!("{root}-other{sep}app"), [false, true, false]).await;
    check(root, root, [false, true, false]).await;
    check(
        &format!(" {root}{sep} "),
        &format!(" {root}{sep}app "),
        [true, true, true],
    )
    .await;
    check(
        &format!("{root}{sep}"),
        &format!("{root}-other{sep}app"),
        [false, false, false],
    )
    .await;
}

#[tokio::test]
async fn empty_prefixes_preserve_the_existing_ioc_match_all_behavior() {
    check("   ", "/any/path", [false, true, false]).await;
}

#[tokio::test]
async fn case_and_separator_contracts_are_platform_specific() {
    if cfg!(windows) {
        check("C:/TRUSTED", "c:\\trusted\\app.exe", [true, true, true]).await;
        check("c:\\trusted", "C:/TRUSTED/app.exe", [true, true, true]).await;
    } else {
        check("/Trusted", "/trusted/app", [false, false, true]).await;
        check("/Trusted", "/Trusted/app", [true, true, true]).await;
        check("/trusted", "/trusted\\app", [false, true, false]).await;
    }
}
