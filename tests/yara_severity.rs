use std::sync::Arc;

use arc_swap::ArcSwap;
use rustinel::{
    config::ResponseConfig,
    memory::{MemoryChunk, MemoryRegion, MemoryRegionKind},
    models::{AlertSeverity, MatchDebugLevel},
    response::{ResponseDecision, ResponseEngine},
    runtime::yara::{build_yara_memory_alert, build_yara_memory_match_details},
    scanner::{build_yara_alert, build_yara_match_details, Scanner},
    sensor::Platform,
};

#[tokio::test]
async fn yara_metadata_controls_file_memory_alerts_and_response() {
    use AlertSeverity::{Critical, High, Informational, Low, Medium};

    let mut cases = vec![
        ("", High),
        (r#"severity = "unknown""#, High),
        (r#"level = "unknown""#, High),
        (r#"score = "unknown""#, High),
        (r#"severity = "" level = """#, High),
        ("severity = 10 level = true score = false", High),
        ("score = -1", High),
        ("score = 101", High),
        ("score = 80.5", High),
        (r#"score = "80.5""#, High),
        (r#"severity = " HIGH ""#, High),
        (r#"level = " Low ""#, Low),
        (r#"severity = "info""#, Informational),
        (r#"severity = "low" level = "critical" score = 100"#, Low),
        (
            r#"score = 100 level = "medium" severity = "unknown""#,
            Medium,
        ),
        (r#"score = 40 level = false severity = "unknown""#, Medium),
        (r#"score = " 80 ""#, Critical),
    ];
    let names = ["informational", "low", "medium", "high", "critical"];
    let severities = [Informational, Low, Medium, High, Critical];
    let named_metadata: Vec<_> = ["severity", "level"]
        .into_iter()
        .flat_map(|key| {
            names
                .into_iter()
                .zip(severities)
                .map(move |(name, severity)| (format!("{key} = \"{name}\""), severity))
        })
        .collect();
    cases.extend(
        named_metadata
            .iter()
            .map(|(metadata, severity)| (metadata.as_str(), *severity)),
    );
    let score_metadata: Vec<_> = [
        (0, Informational),
        (1, Low),
        (39, Low),
        (40, Medium),
        (59, Medium),
        (60, High),
        (79, High),
        (80, Critical),
        (100, Critical),
    ]
    .into_iter()
    .flat_map(|(score, severity)| {
        [
            (format!("score = {score}"), severity),
            (format!("score = \"{score}\""), severity),
        ]
    })
    .collect();
    cases.extend(
        score_metadata
            .iter()
            .map(|(metadata, severity)| (metadata.as_str(), *severity)),
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir(&rules_dir).expect("rules directory");
    let rules: String = cases
        .iter()
        .enumerate()
        .map(|(index, (metadata, _))| {
            format!(
                "rule Case{index} {{ meta: id = \"case-{index}\" {metadata} condition: true }}\n"
            )
        })
        .collect();
    std::fs::write(rules_dir.join("severity.yar"), rules).expect("write rules");
    let scanner = Scanner::new(&rules_dir).expect("compile rules");
    let path = dir.path().join("sample.bin");
    std::fs::write(&path, b"sample").expect("write sample");
    let path = path.to_str().expect("sample path");
    let chunk = MemoryChunk {
        base: 0x1000,
        bytes: b"sample".to_vec(),
        region: MemoryRegion {
            base: 0x1000,
            size: 6,
            readable: true,
            writable: false,
            executable: false,
            kind: MemoryRegionKind::Private,
        },
    };
    let config = Arc::new(ArcSwap::from_pointee(ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        min_severity: "high".to_string(),
        channel_capacity: 4,
        allowlist_images: vec![],
        allowlist_paths: vec![],
    }));
    let (response, worker) = ResponseEngine::new(config);

    for debug in [
        MatchDebugLevel::Off,
        MatchDebugLevel::Summary,
        MatchDebugLevel::Full,
    ] {
        // The second file scan also checks that cached matches retain severity.
        for matches in [
            scanner.scan_file(path, debug).expect("file scan"),
            scanner.scan_file(path, debug).expect("cached file scan"),
            scanner
                .scan_bytes(&chunk.bytes, debug)
                .expect("memory scan"),
        ] {
            assert_eq!(matches.len(), cases.len());
            for (index, (metadata, expected)) in cases.iter().enumerate() {
                let rule_match = matches
                    .iter()
                    .find(|m| m.rule == format!("Case{index}"))
                    .expect("matching rule");
                assert_eq!(rule_match.severity, *expected, "{metadata:?}, {debug:?}");
                for alert in [
                    build_yara_alert(
                        rule_match,
                        path,
                        99_999_999,
                        &Default::default(),
                        build_yara_match_details(debug, rule_match),
                        Platform::Linux,
                        "test",
                    ),
                    build_yara_memory_alert(
                        rule_match,
                        path,
                        99_999_999,
                        &Default::default(),
                        build_yara_memory_match_details(debug, rule_match, &chunk),
                        Platform::Linux,
                        "test",
                    ),
                ] {
                    assert_eq!(alert.severity, *expected);
                    assert_eq!(alert.rule_id, Some(format!("yara::case-{index}")));
                    let decision = response.decision_for_alert(&alert);
                    if *expected >= High {
                        assert!(matches!(decision, ResponseDecision::Terminate { .. }));
                    } else {
                        assert_eq!(
                            decision,
                            ResponseDecision::BelowSeverity {
                                severity: *expected,
                                min_severity: High
                            }
                        );
                    }
                }
            }
        }
    }
    drop(response);
    worker.await.expect("response worker");
}
