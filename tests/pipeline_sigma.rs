#[cfg(test)]
mod common;

use common::{
    assert_ecs_field_eq, assert_ecs_field_present, assert_normalized_field_eq, ecs_json,
    file_create_event, file_delete_event, file_rename_event, image_for, network_connect_event,
    process_start_event, provider_for, renamed_test_file_path, test_file_path, SigmaFixture,
    TestNormalizer, TEST_DESTINATION_IP, TEST_DESTINATION_PORT, TEST_PID, TEST_SOURCE_IP,
    TEST_USER,
};
use rustinel::{
    engine::Engine,
    models::{DetectionEngine, EventCategory, EventFields},
    sensor::Platform,
};

fn load_engine(platform: Platform, fixture: &SigmaFixture) -> Engine {
    let mut engine = Engine::new_for_platform(platform);
    engine
        .load_rules(fixture.rules_dir())
        .expect("sigma rules should load");
    assert_eq!(engine.stats().failed_rules, Vec::<(String, String)>::new());
    assert!(
        engine.stats().total_rules > 0,
        "expected at least one Sigma rule to load"
    );
    engine
}

fn assert_sigma_alert(alert: &rustinel::models::Alert, expected_rule: &str) {
    assert_eq!(alert.engine, DetectionEngine::Sigma);
    assert_eq!(alert.rule_name, expected_rule);
}

#[test]
fn sigma_process_detection_pipeline_maps_to_ecs_for_windows_and_linux() {
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOS] {
        let fixture = SigmaFixture::new();
        fixture.write_process_rule(platform);
        let engine = load_engine(platform, &fixture);
        let harness = TestNormalizer::new(false);

        let normalized = harness
            .normalizer
            .normalize(&process_start_event(platform))
            .expect("process start should normalize");

        assert_eq!(normalized.platform, platform);
        assert_eq!(normalized.provider, provider_for(platform));
        assert_eq!(normalized.category, EventCategory::Process);
        assert_normalized_field_eq(&normalized, "Image", image_for(platform));
        assert!(normalized
            .get_field("CommandLine")
            .expect("command line")
            .contains("example.test"));
        assert_normalized_field_eq(&normalized, "ProcessId", &TEST_PID.to_string());
        assert_normalized_field_eq(&normalized, "User", TEST_USER);

        let alert = engine
            .check_event(&normalized)
            .expect("process Sigma rule should match");
        assert_sigma_alert(&alert, "Test Process Curl");

        let ecs = ecs_json(&alert);
        assert_ecs_field_eq(&ecs, "event.dataset", "edr.process");
        assert_ecs_field_eq(&ecs, "rule.name", "Test Process Curl");
        assert_ecs_field_eq(&ecs, "edr.rule.engine", "Sigma");
        assert_ecs_field_eq(&ecs, "process.executable", image_for(platform));
        assert_ecs_field_eq(&ecs, "process.pid", TEST_PID);
    }
}

#[test]
fn sigma_network_detection_pipeline_enriches_aggregates_and_maps_to_ecs() {
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOS] {
        let fixture = SigmaFixture::new();
        fixture.write_network_rule(platform);
        let engine = load_engine(platform, &fixture);
        let harness = TestNormalizer::new(true);

        harness
            .normalizer
            .normalize(&process_start_event(platform))
            .expect("process start should prime process cache");

        let first = harness
            .normalizer
            .normalize(&network_connect_event(platform))
            .expect("first network connection should be emitted");
        assert_normalized_field_eq(&first, "Image", image_for(platform));
        assert_normalized_field_eq(&first, "DestinationIp", TEST_DESTINATION_IP);
        assert_normalized_field_eq(
            &first,
            "DestinationPort",
            &TEST_DESTINATION_PORT.to_string(),
        );
        assert_normalized_field_eq(&first, "SourceIp", TEST_SOURCE_IP);
        assert_normalized_field_eq(&first, "Protocol", "tcp");

        let repeated = harness
            .normalizer
            .normalize(&network_connect_event(platform))
            .expect("repeated connection should remain available to detection");
        let repeated_alert = engine
            .check_event(&repeated)
            .expect("repeated network connection should match Sigma");
        assert_sigma_alert(&repeated_alert, "Test Network Destination");

        let alert = engine
            .check_event(&first)
            .expect("network Sigma rule should match");
        assert_sigma_alert(&alert, "Test Network Destination");

        let ecs = ecs_json(&alert);
        assert_ecs_field_eq(&ecs, "event.dataset", "edr.network");
        assert_ecs_field_eq(&ecs, "destination.ip", TEST_DESTINATION_IP);
        assert_ecs_field_eq(&ecs, "destination.port", TEST_DESTINATION_PORT);
        assert_ecs_field_eq(&ecs, "source.ip", TEST_SOURCE_IP);
        assert_ecs_field_eq(&ecs, "network.transport", "tcp");
        assert_ecs_field_eq(&ecs, "process.executable", image_for(platform));
    }
}

#[test]
fn sigma_network_rule_loaded_after_first_connection_matches_repeat() {
    let fixture = SigmaFixture::new();
    let harness = TestNormalizer::new(true);

    harness
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .expect("process start should prime process cache");
    harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("first network connection should normalize");

    fixture.write_network_rule(Platform::Linux);
    let engine = load_engine(Platform::Linux, &fixture);
    let repeated = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("repeated network connection should normalize");

    let alert = engine
        .check_event(&repeated)
        .expect("a rule loaded after the first connection should match the repeat");
    assert_sigma_alert(&alert, "Test Network Destination");
}

#[test]
fn sigma_file_detection_pipeline_maps_create_delete_rename_and_ecs() {
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOS] {
        let fixture = SigmaFixture::new();
        let product = match platform {
            Platform::Windows => "windows",
            Platform::Linux => "linux",
            Platform::MacOS => "macos",
        };
        fixture.write_rule(
            "file_create.yml",
            &format!(
                r#"title: Test File Create
logsource:
  product: {product}
  category: file_create
detection:
  selection:
    TargetFilename|endswith: "rustinel-fixture.txt"
    Image|contains: "curl"
  condition: selection
level: low
"#
            ),
        );
        fixture.write_rule(
            "file_rename.yml",
            &format!(
                r#"title: Test File Rename
logsource:
  product: {product}
  category: file_rename
detection:
  selection:
    SourceFilename|endswith: "rustinel-fixture.txt"
    TargetFilename|endswith: "rustinel-renamed.txt"
    Image|contains: "curl"
  condition: selection
level: low
"#
            ),
        );

        let engine = load_engine(platform, &fixture);
        let harness = TestNormalizer::new(false);
        harness
            .normalizer
            .normalize(&process_start_event(platform))
            .expect("process start should prime process cache");

        let create = harness
            .normalizer
            .normalize(&file_create_event(platform))
            .expect("file create should normalize");
        assert_eq!(create.event_id, 11);
        assert_normalized_field_eq(&create, "TargetFilename", test_file_path(platform));
        assert_normalized_field_eq(&create, "Image", image_for(platform));

        let delete = harness
            .normalizer
            .normalize(&file_delete_event(platform))
            .expect("file delete should normalize");
        assert_eq!(delete.event_id, 23);
        assert_normalized_field_eq(&delete, "TargetFilename", test_file_path(platform));

        let rename = harness
            .normalizer
            .normalize(&file_rename_event(platform))
            .expect("file rename should normalize");
        assert_normalized_field_eq(&rename, "SourceFilename", test_file_path(platform));
        assert_normalized_field_eq(&rename, "TargetFilename", renamed_test_file_path(platform));
        assert_normalized_field_eq(&rename, "Image", image_for(platform));

        let create_alert = engine
            .check_event(&create)
            .expect("file create Sigma rule should match");
        assert_sigma_alert(&create_alert, "Test File Create");

        let rename_alert = engine
            .check_event(&rename)
            .expect("file rename Sigma rule should match");
        assert_sigma_alert(&rename_alert, "Test File Rename");

        match &rename_alert.event.fields {
            EventFields::FileEvent(fields) => {
                assert_eq!(
                    fields.source_filename.as_deref(),
                    Some(test_file_path(platform))
                );
                assert_eq!(
                    fields.target_filename.as_deref(),
                    Some(renamed_test_file_path(platform))
                );
            }
            other => panic!("unexpected event fields: {other:?}"),
        }

        let ecs = ecs_json(&create_alert);
        assert_ecs_field_eq(&ecs, "event.dataset", "edr.file");
        assert_ecs_field_eq(&ecs, "file.path", test_file_path(platform));
        assert_ecs_field_present(&ecs, "file.name");
        assert_ecs_field_eq(&ecs, "file.extension", "txt");
        assert_ecs_field_eq(&ecs, "process.executable", image_for(platform));
    }
}
