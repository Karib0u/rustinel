//! End-to-end checks for `rustinel replay`.
//!
//! Replay is the one command that runs the whole detection path without a
//! sensor, so unlike the capture smoke test these run unprivileged in ordinary
//! CI, on whatever platform CI happens to be.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/replay")
}

fn escape(path: &Path) -> String {
    path.display().to_string().replace('\\', "\\\\")
}

fn write_config(root: &Path) -> PathBuf {
    let config_path = root.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[scanner]\n\
             sigma_enabled = true\n\
             sigma_rules_path = \"{sigma}\"\n\
             yara_enabled = false\n\
             \n[ioc]\nenabled = false\n\
             \n[alerts]\ndirectory = \"{alerts}\"\n\
             \n[logging]\nlevel = \"error\"\ndirectory = \"{logs}\"\n",
            sigma = escape(&fixtures().join("sigma")),
            alerts = escape(&root.join("alerts")),
            logs = escape(&root.join("logs")),
        ),
    )
    .expect("write config");
    config_path
}

fn replay(config_path: &Path, recording: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustinel"))
        .arg("replay")
        .arg(recording)
        .arg("--config")
        .arg(config_path)
        .args(extra)
        .output()
        .expect("replay runs")
}

/// Copy the fixture recording and its manifest into `directory` so a test can
/// damage them without touching the checked-in originals.
fn copy_fixture(directory: &Path) -> PathBuf {
    let payload = directory.join("windows-powershell.ndjson");
    std::fs::copy(fixtures().join("windows-powershell.ndjson"), &payload).expect("copy payload");
    std::fs::copy(
        fixtures().join("windows-powershell.manifest.json"),
        directory.join("windows-powershell.manifest.json"),
    )
    .expect("copy manifest");
    payload
}

fn rewrite_manifest(payload: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = payload.with_extension("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("manifest exists"))
            .expect("manifest parses");
    edit(&mut manifest);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&manifest).expect("serializes"),
    )
    .expect("manifest rewritten");
}

#[test]
fn replaying_the_fixture_prints_a_console_alert_list() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());

    let output = replay(
        &config_path,
        &fixtures().join("windows-powershell.ndjson"),
        &[],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Replay of "), "{stdout}");
    assert!(
        stdout.contains("Rustinel Replay Fixture - Encoded PowerShell Command"),
        "{stdout}"
    );
    assert!(
        stdout.contains("4 events replayed, 2 alerts (2 sigma, 0 ioc)"),
        "{stdout}"
    );
    assert!(stdout.contains("not live detections"), "{stdout}");
    assert!(
        !temp.path().join("alerts").exists(),
        "replay must leave the live alert output untouched"
    );
}

#[test]
fn the_output_flag_writes_ecs_ndjson() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    let alerts = temp.path().join("replay-alerts.ndjson");

    let output = replay(
        &config_path,
        &fixtures().join("windows-powershell.ndjson"),
        &["--output", &alerts.display().to_string()],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = std::fs::read_to_string(&alerts).expect("ECS output exists");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "{body}");
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line).expect("ECS line parses");
        assert_eq!(value["event.kind"], "alert");
        assert_eq!(
            value["edr.replay"]["recording"],
            "windows-powershell.ndjson"
        );
    }

    // Nothing about the alert list goes to stdout when it has a file to go to.
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
}

#[cfg(unix)]
#[test]
fn ecs_output_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    let alerts = temp.path().join("replay-alerts.ndjson");

    replay(
        &config_path,
        &fixtures().join("windows-powershell.ndjson"),
        &["--output", &alerts.display().to_string()],
    );

    let mode = std::fs::metadata(&alerts)
        .expect("ECS output exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "replay results are as sensitive as alerts");
}

#[test]
fn an_incomplete_recording_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    let payload = copy_fixture(temp.path());
    rewrite_manifest(&payload, |manifest| {
        manifest["status"] = serde_json::json!("incomplete");
        manifest["events"]["lost"] = serde_json::json!(7);
    });

    let output = replay(&config_path, &payload, &[]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incomplete"), "{stderr}");
}

#[test]
fn a_corrupted_recording_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    let payload = copy_fixture(temp.path());
    let body = std::fs::read_to_string(&payload).expect("payload exists");
    std::fs::write(&payload, body.replace("analyst", "intruder")).expect("payload edited");

    let output = replay(&config_path, &payload, &[]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("checksum"), "{stderr}");
}

#[test]
fn a_recording_from_an_unsupported_schema_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    let payload = copy_fixture(temp.path());
    rewrite_manifest(&payload, |manifest| {
        manifest["schema_version"] = serde_json::json!(99);
    });

    let output = replay(&config_path, &payload, &[]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("schema version"), "{stderr}");
}

#[test]
fn a_missing_recording_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());

    let output = replay(&config_path, &temp.path().join("absent.ndjson"), &[]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("absent.ndjson"), "{stderr}");
}
