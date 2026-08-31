//! Golden regression: the checked-in recording still fires the checked-in rules.
//!
//! The fixture is a small Windows recording of a benign encoded PowerShell
//! launch and the file it writes, produced by the launch script next to it. It
//! runs on every platform in ordinary CI, without sensors or privileges, which
//! is the whole point of replay: the recording carries the behavior, so the host
//! evaluating it does not have to be able to produce it.
//!
//! See `docs/detection.md` for how to regenerate the recording.

use std::path::{Path, PathBuf};

use rustinel::replay::{Format, Replay, ReplayOptions, ReplayReport};
use rustinel::sensor::Platform;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/replay")
}

fn recording() -> PathBuf {
    fixtures().join("windows-powershell.ndjson")
}

/// Write a configuration that points the detectors at the fixture rules and
/// keeps every output path inside `root`.
fn write_config(root: &Path, extra: &str) -> PathBuf {
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
             \n[logging]\nlevel = \"error\"\ndirectory = \"{logs}\"\n{extra}",
            sigma = fixtures()
                .join("sigma")
                .display()
                .to_string()
                .replace('\\', "\\\\"),
            alerts = root
                .join("alerts")
                .display()
                .to_string()
                .replace('\\', "\\\\"),
            logs = root
                .join("logs")
                .display()
                .to_string()
                .replace('\\', "\\\\"),
        ),
    )
    .expect("write config");
    config_path
}

fn options(config_path: &Path) -> ReplayOptions {
    ReplayOptions {
        recording: recording(),
        config_path: Some(config_path.to_path_buf()),
        output: None,
        log_level: None,
    }
}

fn replay_to_string(replay: &Replay, format: Format) -> (String, ReplayReport) {
    let mut buffer = Vec::new();
    let report = replay.run(format, &mut buffer).expect("replay runs");
    (String::from_utf8(buffer).expect("output is utf-8"), report)
}

#[test]
fn the_fixture_recording_fires_both_checked_in_rules() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path(), "");

    let replay = Replay::prepare(&options(&config_path)).expect("replay prepares");
    let (output, report) = replay_to_string(&replay, Format::Console);

    assert_eq!(report.events, 4, "every recorded event is evaluated");
    assert_eq!(report.alerts, 2, "{output}");
    assert_eq!(report.sigma_alerts, 2);
    assert_eq!(report.ioc_alerts, 0);

    let encoded = output
        .find("Rustinel Replay Fixture - Encoded PowerShell Command")
        .expect("the encoded PowerShell rule fires");
    let file_write = output
        .find("Rustinel Replay Fixture - PowerShell Writes To Temp")
        .expect("the file-write rule fires");
    assert!(
        encoded < file_write,
        "alerts follow the recorded event order:\n{output}"
    );

    // Recorded timestamps travel into the alerts unchanged.
    assert!(output.contains("2026-08-16T09:41:02.884Z"), "{output}");
    assert!(output.contains("2026-08-16T09:41:03.402Z"), "{output}");
}

#[test]
fn a_windows_recording_replays_on_a_non_windows_host() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path(), "");

    let replay = Replay::prepare(&options(&config_path)).expect("replay prepares");

    assert_eq!(
        replay.recording().manifest().platform,
        Platform::Windows,
        "the fixture is a Windows recording"
    );
    #[cfg(not(windows))]
    {
        let (_, report) = replay_to_string(&replay, Format::Console);
        assert_eq!(
            report.alerts, 2,
            "Windows rules must be routed by the recorded platform, not the host"
        );
    }
}

#[test]
fn two_replays_of_one_recording_produce_identical_output() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path(), "");

    let first = Replay::prepare(&options(&config_path)).expect("replay prepares");
    let (first_console, first_report) = replay_to_string(&first, Format::Console);
    let (first_ecs, _) = replay_to_string(&first, Format::Ecs);

    let second = Replay::prepare(&options(&config_path)).expect("replay prepares");
    let (second_console, second_report) = replay_to_string(&second, Format::Console);
    let (second_ecs, _) = replay_to_string(&second, Format::Ecs);

    assert_eq!(first_console, second_console);
    assert_eq!(first_ecs, second_ecs);
    assert_eq!(first_report, second_report);
}

#[test]
fn ecs_output_marks_every_alert_as_replayed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path(), "");

    let replay = Replay::prepare(&options(&config_path)).expect("replay prepares");
    let (ecs, _) = replay_to_string(&replay, Format::Ecs);

    let lines: Vec<&str> = ecs.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line).expect("ECS line parses");
        assert_eq!(
            value["edr.replay"]["recording"],
            "windows-powershell.ndjson"
        );
        assert_eq!(value["edr.replay"]["platform"], "windows");
        assert_eq!(
            value["edr.replay"]["recorded_at"],
            "2026-08-16T09:40:58.004Z"
        );
        assert_eq!(value["host.os.type"], "windows");
    }
}

#[test]
fn replay_reports_the_detectors_it_used_and_the_ones_it_skipped() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path(), "");

    let replay = Replay::prepare(&options(&config_path)).expect("replay prepares");
    let configuration = replay.configuration().join("\n");

    assert!(
        configuration.contains("2 rules for windows"),
        "{configuration}"
    );
    assert!(configuration.contains("builtin engine"), "{configuration}");
    assert!(
        configuration.contains("YARA and hash IOC checks"),
        "skipped detectors are named rather than silently dropped:\n{configuration}"
    );
    assert!(
        configuration.contains("dedup      disabled"),
        "{configuration}"
    );
}

#[test]
fn active_response_stays_off_even_when_the_configuration_enables_it() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(
        temp.path(),
        "\n[response]\nenabled = true\nprevention_enabled = true\nmin_severity = \"low\"\n",
    );

    let replay = Replay::prepare(&options(&config_path)).expect("replay prepares");
    let (output, report) = replay_to_string(&replay, Format::Console);

    assert_eq!(report.alerts, 2, "the rules still fire");
    assert!(
        output.contains("response   disabled; replay never acts on the host it runs on"),
        "{output}"
    );
    assert!(
        !temp.path().join("alerts").exists(),
        "replay must not open the live alert output at all"
    );
}

#[test]
fn replay_refuses_to_write_into_the_live_alert_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path(), "");
    let alerts = temp.path().join("alerts");
    std::fs::create_dir_all(&alerts).expect("create alert directory");

    let mut options = options(&config_path);
    options.output = Some(alerts.join("replay.ndjson"));

    let err = match Replay::prepare(&options) {
        Ok(_) => panic!("the alert directory is off limits"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("live alert directory"), "{err}");
}
