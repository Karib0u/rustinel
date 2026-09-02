//! End-to-end test for `rustinel capture`.
//!
//! Capture drives the real sensors, so this needs the same privileges as
//! `rustinel run` and is ignored by default. Run it manually on a controlled
//! privileged host when checking that a clean Ctrl-C produces a complete
//! NDJSON/manifest pair.

#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustinel::capture::{manifest_path_for, CaptureManifest, CaptureStatus};

/// How long the capture is allowed to take to open its recording.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the capture is allowed to take to finalize after Ctrl-C.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

fn write_config(root: &Path) -> std::path::PathBuf {
    let config_path = root.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[logging]\nlevel = \"info\"\ndirectory = \"{logs}\"\nfilename = \"rustinel.log\"\n\
             \n[capture]\ndirectory = \"{captures}\"\n",
            logs = root.join("logs").display(),
            captures = root.join("captures").display(),
        ),
    )
    .expect("write config");
    config_path
}

fn wait_for(deadline: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn read_manifest(path: &Path) -> CaptureManifest {
    serde_json::from_str(&std::fs::read_to_string(path).expect("manifest exists"))
        .expect("manifest parses")
}

#[test]
#[ignore = "requires sensor privileges; run manually on a controlled host"]
fn ctrl_c_finalizes_a_complete_recording() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    let payload = temp.path().join("captures").join("smoke.ndjson");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustinel"))
        .arg("capture")
        .arg("--config")
        .arg(&config_path)
        .arg("--output")
        .arg(&payload)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("capture starts");

    let manifest_path = manifest_path_for(&payload);
    assert!(
        wait_for(STARTUP_TIMEOUT, || manifest_path.exists()),
        "capture did not open a recording within {STARTUP_TIMEOUT:?}"
    );
    assert_eq!(
        read_manifest(&manifest_path).status,
        CaptureStatus::Incomplete,
        "a running capture is marked incomplete until it finalizes"
    );

    // Generate a little activity for the sensors to observe.
    for _ in 0..3 {
        let _ = Command::new("/bin/sh")
            .args(["-c", "echo rustinel-capture-smoke > /dev/null"])
            .status();
    }
    std::thread::sleep(Duration::from_secs(2));

    // SIGINT is what Ctrl-C delivers; the capture must finalize on it.
    let pid = child.id() as i32;
    // SAFETY: `pid` belongs to the child spawned above, which is still running.
    let signalled = unsafe { libc::kill(pid, libc::SIGINT) };
    assert_eq!(signalled, 0, "failed to signal the capture process");

    assert!(
        wait_for(SHUTDOWN_TIMEOUT, || child
            .try_wait()
            .expect("poll capture process")
            .is_some()),
        "capture did not exit within {SHUTDOWN_TIMEOUT:?} of Ctrl-C"
    );
    let status = child.wait().expect("capture exits");
    assert!(status.success(), "capture exited with {status}");

    let manifest = read_manifest(&manifest_path);
    assert_eq!(manifest.status, CaptureStatus::Complete);
    assert!(manifest.is_replayable());
    assert_eq!(
        manifest.events.received,
        manifest.events.written + manifest.events.lost
    );
    assert!(
        manifest.events.written > 0,
        "the session recorded no events at all"
    );

    let payload_lines = std::fs::read_to_string(&payload)
        .expect("recording exists")
        .lines()
        .count();
    assert_eq!(payload_lines as u64, manifest.events.written);
}

#[test]
#[ignore = "requires sensor privileges; run manually on a controlled host"]
fn a_killed_capture_leaves_an_incomplete_recording() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(temp.path());
    let payload = temp.path().join("captures").join("killed.ndjson");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustinel"))
        .arg("capture")
        .arg("--config")
        .arg(&config_path)
        .arg("--output")
        .arg(&payload)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("capture starts");

    let manifest_path = manifest_path_for(&payload);
    assert!(
        wait_for(STARTUP_TIMEOUT, || manifest_path.exists()),
        "capture did not open a recording within {STARTUP_TIMEOUT:?}"
    );

    child.kill().expect("kill capture");
    child.wait().expect("capture exits");

    let manifest = read_manifest(&manifest_path);
    assert_eq!(manifest.status, CaptureStatus::Incomplete);
    assert!(manifest.payload_sha256.is_none());
    assert!(
        !manifest.is_replayable(),
        "an interrupted recording must be rejected by replay"
    );
}
