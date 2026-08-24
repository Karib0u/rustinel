//! Privileged end-to-end checks for Linux file path reconstruction.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustinel::capture::{manifest_path_for, CaptureManifest};
use rustinel::models::NormalizedEvent;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
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
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn stop_capture(mut child: Child) {
    let pid = child.id() as i32;
    // SAFETY: `pid` belongs to the live child created by this test.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
    assert!(
        wait_for(SHUTDOWN_TIMEOUT, || child
            .try_wait()
            .expect("poll capture process")
            .is_some()),
        "capture did not stop"
    );
    assert!(child.wait().expect("capture exits").success());
}

fn open_dir(path: &Path, flags: i32) -> i32 {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).expect("path has no NUL");
    // SAFETY: `path` is a valid NUL-terminated pathname and flags need no mode.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    assert!(fd >= 0, "open failed: {}", std::io::Error::last_os_error());
    fd
}

fn close_fd(fd: i32) {
    // SAFETY: the caller owns `fd` and closes it once.
    assert_eq!(unsafe { libc::close(fd) }, 0);
}

#[test]
#[ignore = "requires root and a live eBPF sensor"]
fn bare_read_only_reuse_cannot_consume_an_old_directory_index_entry() {
    let temp = tempfile::tempdir().expect("tempdir");
    let old_dir = temp.path().join("old");
    let new_dir = temp.path().join("new");
    std::fs::create_dir_all(&old_dir).expect("create old directory");
    std::fs::create_dir_all(&new_dir).expect("create new directory");
    let victim = new_dir.join("fd-reuse-victim.txt");
    std::fs::write(&victim, b"marker").expect("create victim");

    let config_path = write_config(temp.path());
    let payload = temp.path().join("captures").join("linux-file-paths.ndjson");
    let child = Command::new(env!("CARGO_BIN_EXE_rustinel"))
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
        "capture did not initialize"
    );
    std::thread::sleep(Duration::from_secs(1));

    // First populate the index under a descriptor opened with O_DIRECTORY.
    let old_fd = open_dir(
        &old_dir,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    );
    close_fd(old_fd);

    // A plain O_RDONLY directory open bypasses the index filter. Linux should
    // reuse the just-closed descriptor number. Keep it open until the event is
    // drained so the `/proc` fallback has an unambiguous answer.
    let new_fd = open_dir(&new_dir, libc::O_RDONLY | libc::O_CLOEXEC);
    assert_eq!(new_fd, old_fd, "kernel did not reuse the descriptor number");
    let name = CString::new("fd-reuse-victim.txt").unwrap();
    // SAFETY: `new_fd` names `new_dir` and `name` is NUL-terminated.
    assert_eq!(unsafe { libc::unlinkat(new_fd, name.as_ptr(), 0) }, 0);

    std::thread::sleep(Duration::from_secs(2));
    close_fd(new_fd);
    stop_capture(child);

    let manifest: CaptureManifest =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("manifest exists"))
            .expect("manifest parses");
    assert!(
        manifest.is_replayable(),
        "capture is incomplete: {manifest:?}"
    );

    let expected = victim.to_string_lossy();
    let stale = old_dir.join("fd-reuse-victim.txt");
    let mut saw_expected = false;
    for line in std::fs::read_to_string(&payload)
        .expect("capture exists")
        .lines()
    {
        let event: NormalizedEvent = serde_json::from_str(line).expect("event parses");
        let Some(path) = event.get_field("TargetFilename") else {
            continue;
        };
        assert_ne!(
            path,
            stale.to_string_lossy(),
            "stale index path was emitted"
        );
        saw_expected |= path == expected;
    }
    assert!(
        saw_expected,
        "expected delete path was not captured: {expected}"
    );
}
