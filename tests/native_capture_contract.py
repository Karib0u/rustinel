#!/usr/bin/env python3
"""Release-gating checks against the real Linux and Windows capture sensors."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid


STARTUP_TIMEOUT = 30
SHUTDOWN_TIMEOUT = 30
READINESS_LINE = "Start the activity you want to record, then press Ctrl+C to finish."


def stderr_text(process):
    process.rustinel_stderr_thread.join(timeout=5)
    return "".join(process.rustinel_stderr_lines)


def start_capture(binary, root, payload):
    config = root / "config.toml"
    logs = json.dumps(str(root / "logs"))
    captures = json.dumps(str(root / "captures"))
    config.write_text(
        f'[logging]\nlevel = "warn"\ndirectory = {logs}\nfilename = "rustinel.log"\n'
        f"\n[capture]\ndirectory = {captures}\n",
        encoding="utf-8",
    )
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        [str(binary), "capture", "--config", str(config), "--output", str(payload)],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=creationflags,
    )
    ready = threading.Event()
    stderr_lines = []

    def read_stderr():
        for line in process.stderr:
            stderr_lines.append(line)
            if line.rstrip() == READINESS_LINE:
                ready.set()

    stderr_thread = threading.Thread(target=read_stderr, name="capture-stderr", daemon=True)
    stderr_thread.start()
    process.rustinel_stderr_lines = stderr_lines
    process.rustinel_stderr_thread = stderr_thread
    manifest = payload.with_suffix(".manifest.json")
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while not ready.wait(timeout=0.1):
            if process.poll() is not None:
                raise AssertionError(
                    f"capture exited during startup ({process.returncode})\n"
                    f"{stderr_text(process)}"
                )
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"capture did not report readiness within {STARTUP_TIMEOUT}s"
                )
        if not manifest.exists():
            raise AssertionError(
                f"capture reported readiness without creating {manifest}"
            )
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise AssertionError(
            f"capture failed during startup (exit {process.returncode})\n"
            f"{stderr_text(process)}"
        )
    return process, manifest


def stop_capture(process):
    if sys.platform == "win32":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=SHUTDOWN_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise AssertionError(f"capture did not stop after Ctrl-C\n{stderr_text(process)}")
    stderr = stderr_text(process)
    if process.returncode != 0:
        raise AssertionError(f"capture exited {process.returncode}\n{stderr}")


def process_event(events, pid):
    matches = [
        event
        for event in events
        if event.get("category") == "Process"
        and event.get("fields", {}).get("ProcessId") == str(pid)
    ]
    if not matches:
        observed = [
            (
                event.get("fields", {}).get("ProcessId"),
                event.get("fields", {}).get("Image"),
            )
            for event in events
            if event.get("category") == "Process"
        ][-40:]
        raise AssertionError(
            f"no captured process creation for PID {pid}; recent process events: {observed}"
        )
    return matches[-1]


def run_linux_cases(events_expected):
    sleep = Path(shutil.which("sleep") or "/usr/bin/sleep").resolve()
    absolute_cwd = Path.cwd().resolve()
    absolute = subprocess.Popen([str(sleep), "3"])

    relative_cwd = Path(tempfile.mkdtemp(prefix="rustinel-relative-"))
    relative_probe = relative_cwd / "relative-probe"
    relative_probe.symlink_to(sleep)
    relative = subprocess.Popen(["./relative-probe", "3"], cwd=relative_cwd)

    read_fd, write_fd = os.pipe()
    worker = os.fork()
    if worker == 0:
        os.close(read_fd)
        grandchild = os.fork()
        if grandchild == 0:
            os.close(write_fd)
            os.execl(str(sleep), str(sleep), "3")
        os.write(write_fd, str(grandchild).encode("ascii"))
        os.close(write_fd)
        os.waitpid(grandchild, 0)
        os._exit(0)

    os.close(write_fd)
    grandchild = int(os.read(read_fd, 32).decode("ascii"))
    os.close(read_fd)
    events_expected.update(
        {
            "absolute": (absolute.pid, sleep, absolute_cwd),
            "relative": (relative.pid, sleep, relative_cwd.resolve()),
            "fork": (grandchild, worker, Path(sys.executable).resolve()),
        }
    )
    absolute.wait(timeout=10)
    relative.wait(timeout=10)
    os.waitpid(worker, 0)
    shutil.rmtree(relative_cwd)


def assert_linux(events, expected):
    for name in ("absolute", "relative"):
        pid, image, cwd = expected[name]
        event = process_event(events, pid)
        fields = event["fields"]
        assert Path(fields["Image"]).resolve() == image, (name, event)
        assert Path(fields["CurrentDirectory"]).resolve() == cwd, (name, event)

    grandchild, worker, parent_image = expected["fork"]
    event = process_event(events, grandchild)
    fields = event["fields"]
    assert fields.get("ParentProcessId") == str(worker), event
    assert Path(fields["ParentImage"]).resolve() == parent_image, event


def run_windows_case(expected):
    marker = f"rustinel-capture-contract-{uuid.uuid4()}"
    code = "import ctypes,time; ctypes.WinDLL('winhttp.dll'); time.sleep(3)"
    child = subprocess.Popen([sys.executable, "-c", code, marker])
    expected["windows"] = child.pid
    child.wait(timeout=10)


def assert_windows(events, expected):
    pid = expected["windows"]
    process = process_event(events, pid)
    user = process["fields"].get("User")
    assert user, process

    loads = [
        event
        for event in events
        if event.get("category") == "ImageLoad"
        and event.get("fields", {}).get("ProcessId") == str(pid)
        and Path(event.get("fields", {}).get("ImageLoaded", "")).name.casefold()
        == "winhttp.dll"
    ]
    assert loads, f"no normalized winhttp.dll image load for PID {pid}"
    assert any(event.get("event_id") == 7 and event.get("opcode") == 10 for event in loads), loads


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if sys.platform not in ("linux", "win32"):
        parser.error("the native capture contract suite supports Linux and Windows")

    with tempfile.TemporaryDirectory(prefix="rustinel-capture-contract-") as directory:
        root = Path(directory)
        payload = root / "captures" / "contract.ndjson"
        process, manifest_path = start_capture(binary, root, payload)
        expected = {}
        try:
            if sys.platform == "linux":
                run_linux_cases(expected)
            else:
                run_windows_case(expected)
            time.sleep(3)
        finally:
            stop_capture(process)

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["status"] == "complete", manifest
        assert manifest["events"]["lost"] == 0, manifest
        assert manifest["events"]["source_lost"] == 0, manifest
        events = [json.loads(line) for line in payload.read_text(encoding="utf-8").splitlines()]
        if sys.platform == "linux":
            assert_linux(events, expected)
        else:
            assert_windows(events, expected)
        print(f"native capture contract passed: {len(events)} events")


if __name__ == "__main__":
    main()
