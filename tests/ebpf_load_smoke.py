#!/usr/bin/env python3
"""Load Rustinel's embedded eBPF object and exercise every event family."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


STARTUP_TIMEOUT = 30
SHUTDOWN_TIMEOUT = 30
EVENT_TIMEOUT = 15
WHOAMI_RULE = "Example - Whoami Execution (Linux)"


def toml_string(path):
    return json.dumps(str(path))


def read_logs(logs_dir):
    chunks = []
    for path in sorted(logs_dir.glob("rustinel.log*")):
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def wait_for_startup(process, logs_dir):
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        logs = read_logs(logs_dir)
        if "eBPF tracepoints attached" in logs:
            return
        if process.poll() is not None:
            raise AssertionError(f"agent exited during startup ({process.returncode})")
        time.sleep(0.1)
    raise AssertionError(
        f"agent did not attach its eBPF tracepoints within {STARTUP_TIMEOUT}s"
    )


def stop_agent(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        returncode = process.wait(timeout=SHUTDOWN_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise AssertionError("agent did not stop after SIGINT")
    if returncode != 0:
        raise AssertionError(f"agent exited {returncode}")


def verify_embedded_object(binary, ebpf_object, artifacts_dir):
    expected = ebpf_object.read_bytes()
    executable = binary.read_bytes()
    offset = executable.find(expected)
    if offset < 0:
        raise AssertionError(
            f"{binary} does not contain the downloaded eBPF object {ebpf_object}"
        )

    expected_hash = hashlib.sha256(expected).hexdigest()
    embedded_hash = hashlib.sha256(executable[offset : offset + len(expected)]).hexdigest()
    if embedded_hash != expected_hash:
        raise AssertionError(
            f"embedded eBPF hash {embedded_hash} does not match artifact {expected_hash}"
        )
    (artifacts_dir / "ebpf-object.sha256").write_text(
        f"{expected_hash}  {ebpf_object.name}\n", encoding="utf-8"
    )
    print(f"embedded eBPF object matches artifact: {expected_hash}")


def write_config(config, rules_dir, logs_dir):
    config.write_text(
        "[scanner]\n"
        "sigma_enabled = true\n"
        f"sigma_rules_path = {toml_string(rules_dir)}\n"
        "yara_enabled = false\n"
        "\n[ioc]\n"
        "enabled = false\n"
        "\n[reload]\n"
        "enabled = false\n"
        "\n[dedup]\n"
        "enabled = false\n"
        "\n[logging]\n"
        'level = "info"\n'
        f"directory = {toml_string(logs_dir)}\n"
        'filename = "rustinel.log"\n'
        "console_output = false\n"
        "\n[alerts]\n"
        f"directory = {toml_string(logs_dir)}\n"
        'filename = "alerts.json"\n'
        "\n[telemetry]\n"
        "enabled = true\n"
        "snapshot_interval_secs = 1\n",
        encoding="utf-8",
    )


def generate_events(run_dir):
    subprocess.run(["whoami"], check=True, stdout=subprocess.DEVNULL)

    file_dir = run_dir / "file-events"
    file_dir.mkdir()
    original = file_dir / "created"
    renamed = file_dir / "renamed"
    subprocess.run(["touch", str(original)], check=True)
    subprocess.run(["mv", str(original), str(renamed)], check=True)
    subprocess.run(["rm", str(renamed)], check=True)

    subprocess.run(
        ["curl", "-sS", "--max-time", "15", "https://example.com", "-o", "/dev/null"],
        check=True,
    )


def wait_for_event_families(logs_dir):
    telemetry_path = logs_dir / "telemetry.json"
    deadline = time.monotonic() + EVENT_TIMEOUT
    last_counts = {}
    while time.monotonic() < deadline:
        if telemetry_path.exists():
            try:
                telemetry = json.loads(telemetry_path.read_text(encoding="utf-8"))
                families = telemetry.get("linux_ebpf", {}).get("families", [])
                last_counts = {
                    family.get("ring"): family.get("canonical_emitted", 0)
                    for family in families
                }
                expected = ("process", "file", "network", "dns")
                if all(last_counts.get(name, 0) > 0 for name in expected):
                    return
            except (json.JSONDecodeError, OSError):
                pass
        time.sleep(0.2)
    raise AssertionError(
        f"not every eBPF family emitted a canonical event within {EVENT_TIMEOUT}s: {last_counts}"
    )


def assert_results(logs_dir):
    telemetry_path = logs_dir / "telemetry.json"
    telemetry = json.loads(telemetry_path.read_text(encoding="utf-8"))
    families = {
        family["ring"]: family["canonical_emitted"]
        for family in telemetry["linux_ebpf"]["families"]
    }
    for name in ("process", "file", "network", "dns"):
        assert families.get(name, 0) > 0, (name, families)

    alerts = []
    for path in sorted(logs_dir.glob("alerts.json*")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                alerts.append(json.loads(line))
    assert any(alert.get("rule.name") == WHOAMI_RULE for alert in alerts), alerts

    logs = read_logs(logs_dir)
    assert "eBPF tracepoints attached" in logs
    forbidden = ("eBPF sensor failed to start", "eBPF object load failed")
    assert not any(message in logs for message in forbidden), logs
    print(f"eBPF load smoke passed: {families}")


def write_doctor_output(binary, config, run_dir):
    result = subprocess.run(
        [str(binary), "--config", str(config), "doctor", "--json"],
        cwd=run_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    (run_dir / "doctor.json").write_text(result.stdout, encoding="utf-8")
    (run_dir / "doctor.stderr.log").write_text(result.stderr, encoding="utf-8")


def make_artifacts_readable(root):
    for path in [root, *root.rglob("*")]:
        try:
            mode = path.stat().st_mode
            if path.is_dir():
                path.chmod(mode | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            else:
                path.chmod(mode | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--ebpf-object", type=Path, required=True)
    parser.add_argument("--rules-dir", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("the eBPF load smoke test only supports Linux")

    binary = args.binary.resolve()
    ebpf_object = args.ebpf_object.resolve()
    rules_dir = args.rules_dir.resolve()
    artifacts_dir = args.artifacts_dir.resolve()
    run_dir = artifacts_dir / f"run-{int(time.time())}-{os.getpid()}"
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True)
    config = run_dir / "config.toml"
    stdout_path = run_dir / "agent.stdout.log"
    stderr_path = run_dir / "agent.stderr.log"
    process = None

    try:
        write_config(config, rules_dir, logs_dir)
        verify_embedded_object(binary, ebpf_object, run_dir)
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            process = subprocess.Popen(
                [str(binary), "--config", str(config), "run", "--no-console"],
                cwd=run_dir,
                stdout=stdout,
                stderr=stderr,
                text=True,
            )
            wait_for_startup(process, logs_dir)
            generate_events(run_dir)
            wait_for_event_families(logs_dir)
            stop_agent(process)
        assert_results(logs_dir)
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        write_doctor_output(binary, config, run_dir)
        raise
    finally:
        make_artifacts_readable(artifacts_dir)


if __name__ == "__main__":
    main()
