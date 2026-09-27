#!/usr/bin/env python3
"""Check that a managed SIGTERM stop drains the live Linux runtime."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from ebpf_load_smoke import read_logs, write_config


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rules-dir", type=Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rustinel-systemd-stop-") as directory:
        root = Path(directory)
        logs_dir = root / "logs"
        logs_dir.mkdir()
        config = root / "config.toml"
        write_config(config, args.rules_dir.resolve(), logs_dir)
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                "snapshot_interval_secs = 1", "snapshot_interval_secs = 3600"
            ),
            encoding="utf-8",
        )

        unit = "rustinel-stop-ci-" + str(os.getpid()) + ".service"
        started = False
        try:
            run(
                "systemd-run",
                "--unit=" + unit,
                "--property=KillSignal=SIGTERM",
                "--property=TimeoutStopSec=30s",
                "--property=WorkingDirectory=" + str(root),
                str(args.binary.resolve()),
                "run",
                "--config",
                str(config),
                "--no-console",
            )
            started = True
            deadline = time.monotonic() + 30
            while "Agent ready" not in read_logs(logs_dir):
                if time.monotonic() >= deadline:
                    raise AssertionError("agent did not become ready under systemd")
                state = run("systemctl", "show", "-p", "ActiveState", "--value", unit).stdout.strip()
                if state not in ("active", "activating"):
                    raise AssertionError(f"agent exited before readiness: {state}")
                time.sleep(0.1)

            run("systemctl", "stop", unit)
            started = False
            logs = read_logs(logs_dir)
            assert "Received SIGTERM, shutting down" in logs, logs
            assert "Shutdown complete" in logs, logs
            telemetry = json.loads((logs_dir / "telemetry.json").read_text(encoding="utf-8"))
            assert telemetry["pid"] > 0, telemetry
            print("systemd SIGTERM stop drained and wrote final telemetry")
        finally:
            if started:
                subprocess.run(["systemctl", "stop", unit], check=False)
            subprocess.run(["systemctl", "reset-failed", unit], check=False)


if __name__ == "__main__":
    main()
