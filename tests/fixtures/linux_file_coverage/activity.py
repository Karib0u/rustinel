"""Check per-process activity totals using ordinary fio and i386 BusyBox jobs."""

import json
import subprocess
import tempfile
import time
from pathlib import Path


def workload(*args):
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            raise
        assert child.returncode == 0, (args, child.returncode, stderr)
        return child.pid, stdout


def check(fio, busybox, logs, artifacts):
    expected = {}
    observed = {}
    try:
        with tempfile.TemporaryDirectory(prefix="rustinel-activity-", dir=artifacts) as tmp:
            root = Path(tmp)
            data = root / "fio.bin"
            fio_pid, output = workload(
                str(fio), "--name=rustinel-write", "--ioengine=io_uring",
                "--rw=write", "--size=1m", "--bs=4k", "--iodepth=4", "--direct=1",
                "--thread=1", "--fallocate=none", "--output-format=json", f"--filename={data}",
            )
            assert json.loads(output)["jobs"][0]["write"]["io_bytes"] == 1_048_576, output
            assert data.stat().st_size == 1_048_576, data
            expected["fio write"] = ("io_uring_submissions", fio_pid, 256)

            original = root / "original"
            renamed = root / "renamed"
            directory = root / "directory"
            for action, args, result in (
                ("touch", [original], original.is_file),
                ("mv", [original, renamed], lambda: renamed.is_file() and not original.exists()),
                ("mkdir", [directory], directory.is_dir),
                ("rm", [renamed], lambda: not renamed.exists()),
            ):
                pid, _ = workload(str(busybox), action, *map(str, args))
                assert result(), (action, args)
                expected[f"i386 {action}"] = ("ia32_file_syscalls", pid, 1)

            deadline = time.monotonic() + 15
            telemetry_path = logs / "telemetry.json"
            while time.monotonic() < deadline:
                if telemetry_path.is_file():
                    snapshot = json.loads(telemetry_path.read_text(encoding="utf-8"))
                    rows = snapshot.get("linux_ebpf", {}).get("activity", [])
                    counts = {
                        (row["kind"], process["pid"]): process["count"]
                        for row in rows
                        for process in row["processes"]
                        if process["process_start_time"] > 0
                    }
                    observed = {
                        name: counts.get((kind, pid), 0)
                        for name, (kind, pid, _) in expected.items()
                    }
                    if observed == {name: count for name, (_, _, count) in expected.items()}:
                        return
                time.sleep(0.2)
            raise AssertionError(f"activity counts differ: expected {expected}, observed {observed}")
    finally:
        (artifacts / "activity-coverage.json").write_text(
            json.dumps({"expected": expected, "observed": observed}, indent=2) + "\n",
            encoding="utf-8",
        )
