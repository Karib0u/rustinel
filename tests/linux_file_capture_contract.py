#!/usr/bin/env python3
"""Check the live Linux sensor's normalized file events for benign operations."""

import argparse
import json
from pathlib import Path
import tempfile
import time

from fixtures.linux_file_coverage import compat, native
from native_capture_contract import start_capture, stderr_text, stop_capture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--busybox-i386", type=Path, help="measure 32-bit process and network fields")
    args = parser.parse_args()
    artifacts = args.artifacts_dir
    artifacts.mkdir(parents=True, exist_ok=True)

    completed = []
    report = {"completed_workload_checks": completed}
    try:
        with tempfile.TemporaryDirectory(prefix="rustinel-linux-file-") as directory:
            root = Path(directory).resolve()
            workload = root / "workload"
            payload = root / "captures" / "linux-file.ndjson"
            process, manifest_path = start_capture(args.binary.resolve(), root, payload)
            try:
                native.run(workload, completed)
                if args.busybox_i386:
                    report["compat_workloads"] = compat.run(args.busybox_i386.resolve())
                time.sleep(3)
            finally:
                try:
                    stop_capture(process)
                finally:
                    (artifacts / "capture.stderr.log").write_text(
                        stderr_text(process), encoding="utf-8"
                    )

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            report["manifest"] = manifest
            with payload.open(encoding="utf-8") as lines:
                events = list(map(json.loads, lines))
            report.update(native.compare(events, workload, completed))
            if "compat_workloads" in report:
                report["compat_observed"] = compat.compare(events, report["compat_workloads"])
            assert manifest["status"] == "complete", manifest
            assert manifest["events"]["lost"] == manifest["events"]["source_lost"] == 0, manifest
            assert report["matches"], (
                report["expected"], report["observed"], report["observed_process_ids"]
            )
            if "compat_observed" in report:
                observed = report["compat_observed"]
                assert observed["connect"] and observed["exec"], (
                    report["compat_workloads"], observed
                )
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (artifacts / "file-coverage.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
    print("Linux file capture contract passed")


if __name__ == "__main__":
    main()
