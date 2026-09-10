#!/usr/bin/env python3
"""Summarize JSON from the windows_process_capture example using only stdlib."""

import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import median


def summarize(path):
    capture = json.loads(path.read_text(encoding="utf-8-sig"))
    expected = {child["pid"]: child["marker"] for child in capture["expected"]}
    events = [event for event in capture["events"] if event["pid"] in expected]
    latencies = sorted(event["latency_ms"] for event in events)
    sources = Counter()
    complete = 0
    for event in events:
        fields = event["event"]["fields"]
        command_line = fields.get("CommandLine")
        complete += command_line is not None and expected[event["pid"]] in command_line
        sources[fields.get("WindowsProcessMetadata", {}).get("command_line_source", "manifest-only")] += 1
    return {
        "file": path.name,
        "expected": capture["count"],
        "creations": len(events),
        "duplicate_creations": len(events) - len({event["pid"] for event in events}),
        "complete_command_lines": complete,
        "sources": dict(sources),
        "field_counts": {
            field: sum(event["event"]["fields"].get(field) is not None for event in events)
            for field in ("CommandLine", "Image", "ProcessStartTime", "ParentProcessId", "IntegrityLevel", "User")
        },
        "launches_per_second": capture["count"] / capture["workload_seconds"],
        "latency_median_ms": median(latencies) if latencies else None,
        "latency_p95_ms": latencies[int((len(latencies) - 1) * 0.95)] if latencies else None,
        "cpu_seconds": capture["cpu_seconds"],
        "kernel_lost": capture["kernel_lost"],
        "correlation": capture.get("telemetry", {}).get("windows_process_correlation"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", type=Path, nargs="+")
    args = parser.parse_args()
    print(json.dumps([summarize(path) for path in args.captures], indent=2))
