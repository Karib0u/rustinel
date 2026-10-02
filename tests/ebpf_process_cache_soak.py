#!/usr/bin/env python3
"""Verify live process-cache and RSS stability across fork/exec/exit bursts."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from ebpf_load_smoke import (
    make_artifacts_readable,
    stop_agent,
    wait_for_startup,
    write_config,
)


def sample(process, logs_dir):
    if process.poll() is not None:
        raise AssertionError(f"agent exited {process.returncode}")
    telemetry = json.loads((logs_dir / "telemetry.json").read_text())
    if telemetry["pid"] != process.pid:
        raise AssertionError("telemetry belongs to a different agent")
    status = Path(f"/proc/{process.pid}/status").read_text().splitlines()
    rss_kib = next(int(line.split()[1]) for line in status if line.startswith("VmRSS:"))
    return {
        "rss_kib": rss_kib,
        "processes": telemetry["host_state"]["processes"],
        "retired_processes": telemetry["host_state"]["retired_processes"],
        "telemetry": telemetry,
    }


def wait_for_sample(process, logs_dir):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            return sample(process, logs_dir)
        except (OSError, json.JSONDecodeError, KeyError):
            time.sleep(0.2)
    raise AssertionError("agent did not write usable host-state telemetry")


def assert_no_process_drops(snapshot):
    telemetry = snapshot["telemetry"]
    family = next(f for f in telemetry["linux_ebpf"]["families"] if f["ring"] == "process")
    for counter in ("kernel_ring_full", "kernel_map_full", "short_reads", "userspace_dropped"):
        if family[counter]:
            raise AssertionError(f"process sensor {counter}={family[counter]}")
    for channel in telemetry["channels"]:
        if channel["channel"] == "sensor_events" and channel["dropped"]:
            raise AssertionError(f"sensor ingress dropped {channel['dropped']} events")


def record_sample(process, logs_dir, report, label):
    snapshot = wait_for_sample(process, logs_dir)
    row = {"phase": label, **snapshot}
    report.append(row)
    print(json.dumps({k: v for k, v in row.items() if k != "telemetry"}), flush=True)
    assert_no_process_drops(snapshot)
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rules-dir", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--launches", type=int, default=20_000)
    parser.add_argument("--idle-seconds", type=int, default=75)
    parser.add_argument("--max-live-growth", type=int, default=8)
    parser.add_argument("--max-retired-background", type=int, default=128)
    parser.add_argument("--max-rss-growth-mib", type=int, default=16)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run this soak as root on an isolated Linux host")
    if args.rounds < 2 or args.launches < 1 or args.idle_seconds < 75:
        parser.error("use at least two rounds, one launch, and 75 idle seconds")
    if min(args.max_live_growth, args.max_retired_background, args.max_rss_growth_mib) < 0:
        parser.error("growth limits must be nonnegative")

    binary = args.binary.resolve()
    artifacts_dir = args.artifacts_dir.resolve()
    run_dir = artifacts_dir / f"run-{int(time.time())}-{os.getpid()}"
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True)
    config = run_dir / "config.toml"
    write_config(config, args.rules_dir.resolve(), logs_dir)
    report = []
    process = None
    try:
        with (run_dir / "agent.stdout.log").open("w") as stdout, (
            run_dir / "agent.stderr.log"
        ).open("w") as stderr:
            process = subprocess.Popen(
                [str(binary), "--config", str(config), "run", "--no-console"],
                cwd=run_dir,
                stdout=stdout,
                stderr=stderr,
            )
            wait_for_startup(process, logs_dir)
            time.sleep(3)
            baseline = record_sample(process, logs_dir, report, "baseline")
            warm_rss = None
            for round_index in range(1, args.rounds + 1):
                # close_fds uses Python's fork/exec path, also exercising fork inheritance.
                for _ in range(args.launches):
                    subprocess.run(["/bin/true"], check=True, close_fds=True)
                time.sleep(3)
                burst = record_sample(process, logs_dir, report, f"burst-{round_index}")
                if burst["processes"] > baseline["processes"] + args.max_live_growth:
                    raise AssertionError("live process identities accumulated after exit")
                family = next(
                    f for f in burst["telemetry"]["linux_ebpf"]["families"]
                    if f["ring"] == "process"
                )
                if family["canonical_emitted"] < round_index * args.launches:
                    raise AssertionError("sensor did not observe the process burst")
                # TTL is 60s, cleanup runs at most every 10s, telemetry every 1s.
                time.sleep(args.idle_seconds)
                settled = record_sample(process, logs_dir, report, f"settled-{round_index}")
                if settled["retired_processes"] > args.max_retired_background:
                    raise AssertionError("burst metadata did not expire from the graveyard")
                if settled["processes"] > baseline["processes"] + args.max_live_growth:
                    raise AssertionError("live process cache did not return to baseline")
                if warm_rss is None:
                    warm_rss = settled["rss_kib"]
                elif settled["rss_kib"] > warm_rss + args.max_rss_growth_mib * 1024:
                    raise AssertionError("RSS continued growing after the first warmup burst")
            stop_agent(process)
        print(f"process cache soak passed; samples: {run_dir / 'samples.json'}", flush=True)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        (run_dir / "samples.json").write_text(json.dumps(report, indent=2) + "\n")
        make_artifacts_readable(artifacts_dir)


if __name__ == "__main__":
    main()
