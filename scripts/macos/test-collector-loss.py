#!/usr/bin/env python3
"""Overload a disposable privileged agent capturing lo0 and assert kernel loss.

Usage: sudo python3 scripts/macos/test-collector-loss.py PID SNAPSHOT_PATH
Start the entitled agent with telemetry enabled and lo0 included in capture.
This deliberately suspends detection briefly. Use only on a test Mac.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import tempfile
import threading
import time


def counts(path):
    snapshot = json.loads(path.read_text())
    macos = snapshot["macos_collectors"]
    return (
        macos["esf"]["kernel_dropped"],
        macos["bpf"]["kernel_dropped"],
    )


def flood(stop):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while not stop.is_set():
            sock.sendto(b"collector-loss-test" * 32, ("127.0.0.1", 53))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    baseline = counts(args.snapshot)
    snapshot = json.loads(args.snapshot.read_text())
    if snapshot["pid"] != args.pid or args.pid <= 1 or args.pid == os.getpid():
        parser.error("PID must match the running test agent's snapshot")
    bpf = snapshot["macos_collectors"]["bpf"]
    if not bpf.get("interfaces", {}).get("lo0", {}).get("active"):
        parser.error("the test requires an active lo0 capture device")
    stop = threading.Event()
    traffic = threading.Thread(target=flood, args=(stop,))
    suspended = False
    try:
        os.kill(args.pid, signal.SIGSTOP)
        suspended = True
        traffic.start()
        deadline = time.monotonic() + 10
        with tempfile.TemporaryDirectory(prefix="rustinel-loss-") as directory:
            path = Path(directory) / "event"
            while time.monotonic() < deadline:
                path.write_bytes(b"test")
                path.unlink()
    finally:
        stop.set()
        if suspended:
            os.kill(args.pid, signal.SIGCONT)
        if traffic.ident is not None:
            traffic.join()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        with tempfile.NamedTemporaryFile(prefix="rustinel-loss-probe-"):
            pass
        current = counts(args.snapshot)
        delta = tuple(after - before for after, before in zip(current, baseline))
        if all(value > 0 for value in delta):
            bpf = json.loads(args.snapshot.read_text())["macos_collectors"]["bpf"]
            for counter in ("kernel_received", "kernel_dropped", "stats_polls", "stats_errors"):
                if bpf[counter] != sum(item[counter] for item in bpf["interfaces"].values()):
                    raise SystemExit(f"FAIL: per-interface {counter} does not reconcile")
            print(f"PASS: ESF kernel gaps +{delta[0]}, BPF kernel drops +{delta[1]}")
            print("PASS: per-interface counters reconcile with BPF totals")
            return
        time.sleep(1)
    raise SystemExit(
        f"FAIL: expected loss on both sources, observed ESF +{delta[0]}, BPF +{delta[1]}. "
        "Check the ES entitlement, lo0 capture, and snapshot reporting interval."
    )


if __name__ == "__main__":
    main()
