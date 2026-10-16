#!/usr/bin/env python3
"""
Realistic and stress benchmark for Rustinel on Windows, Linux, and macOS.

The fixed-length workloads in windows.ps1 and linux.sh measure the cost of the
agent at rest. This harness measures what an operator cares about on a working
machine, with the full community rule corpus loaded:

  idle      the agent alone
  steady    a desktop-like mix of short commands, editor-style file saves,
            executable and archive drops, loopback and DNS traffic, and a
            periodic build burst, at a sustained rate
  ramp      the same mix at 2x, 4x, 8x, 16x the steady rate, to find where
            the first events are lost

Throughout, it injects canary events (one per detection engine) and checks that
each one raised its alert, and how late. It reads the agent's own telemetry to
report dropped events per channel and per sensor category, and kernel-side loss
(ETW buffers, eBPF rings, Endpoint Security).

Run it elevated (root or Administrator), once with --mode baseline (no agent)
and once per agent version:

    sudo python3 scripts/bench/realistic.py --agent ./rustinel --corpus rules-bench
    python3 scripts/bench/realistic.py compare run-a/summary.json run-b/summary.json

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import platform
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
OS_NAME = "windows" if IS_WINDOWS else "macos" if IS_MAC else "linux"

CANARY_IP_PREFIX = "203.0.113."  # TEST-NET-3, never routed
CANARY_LOOPBACK_IP = "127.0.0.2"  # Windows reports network events only for connections that complete
CANARY_DNS_SUFFIX = "rustinel-bench-canary.invalid"
CANARY_RE = re.compile(r"RUSTINEL_BENCH_CANARY_([PFYD])_(\d{6})", re.IGNORECASE)  # DNS names are lowercased
CANARY_PROCESS_RULE = "Rustinel Bench Canary Process"
CANARY_FILE_RULE = "Rustinel Bench Canary File"
CANARY_WINDOW_SECS = 30  # a canary not seen this long after injection counts as missed


# --------------------------------------------------------------------------- helpers


def now() -> float:
    return time.monotonic()


def pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round(p / 100.0 * (len(ordered) - 1)))))
    return ordered[idx]


def r(value: float | None, digits: int = 2) -> float | None:
    return None if value is None else round(value, digits)


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def is_admin() -> bool:
    if IS_WINDOWS:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def toml_str(path: str | Path) -> str:
    # TOML literal string: no escape processing, so Windows backslashes are safe.
    return "'" + str(path) + "'"


# --------------------------------------------------------------------------- process stats


class ProcStats:
    """CPU seconds, resident memory, and thread count of one process, without psutil."""

    def __init__(self, pid: int):
        self.pid = pid
        self._handle = None
        if IS_WINDOWS:
            import ctypes

            access = 0x1000 | 0x0010  # QUERY_LIMITED_INFORMATION | VM_READ
            self._handle = ctypes.windll.kernel32.OpenProcess(access, False, pid)

    def read(self) -> tuple[float, float, int] | None:
        try:
            if IS_WINDOWS:
                return self._read_windows()
            if IS_MAC:
                return self._read_mac()
            return self._read_linux()
        except Exception:
            return None

    @staticmethod
    def system_busy() -> tuple[float, float] | None:
        """(busy, total) CPU seconds across all cores since boot."""
        try:
            if IS_WINDOWS:
                import ctypes
                from ctypes import wintypes

                class FILETIME(ctypes.Structure):
                    _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

                i, k, u = FILETIME(), FILETIME(), FILETIME()
                ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
                v = lambda f: ((f.hi << 32) | f.lo) / 1e7
                total = v(k) + v(u)  # kernel time includes idle
                return total - v(i), total
            if IS_MAC:
                return None
            with open("/proc/stat") as fh:
                vals = [float(x) for x in fh.readline().split()[1:]]
            idle = vals[3] + vals[4]
            total = sum(vals[:8])
            return total - idle, total
        except Exception:
            return None

    def thread_cpu(self) -> dict[int, tuple[str, float]]:
        """Cumulative CPU seconds per thread id, with the thread name when the OS has one."""
        try:
            if IS_WINDOWS:
                return self._threads_windows()
            if IS_MAC:
                return {}
            return self._threads_linux()
        except Exception:
            return {}

    def _threads_linux(self):
        out = {}
        ticks = os.sysconf("SC_CLK_TCK")
        for tid in os.listdir(f"/proc/{self.pid}/task"):
            try:
                with open(f"/proc/{self.pid}/task/{tid}/stat") as fh:
                    raw = fh.read()
            except OSError:
                continue
            name = raw[raw.index("(") + 1 : raw.rindex(")")]
            fields = raw[raw.rindex(")") + 2 :].split()
            out[int(tid)] = (name, (int(fields[11]) + int(fields[12])) / ticks)
        return out

    def _threads_windows(self):
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.OpenThread.restype = wintypes.HANDLE

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        class FILETIME(ctypes.Structure):
            _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

        out = {}
        snap = k32.CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
        if not snap or snap == wintypes.HANDLE(-1).value:
            return out
        try:
            entry = THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            ok = k32.Thread32First(snap, ctypes.byref(entry))
            while ok:
                if entry.th32OwnerProcessID == self.pid:
                    h = k32.OpenThread(0x0800, False, entry.th32ThreadID)  # THREAD_QUERY_LIMITED_INFORMATION
                    if h:
                        c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
                        if k32.GetThreadTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
                            ticks = ((k.hi << 32) | k.lo) + ((u.hi << 32) | u.lo)
                            name = ""
                            buf = ctypes.c_wchar_p()
                            if k32.GetThreadDescription(h, ctypes.byref(buf)) >= 0 and buf.value:
                                name = buf.value
                                k32.LocalFree(buf)
                            out[entry.th32ThreadID] = (name, ticks / 1e7)
                        k32.CloseHandle(h)
                ok = k32.Thread32Next(snap, ctypes.byref(entry))
        finally:
            k32.CloseHandle(snap)
        return out

    def _read_linux(self):
        with open(f"/proc/{self.pid}/stat") as fh:
            raw = fh.read()
        fields = raw[raw.rindex(")") + 2 :].split()
        ticks = os.sysconf("SC_CLK_TCK")
        cpu = (int(fields[11]) + int(fields[12])) / ticks
        threads = int(fields[17])
        rss_kb = 0
        with open(f"/proc/{self.pid}/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
        return cpu, rss_kb / 1024.0, threads

    def _read_mac(self):
        out = subprocess.run(
            ["ps", "-p", str(self.pid), "-o", "cputime=", "-o", "rss="], capture_output=True, text=True
        ).stdout.split()
        seconds = 0.0
        for part in out[0].split(":"):
            seconds = seconds * 60 + float(part)
        return seconds, int(out[1]) / 1024.0, 0

    def _read_windows(self):
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not ctypes.windll.kernel32.GetProcessTimes(
            self._handle, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)
        ):
            return None
        ticks = ((k.hi << 32) | k.lo) + ((u.hi << 32) | u.lo)
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        if not ctypes.windll.psapi.GetProcessMemoryInfo(self._handle, ctypes.byref(pmc), pmc.cb):
            return None
        return ticks / 1e7, pmc.WorkingSetSize / (1024.0 * 1024.0), 0


class Sampler(threading.Thread):
    def __init__(self, pid: int, csv_path: Path):
        super().__init__(daemon=True)
        self.stats = ProcStats(pid)
        self.csv_path = csv_path
        self.stop_flag = threading.Event()
        self.phase = "start"
        self.samples: list[tuple[str, float, float, float, int]] = []  # phase, t, cpu%, rss_mb, threads
        self.thread_samples: list[tuple[str, float, dict]] = []  # phase, dt, {tid: (name, cpu seconds in the interval)}
        self.system_samples: list[tuple[str, float]] = []  # phase, whole-machine busy percent
        self.lock = threading.Lock()

    def run(self):
        with open(self.csv_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["time", "phase", "cpu_percent", "rss_mb", "threads"])
            last = self.stats.read()
            last_t = now()
            last_threads = self.stats.thread_cpu()
            last_sys = self.stats.system_busy()
            while not self.stop_flag.wait(1.0):
                cur = self.stats.read()
                t = now()
                threads = self.stats.thread_cpu()
                if threads and last_threads:
                    delta = {tid: (n, c - last_threads.get(tid, (n, 0.0))[1]) for tid, (n, c) in threads.items()}
                    with self.lock:
                        self.thread_samples.append((self.phase, t - last_t, delta))
                last_threads = threads
                sys_now = self.stats.system_busy()
                if sys_now and last_sys and sys_now[1] > last_sys[1]:
                    with self.lock:
                        self.system_samples.append((self.phase, (sys_now[0] - last_sys[0]) / (sys_now[1] - last_sys[1]) * 100.0))
                last_sys = sys_now
                if cur is None or last is None:
                    last, last_t = cur, t
                    continue
                cpu = max(0.0, (cur[0] - last[0]) / max(t - last_t, 1e-6) * 100.0)
                with self.lock:
                    self.samples.append((self.phase, t, cpu, cur[1], cur[2]))
                writer.writerow([f"{t:.2f}", self.phase, f"{cpu:.2f}", f"{cur[1]:.1f}", cur[2]])
                last, last_t = cur, t

    def thread_summary(self, phase: str, top: int = 6) -> list[dict]:
        """The busiest threads of a phase: average and peak percent of one core."""
        with self.lock:
            rows = [s for s in self.thread_samples if s[0] == phase]
        per: dict[int, dict] = {}
        for _, dt, delta in rows:
            for tid, (name, cpu) in delta.items():
                e = per.setdefault(tid, {"name": name, "cpu": 0.0, "peak": 0.0})
                e["cpu"] += cpu
                e["peak"] = max(e["peak"], cpu / max(dt, 1e-6) * 100.0)
                e["name"] = e["name"] or name
        total = sum(dt for _, dt, _ in rows) or 1.0
        ranked = sorted(per.items(), key=lambda kv: -kv[1]["cpu"])[:top]
        return [{"tid": tid, "name": e["name"], "avg_percent": r(e["cpu"] / total * 100.0, 1), "peak_percent": r(e["peak"], 1)} for tid, e in ranked]

    def summary(self, phase: str) -> dict:
        with self.lock:
            rows = [s for s in self.samples if s[0] == phase]
        if not rows:
            return {"samples": 0}
        cpu = [s[2] for s in rows]
        rss = [s[3] for s in rows]
        return {
            "samples": len(rows),
            "cpu_avg_percent": r(statistics.mean(cpu), 3),
            "cpu_p95_percent": r(pct(cpu, 95), 3),
            "cpu_max_percent": r(max(cpu), 3),
            "rss_avg_mb": r(statistics.mean(rss), 1),
            "rss_max_mb": r(max(rss), 1),
            "threads_max": max(s[4] for s in rows),
            "top_threads": self.thread_summary(phase),
            "machine_cpu_avg_percent": r(statistics.mean([c for p_, c in self.system_samples if p_ == phase]), 1) if any(p_ == phase for p_, _ in self.system_samples) else None,
        }


# --------------------------------------------------------------------------- telemetry


def read_telemetry(path: Path) -> dict | None:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except Exception:
        return None


def sync_telemetry(path: Path, timeout: float = 20.0) -> dict | None:
    """Wait for a snapshot written after this call, then return it."""
    start = time.time()
    deadline = start + timeout
    while time.time() < deadline:
        try:
            if os.path.getmtime(path) > start:
                break
        except OSError:
            pass
        time.sleep(0.5)
    return read_telemetry(path)


def _kernel_numbers(node, out: dict, prefix: str = "") -> None:
    keys = ("ring_full", "map_full", "oversized", "kernel_dropped")
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (int, float)) and any(key.endswith(k) or key == k for k in keys):
                out[prefix + key] = out.get(prefix + key, 0) + value
            else:
                _kernel_numbers(value, out, prefix)
    elif isinstance(node, list):
        for item in node:
            _kernel_numbers(item, out, prefix)


def telemetry_counters(t: dict | None) -> dict:
    if not t:
        return {}
    chan = {c["channel"]: (c.get("accepted", 0), c.get("dropped", 0)) for c in t.get("channels", [])}
    cats = {c["category"]: (c.get("accepted", 0), c.get("dropped", 0)) for c in t.get("sensor_events_by_category", [])}
    kernel: dict = {}
    for section in ("linux_ebpf", "macos_collectors"):
        if section in t:
            _kernel_numbers(t[section], kernel, section + ".")
    return {"channels": chan, "categories": cats, "kernel": kernel}


def etw_lost_from_logs(log_dir: Path) -> int:
    """Windows ETW kernel buffer loss is only logged: `lost_total=N`."""
    best = 0
    for path in glob.glob(str(log_dir / "rustinel.log*")):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for m in re.finditer(r"lost_total=(\d+)", fh.read()):
                    best = max(best, int(m.group(1)))
        except OSError:
            pass
    return best


def delta_counters(a: dict, b: dict) -> dict:
    out = {"channels": {}, "categories": {}, "kernel": {}}
    for section in ("channels", "categories"):
        for name, (acc, drop) in b.get(section, {}).items():
            pa, pd = a.get(section, {}).get(name, (0, 0))
            out[section][name] = {"accepted": acc - pa, "dropped": drop - pd}
    for name, value in b.get("kernel", {}).items():
        out["kernel"][name] = value - a.get("kernel", {}).get(name, 0)
    return out


# --------------------------------------------------------------------------- canaries


class Canaries:
    """Inject one event per detection engine and watch the alert files for each."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.listener = None
        if IS_WINDOWS:
            # The Windows network provider reports a connection once it completes, so a canary to an
            # unrouted address is never seen. Complete one to a second loopback address instead.
            self.listener = socket.socket()
            self.listener.bind((CANARY_LOOPBACK_IP, 0))
            self.listener.listen(8)
            threading.Thread(target=self._accept, daemon=True).start()
        self.sent: dict[str, dict] = {}  # key -> {kind, t_send, t_seen, phase}
        self.lock = threading.Lock()
        self.counter = 0
        self.phase = "start"

    def _accept(self):
        while True:
            try:
                conn, _ = self.listener.accept()
                conn.close()
            except OSError:
                return

    def _next(self) -> int:
        self.counter += 1
        return self.counter

    def _record(self, key: str, kind: str):
        with self.lock:
            self.sent[key] = {"kind": kind, "t_send": now(), "t_seen": None, "phase": self.phase}

    def send_all(self):
        n = self._next()
        cid = f"{n:06d}"
        # P: Sigma process_creation on the command line
        self._record(f"P{cid}", "sigma_process")
        marker = f"RUSTINEL_BENCH_CANARY_P_{cid}"
        cmd = ["cmd", "/c", "echo", marker] if IS_WINDOWS else ["/bin/echo", marker]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # F: Sigma file_event on the file name
        self._record(f"F{cid}", "sigma_file")
        (self.workdir / f"RUSTINEL_BENCH_CANARY_F_{cid}.txt").write_text("canary")
        # Y: YARA on the content of a written script
        self._record(f"Y{cid}", "yara_file")
        (self.workdir / f"RUSTINEL_BENCH_CANARY_Y_{cid}.ps1").write_text(f"# RUSTINEL_BENCH_YARA_CANARY_{cid}\n")
        # N: IOC IP, a connection attempt to a listed address; the port identifies it
        s = socket.socket()
        if self.listener is not None:
            s.bind((CANARY_LOOPBACK_IP, 0))  # the unique source port identifies the canary
            port = s.getsockname()[1]
            self._record(f"N{port}", "ioc_ip")
            try:
                s.connect((CANARY_LOOPBACK_IP, self.listener.getsockname()[1]))
            except OSError:
                pass
        else:
            port = 20000 + (n % 20000)  # the destination port identifies the canary
            self._record(f"N{port}", "ioc_ip")
            s.setblocking(False)
            try:
                s.connect_ex((f"{CANARY_IP_PREFIX}{n % 250 + 1}", port))
            except OSError:
                pass
            time.sleep(0.05)
        s.close()
        # D: IOC domain, a lookup of a listed wildcard name
        self._record(f"D{cid}", "ioc_domain")
        try:
            socket.getaddrinfo(f"RUSTINEL_BENCH_CANARY_D_{cid}.{CANARY_DNS_SUFFIX}".lower(), None)
        except OSError:
            pass

    def seen(self, key: str):
        with self.lock:
            entry = self.sent.get(key)
            if entry and entry["t_seen"] is None:
                entry["t_seen"] = now()

    def summary(self) -> dict:
        out: dict = {}
        with self.lock:
            entries = list(self.sent.values())
        t = now()
        for entry in entries:
            if entry["t_seen"] is None and t - entry["t_send"] < CANARY_WINDOW_SECS:
                continue  # still in flight
            for scope in (entry["phase"], "all"):
                bucket = out.setdefault(scope, {}).setdefault(entry["kind"], {"sent": 0, "detected": 0, "latency_s": []})
                bucket["sent"] += 1
                if entry["t_seen"] is not None:
                    bucket["detected"] += 1
                    bucket["latency_s"].append(entry["t_seen"] - entry["t_send"])
        for scope in out.values():
            for bucket in scope.values():
                lat = bucket.pop("latency_s")
                bucket["detected_percent"] = r(100.0 * bucket["detected"] / bucket["sent"], 1) if bucket["sent"] else None
                bucket["latency_p50_s"] = r(pct(lat, 50), 3)
                bucket["latency_p95_s"] = r(pct(lat, 95), 3)
                bucket["latency_max_s"] = r(max(lat), 3) if lat else None
        return out


class AlertTail(threading.Thread):
    def __init__(self, alert_glob: str, canaries: Canaries):
        super().__init__(daemon=True)
        self.alert_glob = alert_glob
        self.canaries = canaries
        self.stop_flag = threading.Event()
        self.offsets: dict[str, int] = {}
        self.total = 0
        self.canary_alerts = 0
        self.rules: dict[str, int] = {}
        self.phase_counts: dict[str, int] = {}
        self.phase = "start"
        self.carry: dict[str, str] = {}

    def run(self):
        while not self.stop_flag.is_set():
            self.poll()
            self.stop_flag.wait(0.1)
        self.poll()

    def poll(self):
        for path in glob.glob(self.alert_glob):
            try:
                with open(path, "rb") as fh:
                    fh.seek(self.offsets.get(path, 0))
                    data = fh.read()
                    self.offsets[path] = fh.tell()
            except OSError:
                continue
            if not data:
                continue
            text = self.carry.pop(path, "") + data.decode("utf-8", "replace")
            lines = text.split("\n")
            self.carry[path] = lines.pop()  # trailing partial line
            for line in lines:
                if line.strip():
                    self.handle(line)

    def handle(self, line: str):
        self.total += 1
        self.phase_counts[self.phase] = self.phase_counts.get(self.phase, 0) + 1
        hit = False
        for m in CANARY_RE.finditer(line):
            self.canaries.seen(f"{m.group(1).upper()}{m.group(2)}")
            hit = True
        if CANARY_IP_PREFIX in line or CANARY_LOOPBACK_IP in line:
            for m in re.finditer(r'"(?:destination|source)\.port":\s*(\d+)', line):
                self.canaries.seen(f"N{m.group(1)}")
                hit = True
        if hit:
            self.canary_alerts += 1
            return
        m = re.search(r'"rule\.name":"([^"]*)"', line)
        name = m.group(1) if m else "?"
        self.rules[name] = self.rules.get(name, 0) + 1


# --------------------------------------------------------------------------- workload


class Pacer:
    """Hand out evenly spaced execution slots at a rate that can change at runtime."""

    def __init__(self):
        self.rate = 0.0
        self.lock = threading.Lock()
        self.next_t = now()

    def acquire(self, stop: threading.Event) -> bool:
        while not stop.is_set():
            with self.lock:
                rate = self.rate
                if rate <= 0:
                    wait = 0.25
                else:
                    t = now()
                    if self.next_t < t - 1.0:
                        self.next_t = t  # fell behind, do not burst to catch up
                    slot = self.next_t
                    self.next_t += 1.0 / rate
                    wait = slot - t
            if rate <= 0:
                stop.wait(wait)
                continue
            if wait > 0:
                if stop.wait(wait):
                    return False
            return True
        return False


class Workload:
    """A desktop-like activity mix. All rates are per second at multiplier 1."""

    BASE_RATES = {"proc": 6.0, "file": 120.0, "drop": 0.6, "blob": 0.5, "net": 8.0, "dns": 1.0, "reg": 6.0}

    def __init__(self, workdir: Path, seed: int, dns: bool):
        self.workdir = workdir
        self.rng = random.Random(seed)
        self.dns = dns
        self.stop = threading.Event()
        self.mult = 0.0
        self.pacers = {k: Pacer() for k in self.BASE_RATES}
        self.lat: dict[str, list[tuple[str, float]]] = {k: [] for k in self.BASE_RATES}
        self.done = {k: 0 for k in self.BASE_RATES}
        self.errors = {k: 0 for k in self.BASE_RATES}
        self.phase = "start"
        self.lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.files: list[Path] = []
        self.proj = workdir / "project"
        self.downloads = workdir / "downloads"
        self.build = workdir / "build"
        for d in (self.proj, self.downloads, self.build):
            d.mkdir(parents=True, exist_ok=True)
        self.blob_pool = os.urandom(4 * 1024 * 1024)
        self.server = None
        self.server_port = 0
        self.python = sys.executable
        if IS_WINDOWS:
            sysdir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
            self.cmds = [
                ["cmd", "/c", "ver"],
                ["hostname"],
                ["cmd", "/c", "dir", str(workdir)],
                [str(sysdir / "findstr.exe"), "/?"],
                [str(sysdir / "where.exe"), "cmd"],
                ["cmd", "/c", "echo build && echo done"],
            ]
            self.exe_sources = [sysdir / n for n in ("hostname.exe", "find.exe", "where.exe", "findstr.exe", "attrib.exe")]
            self.exe_suffix = ".exe"
            self.can_exec_drops = True
        elif IS_MAC:
            self.cmds = [["/bin/ls", str(workdir)], ["/bin/date"], ["/bin/hostname"],
                         ["/bin/sh", "-c", "ls >/dev/null; date >/dev/null"], ["/usr/bin/sw_vers"]]
            self.exe_sources = [Path(p) for p in ("/bin/ls", "/bin/cat", "/bin/date", "/bin/echo")]
            self.exe_suffix = ""
            self.can_exec_drops = False  # macOS kills a re-signed copy of a system binary
        else:
            self.cmds = [["/bin/ls", str(workdir)], ["/bin/date"], ["/bin/hostname"],
                         ["/bin/sh", "-c", "ls >/dev/null; date >/dev/null"],
                         ["/usr/bin/env"], ["/bin/cat", "/etc/os-release"]]
            self.exe_sources = [Path(p) for p in ("/bin/ls", "/bin/cat", "/bin/date", "/usr/bin/env", "/bin/echo") if Path(p).exists()]
            self.exe_suffix = ""
            self.can_exec_drops = True
        self.exe_sources = [p for p in self.exe_sources if p.exists()]
        self._seed_tree()

    # -- setup

    def _seed_tree(self):
        for i in range(40):
            (self.proj / f"pkg{i:02d}").mkdir(exist_ok=True)
        for i in range(1500):
            p = self.proj / f"pkg{i % 40:02d}" / f"src_{i:05d}.txt"
            p.write_bytes(self._payload(small=True))
            self.files.append(p)

    def _payload(self, small: bool = False) -> bytes:
        if small:
            size = int(min(self.rng.lognormvariate(7.0, 1.2), 64 * 1024))
        else:
            size = self.rng.randint(512 * 1024, 3 * 1024 * 1024)
        off = self.rng.randint(0, len(self.blob_pool) - size - 1) if size < len(self.blob_pool) - 1 else 0
        return self.blob_pool[off : off + size]

    def start_server(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(64)
        self.server = srv
        self.server_port = srv.getsockname()[1]

        def serve():
            while not self.stop.is_set():
                try:
                    srv.settimeout(0.5)
                    conn, _ = srv.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.settimeout(1.0)
                    data = conn.recv(256)
                    conn.sendall(data)
                except OSError:
                    pass
                finally:
                    conn.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self.threads.append(t)

    # -- operations

    def _timed(self, kind: str, fn):
        t0 = now()
        try:
            fn()
            ok = True
        except Exception:
            ok = False
        dt = now() - t0
        with self.lock:
            if ok:
                self.done[kind] += 1
                self.lat[kind].append((self.phase, dt))
            else:
                self.errors[kind] += 1

    def op_proc(self):
        def run():
            flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
            subprocess.run(self.rng.choice(self.cmds), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)

        self._timed("proc", run)

    def op_file(self):
        roll = self.rng.random()

        def run():
            if roll < 0.30 or not self.files:  # new file
                p = self.proj / f"pkg{self.rng.randrange(40):02d}" / f"new_{self.rng.getrandbits(40):x}.txt"
                p.write_bytes(self._payload(small=True))
                with self.lock:
                    self.files.append(p)
            elif roll < 0.55:  # editor-style save: temp file then replace
                p = self.rng.choice(self.files)
                tmp = p.with_suffix(".tmp")
                tmp.write_bytes(self._payload(small=True))
                os.replace(tmp, p)
            elif roll < 0.80:  # read
                p = self.rng.choice(self.files)
                p.read_bytes()
            elif roll < 0.90:  # rename
                with self.lock:
                    if not self.files:
                        return
                    i = self.rng.randrange(len(self.files))
                    p = self.files[i]
                    q = p.with_name(f"mv_{self.rng.getrandbits(40):x}.txt")
                    self.files[i] = q
                os.replace(p, q)
            else:  # delete, keep a floor
                with self.lock:
                    if len(self.files) < 500:
                        return
                    p = self.files.pop(self.rng.randrange(len(self.files)))
                os.remove(p)

        self._timed("file", run)

    def op_drop(self):
        """A downloaded executable, sometimes run: exercises hashing, YARA, and image resolution."""

        def run():
            if not self.exe_sources:
                return
            src = self.rng.choice(self.exe_sources)
            dst = self.downloads / f"tool_{self.rng.getrandbits(40):x}{self.exe_suffix}"
            shutil.copyfile(src, dst)
            if not IS_WINDOWS:
                os.chmod(dst, 0o755)
            if self.can_exec_drops and self.rng.random() < 0.3:
                flags = 0x08000000 if IS_WINDOWS else 0
                subprocess.run([str(dst)] + (["/?"] if IS_WINDOWS else ["--version"]), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, creationflags=flags, timeout=10)
            # keep the downloads folder bounded
            files = sorted(self.downloads.iterdir(), key=lambda p: p.stat().st_mtime)
            for old in files[:-60]:
                try:
                    old.unlink()
                except OSError:
                    pass

        self._timed("drop", run)

    def op_blob(self):
        """An archive or document written to disk (larger, not executable)."""

        def run():
            ext = self.rng.choice([".zip", ".pdf", ".docx", ".7z", ".js", ".ps1"])
            p = self.downloads / f"doc_{self.rng.getrandbits(40):x}{ext}"
            p.write_bytes(self._payload(small=False))

        self._timed("blob", run)

    def op_net(self):
        def run():
            with socket.create_connection(("127.0.0.1", self.server_port), timeout=2) as s:
                s.sendall(b"ping" * 16)
                s.recv(256)

        self._timed("net", run)

    NAMES = ["example.com", "github.com", "pypi.org", "crates.io", "wikipedia.org", "debian.org", "microsoft.com", "apple.com"]

    def op_dns(self):
        if not self.dns:
            return

        def run():
            name = self.rng.choice(self.NAMES)
            if self.rng.random() < 0.5:
                name = f"{self.rng.getrandbits(32):x}.{name}"
            try:
                socket.getaddrinfo(name, 443)
            except socket.gaierror:
                pass  # NXDOMAIN or offline: the query still happened

        self._timed("dns", run)

    def op_reg(self):
        if not IS_WINDOWS:
            return

        def run():
            import winreg

            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\RustinelBench") as key:
                name = f"v{self.rng.randrange(200)}"
                if self.rng.random() < 0.7:
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, f"value-{self.rng.getrandbits(32):x}")
                else:
                    try:
                        winreg.DeleteValue(key, name)
                    except OSError:
                        pass

        self._timed("reg", run)

    def build_burst(self):
        """Roughly a `make -j8`: many short interpreters each reading and writing a few files."""
        script = (
            "import hashlib,os,sys\n"
            "d=sys.argv[1]\n"
            "h=hashlib.sha256()\n"
            "for i in range(8):\n"
            "    p=os.path.join(d,'o%s_%d.obj'%(os.getpid(),i)); open(p,'wb').write(os.urandom(4096)); h.update(open(p,'rb').read())\n"
        )
        procs = []
        for _ in range(24):
            flags = 0x08000000 if IS_WINDOWS else 0
            procs.append(subprocess.Popen([self.python, "-c", script, str(self.build)], stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, creationflags=flags))
            if len(procs) >= 8:
                procs.pop(0).wait()
        for p in procs:
            p.wait()
        for f in list(self.build.iterdir())[:-400]:
            try:
                f.unlink()
            except OSError:
                pass

    # -- control

    def _worker(self, kind: str, fn):
        pacer = self.pacers[kind]
        while pacer.acquire(self.stop):
            fn()

    THREADS = {"proc": 4, "file": 4, "drop": 2, "blob": 1, "net": 2, "dns": 2, "reg": 1}

    def start(self):
        self.start_server()
        ops = {"proc": self.op_proc, "file": self.op_file, "drop": self.op_drop, "blob": self.op_blob,
               "net": self.op_net, "dns": self.op_dns, "reg": self.op_reg}
        for kind, fn in ops.items():
            for _ in range(self.THREADS[kind]):
                t = threading.Thread(target=self._worker, args=(kind, fn), daemon=True)
                t.start()
                self.threads.append(t)

        def builder():
            while not self.stop.wait(1.0):
                if self.mult > 0 and int(now()) % 60 == 0:
                    self.build_burst()
                    self.stop.wait(2.0)

        t = threading.Thread(target=builder, daemon=True)
        t.start()
        self.threads.append(t)

    def set_multiplier(self, mult: float):
        self.mult = mult
        for kind, base in self.BASE_RATES.items():
            self.pacers[kind].rate = base * mult

    def set_phase(self, phase: str):
        self.phase = phase

    def phase_summary(self, phase: str, seconds: float) -> dict:
        out = {}
        with self.lock:
            for kind in self.BASE_RATES:
                lat = [d for p, d in self.lat[kind] if p == phase]
                if not lat:
                    continue
                out[kind] = {
                    "ops": len(lat),
                    "ops_per_s": r(len(lat) / seconds, 2),
                    "latency_p50_ms": r(pct(lat, 50) * 1000, 2),
                    "latency_p95_ms": r(pct(lat, 95) * 1000, 2),
                    "latency_max_ms": r(max(lat) * 1000, 2),
                }
        return out

    def shutdown(self):
        self.stop.set()
        for t in self.threads:
            t.join(timeout=3)
        if self.server:
            self.server.close()


# --------------------------------------------------------------------------- agent


def agent_version(agent: str) -> tuple[int, ...]:
    out = subprocess.run([agent, "--version"], capture_output=True, text=True).stdout
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


CANARY_SIGMA = """title: {name}
id: {id}
status: test
description: Canary used by scripts/bench/realistic.py
logsource:
  category: {category}
  product: {product}
detection:
  selection:
    {field}|contains: 'RUSTINEL_BENCH_CANARY_{tag}_'
  condition: selection
level: critical
"""

CANARY_YARA = """rule Rustinel_Bench_Canary {
    meta:
        description = "Canary used by scripts/bench/realistic.py"
    strings:
        $a = "RUSTINEL_BENCH_YARA_CANARY_"
    condition:
        $a
}
"""


def prepare_rules(corpus: Path, run_dir: Path) -> dict[str, Path]:
    rules = run_dir / "rules"
    shutil.rmtree(rules, ignore_errors=True)
    for sub in ("sigma", "yara", "ioc"):
        src = corpus / sub
        if src.is_dir():
            shutil.copytree(src, rules / sub)
        else:
            (rules / sub).mkdir(parents=True)
    product = OS_NAME
    (rules / "sigma" / "rustinel_bench_canary_process.yml").write_text(
        CANARY_SIGMA.format(name=CANARY_PROCESS_RULE, id="0c1a5e6e-7a53-4a6a-9d44-2b6c8f1d0a01", category="process_creation",
                            product=product, field="CommandLine", tag="P"))
    (rules / "sigma" / "rustinel_bench_canary_file.yml").write_text(
        CANARY_SIGMA.format(name=CANARY_FILE_RULE, id="0c1a5e6e-7a53-4a6a-9d44-2b6c8f1d0a02", category="file_event",
                            product=product, field="TargetFilename", tag="F"))
    (rules / "yara" / "rustinel_bench_canary.yar").write_text(CANARY_YARA)
    ioc = rules / "ioc"
    for name, header in (("hashes.txt", "# Hashes"), ("ips.txt", "# IPs"), ("domains.txt", "# Domains"), ("paths_regex.txt", "# Path regex")):
        if not (ioc / name).exists():
            (ioc / name).write_text(header + "\n")
    with open(ioc / "ips.txt", "a", newline="\n") as fh:
        for i in range(1, 251):
            fh.write(f"{CANARY_IP_PREFIX}{i};rustinel-bench-canary\n")
    with open(ioc / "domains.txt", "a", newline="\n") as fh:
        fh.write(f"*.{CANARY_DNS_SUFFIX};rustinel-bench-canary\n")
    with open(ioc / "ips.txt", "a", newline="\n") as fh:
        fh.write(f"{CANARY_LOOPBACK_IP};rustinel-bench-canary\n")
    return {"sigma": rules / "sigma", "yara": rules / "yara", "ioc": ioc}


def config_path(run_dir: Path) -> Path:
    return run_dir / "config" / "config.toml"


def write_config(run_dir: Path, rules: dict[str, Path], version: tuple[int, ...]) -> tuple[Path, Path]:
    log_dir = run_dir / "agent-logs"
    # The agent watches the config file's parent directory and re-fingerprints every rule file on any
    # write there, so the config gets its own directory away from the sample and log files.
    cfg = config_path(run_dir)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    text = f"""[scanner]
sigma_rules_path = {toml_str(rules['sigma'])}
yara_rules_path = {toml_str(rules['yara'])}

[logging]
directory = {toml_str(log_dir)}

[alerts]
directory = {toml_str(log_dir)}

[ioc]
hashes_path = {toml_str(rules['ioc'] / 'hashes.txt')}
ips_path = {toml_str(rules['ioc'] / 'ips.txt')}
domains_path = {toml_str(rules['ioc'] / 'domains.txt')}
paths_regex_path = {toml_str(rules['ioc'] / 'paths_regex.txt')}

[telemetry]
enabled = true
snapshot_interval_secs = 5
"""
    if version >= (1, 10, 0):
        text += "loss_alert_interval_secs = 15\n"
        text += f"\n[agent]\ndirectory = {toml_str(run_dir / 'agent-state')}\n"
    cfg.write_text(text)
    return cfg, log_dir


def start_agent(agent: str, cfg: Path, run_dir: Path) -> subprocess.Popen:
    out = open(run_dir / "agent.stdout.log", "w")
    flags = 0x00000200 if IS_WINDOWS else 0  # CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen([agent, "--config", str(cfg), "run"], stdout=out, stderr=subprocess.STDOUT, creationflags=flags)


def wait_ready(proc: subprocess.Popen, run_dir: Path, timeout: float = 240.0) -> float | None:
    t0 = now()
    path = run_dir / "agent.stdout.log"
    while now() - t0 < timeout:
        if proc.poll() is not None:
            return None
        try:
            if "Agent ready" in path.read_text(errors="replace"):
                return now() - t0
        except OSError:
            pass
        time.sleep(0.5)
    return None


def stop_agent(proc: subprocess.Popen):
    if proc.poll() is not None:
        return
    try:
        if IS_WINDOWS:
            proc.terminate()
        else:
            import signal

            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=30)
    except Exception:
        proc.kill()


# --------------------------------------------------------------------------- run


def run(args) -> int:
    if args.mode == "with-agent" and not is_admin():
        print("Run elevated: root (sudo) or an Administrator shell. The sensors need it.", file=sys.stderr)
        return 2
    corpus = Path(args.corpus).resolve()
    if args.mode == "with-agent" and not (corpus / "sigma").is_dir():
        print(f"--corpus must contain sigma/, yara/, ioc/ (python scripts/rules/fetch_corpus.py --output {corpus})", file=sys.stderr)
        return 2
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = Path(args.output_dir).resolve() / f"{args.mode}-{OS_NAME}-{stamp}"
    run_dir.mkdir(parents=True)
    workdir = run_dir / "work"
    workdir.mkdir()
    errors: list[str] = []
    summary: dict = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": OS_NAME,
        "mode": args.mode,
        "machine": {"os": platform.platform(), "cpu": platform.processor(), "logical_cpus": os.cpu_count(),
                    "python": platform.python_version()},
        "parameters": {k: getattr(args, k) for k in ("idle_secs", "warmup_secs", "steady_secs", "ramp", "ramp_step_secs", "seed", "dns")},
        "phases": {},
    }
    proc = None
    sampler = None
    tail = None
    canaries = Canaries(workdir)
    workload = Workload(workdir, args.seed, args.dns)
    log_dir = run_dir / "agent-logs"
    tele_path = log_dir / "telemetry.json"
    counters_prev: dict = {}
    etw_prev = 0
    try:
        if args.mode == "with-agent":
            agent = str(Path(args.agent).resolve())
            version = agent_version(agent)
            summary["agent"] = {"path": agent, "version": ".".join(map(str, version))}
            log(f"preparing rules from {corpus}")
            rules = prepare_rules(corpus, run_dir)
            summary["rule_inventory"] = {
                "sigma_files": sum(1 for _ in rules["sigma"].rglob("*.y*ml")),
                "yara_files": sum(1 for _ in rules["yara"].rglob("*.yar*")),
                "ioc_lines": {p.name: sum(1 for l in open(p, errors="replace") if l.strip() and not l.startswith("#"))
                              for p in rules["ioc"].glob("*.txt")},
            }
            meta = corpus / "sources" / "metadata.json"
            if meta.exists():
                summary["corpus_metadata"] = json.loads(meta.read_text())
            cfg, log_dir = write_config(run_dir, rules, version)
            tele_path = log_dir / "telemetry.json"
            log(f"starting {agent} (version {summary['agent']['version']})")
            proc = start_agent(agent, cfg, run_dir)
            ready = wait_ready(proc, run_dir)
            if ready is None:
                errors.append("the agent did not become ready")
                raise RuntimeError("agent did not start; see agent.stdout.log")
            summary["agent"]["startup_seconds"] = r(ready, 1)
            log(f"agent ready after {ready:.1f}s (pid {proc.pid})")
            sampler = Sampler(proc.pid, run_dir / "resource-samples.csv")
            sampler.start()
            tail = AlertTail(str(log_dir / "alerts.json*"), canaries)
            tail.start()
            time.sleep(5)
            counters_prev = telemetry_counters(sync_telemetry(tele_path))
            etw_prev = etw_lost_from_logs(log_dir)

        workload.start()
        seq = [("idle", 0.0, args.idle_secs), ("warmup", 1.0, args.warmup_secs), ("steady", 1.0, args.steady_secs)]
        if not args.skip_ramp:
            for m in args.ramp:
                seq.append((f"ramp_x{m:g}", float(m), args.ramp_step_secs))
        for name, mult, secs in seq:
            if secs <= 0:
                continue
            canaries.phase = name
            workload.set_phase(name)
            if sampler:
                sampler.phase = name
            if tail:
                tail.phase = name
            workload.set_multiplier(mult)
            log(f"phase {name}: x{mult:g} for {secs}s")
            t_end = now() + secs
            t_phase = now()
            next_canary = now() + 3
            while now() < t_end:
                if proc is not None and proc.poll() is not None:
                    errors.append(f"the agent exited during {name} with code {proc.returncode}")
                    raise RuntimeError("agent exited")
                if args.mode == "with-agent" and name != "idle" and now() >= next_canary:
                    canaries.send_all()
                    next_canary = now() + args.canary_interval
                time.sleep(0.2)
            elapsed = now() - t_phase
            phase: dict = {"multiplier": mult, "seconds": r(elapsed, 1), "workload": workload.phase_summary(name, elapsed)}
            if proc is not None:
                phase["agent"] = sampler.summary(name)
                cur = telemetry_counters(sync_telemetry(tele_path))
                d = delta_counters(counters_prev, cur)
                counters_prev = cur
                sensor = d["channels"].get("sensor_events", {})
                phase["events"] = {
                    "sensor_events_accepted": sensor.get("accepted"),
                    "sensor_events_per_s": r((sensor.get("accepted") or 0) / elapsed, 1),
                }
                phase["events"]["accepted_by_category_per_s"] = {
                    k: r(v["accepted"] / elapsed, 1) for k, v in sorted(d["categories"].items(), key=lambda kv: -kv[1]["accepted"]) if v["accepted"]
                }
                phase["dropped_by_channel"] = {k: v["dropped"] for k, v in d["channels"].items() if v["dropped"]}
                phase["dropped_by_category"] = {k: v["dropped"] for k, v in d["categories"].items() if v["dropped"]}
                phase["kernel_loss"] = {k: v for k, v in d["kernel"].items() if v}
                etw = etw_lost_from_logs(log_dir)
                if etw - etw_prev:
                    phase["kernel_loss"]["etw_events_lost"] = etw - etw_prev
                etw_prev = etw
                phase["background_alerts"] = (tail.phase_counts.get(name, 0))
            summary["phases"][name] = phase

        if proc is not None:
            time.sleep(CANARY_WINDOW_SECS if not args.skip_drain else 3)  # let in-flight canaries land
    except Exception as exc:  # noqa: BLE001
        errors.append(f"harness error: {exc}")
    finally:
        workload.shutdown()
        if tail:
            tail.stop_flag.set()
            tail.join(timeout=5)
        if sampler:
            sampler.stop_flag.set()
            sampler.join(timeout=3)
        doctor_ok = False
        if proc is not None:
            if proc.poll() is None and config_path(run_dir).exists():
                d = subprocess.run([str(Path(args.agent).resolve()), "--config", str(config_path(run_dir)), "doctor", "--json"],
                                   capture_output=True, text=True)
                (run_dir / "doctor.json").write_text(d.stdout)
                doctor_ok = True
            stop_agent(proc)
        shutil.rmtree(workdir, ignore_errors=True)

    # ------------------------------------------------------------------ verdicts
    if proc is not None:
        summary["canaries"] = canaries.summary()
        summary["alerts"] = {"total": tail.total if tail else 0, "canary": tail.canary_alerts if tail else 0,
                             "top_rules": dict(sorted((tail.rules if tail else {}).items(), key=lambda kv: -kv[1])[:10])}
        if doctor_ok:
            try:
                doc = json.loads((run_dir / "doctor.json").read_text())
                bad = [c for c in doc.get("results", []) if str(c.get("status", "")).lower() in ("warn", "fail")]
                summary["doctor_findings"] = [{"id": c.get("id"), "status": c.get("status"), "message": c.get("message"), "detail": c.get("detail")} for c in bad]
            except Exception:
                summary["doctor_findings"] = "doctor output was not JSON"
        for name in ("idle", "warmup", "steady"):
            ph = summary["phases"].get(name, {})
            lost = ph.get("dropped_by_channel") or ph.get("dropped_by_category") or ph.get("kernel_loss")
            if lost:
                errors.append(f"events were lost during {name} (normal load): channels={ph.get('dropped_by_channel')} "
                              f"categories={ph.get('dropped_by_category')} kernel={ph.get('kernel_loss')}")
        steady = summary.get("canaries", {}).get("steady", {})
        for kind, b in steady.items():
            if b["detected_percent"] is not None and b["detected_percent"] < 100:
                errors.append(f"steady-state canary {kind} detected {b['detected_percent']}% ({b['detected']}/{b['sent']})")
        first_loss = None
        for name, ph in summary["phases"].items():
            if name.startswith("ramp") and (ph.get("dropped_by_channel") or ph.get("dropped_by_category") or ph.get("kernel_loss")):
                first_loss = name
                break
        summary["headroom"] = {
            "first_phase_with_loss": first_loss,
            "note": "Highest ramp phase without any dropped or kernel-lost event is the last one before this.",
        }
    summary["valid"] = not errors
    summary["validation_errors"] = errors
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print_report(summary)
    log(f"summary: {run_dir / 'summary.json'}")
    return 0 if not errors else 1


def print_report(s: dict):
    print()
    print(f"== {s['platform']} {s['mode']}" + (f" agent {s['agent']['version']}" if "agent" in s else ""))
    if "rule_inventory" in s:
        ri = s["rule_inventory"]
        print(f"   rules: {ri['sigma_files']} sigma, {ri['yara_files']} yara, ioc {ri['ioc_lines']}")
    hdr = f"{'phase':<12}{'cpu avg':>9}{'cpu p95':>9}{'rss max':>9}{'ev/s':>8}{'lost':>9}{'proc p95':>10}{'file p95':>10}"
    print(hdr)
    for name, ph in s["phases"].items():
        ag = ph.get("agent", {})
        lost = sum((ph.get("dropped_by_channel") or {}).values()) + sum((ph.get("kernel_loss") or {}).values())
        wl = ph.get("workload", {})
        def f(v, w, suffix=""):
            return f"{'-' if v is None else v}{suffix}".rjust(w)
        print(f"{name:<12}{f(ag.get('cpu_avg_percent'), 9)}{f(ag.get('cpu_p95_percent'), 9)}{f(ag.get('rss_max_mb'), 9)}"
              f"{f(ph.get('events', {}).get('sensor_events_per_s'), 8)}{f(lost if ag else None, 9)}"
              f"{f(wl.get('proc', {}).get('latency_p95_ms'), 10)}{f(wl.get('file', {}).get('latency_p95_ms'), 10)}")
    if "canaries" in s:
        print("canaries (all phases): " + ", ".join(
            f"{k} {v['detected']}/{v['sent']} p95 {v['latency_p95_s']}s" for k, v in s["canaries"].get("all", {}).items()))
    print("valid:", s["valid"], *s["validation_errors"], sep="\n  " if s["validation_errors"] else " ")


def compare(paths: list[str]) -> int:
    runs = [json.loads(Path(p).read_text()) for p in paths]
    labels = [(r_.get("agent", {}).get("version") or r_["mode"]) for r_ in runs]
    print(f"{'metric':<34}" + "".join(f"{l:>16}" for l in labels))

    def row(name, getter):
        vals = []
        for run_ in runs:
            try:
                v = getter(run_)
            except Exception:
                v = None
            vals.append("-" if v is None else str(v))
        print(f"{name:<34}" + "".join(f"{v:>16}" for v in vals))

    row("valid", lambda x: x["valid"])
    row("startup seconds", lambda x: x["agent"]["startup_seconds"])
    for phase in runs[0]["phases"]:
        if phase == "warmup":
            continue
        row(f"{phase} cpu avg %", lambda x, p=phase: x["phases"][p]["agent"]["cpu_avg_percent"])
        row(f"{phase} rss max MB", lambda x, p=phase: x["phases"][p]["agent"]["rss_max_mb"])
        if phase != "idle":
            row(f"{phase} events/s", lambda x, p=phase: x["phases"][p]["events"]["sensor_events_per_s"])
            row(f"{phase} lost events", lambda x, p=phase: sum((x["phases"][p].get("dropped_by_channel") or {}).values())
                + sum((x["phases"][p].get("kernel_loss") or {}).values()))
            row(f"{phase} proc p95 ms", lambda x, p=phase: x["phases"][p]["workload"]["proc"]["latency_p95_ms"])
            row(f"{phase} file p95 ms", lambda x, p=phase: x["phases"][p]["workload"]["file"]["latency_p95_ms"])
    for kind in ("sigma_process", "sigma_file", "yara_file", "ioc_ip", "ioc_domain"):
        row(f"canary {kind} detected %", lambda x, k=kind: x["canaries"]["all"][k]["detected_percent"])
        row(f"canary {kind} p95 s", lambda x, k=kind: x["canaries"]["all"][k]["latency_p95_s"])
    row("first phase with loss", lambda x: x["headroom"]["first_phase_with_loss"])
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "compare":
        return compare(sys.argv[2:])
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["with-agent", "baseline"], default="with-agent")
    p.add_argument("--agent", default="./rustinel" if not IS_WINDOWS else r".\rustinel.exe", help="Path to the rustinel binary.")
    p.add_argument("--corpus", default="rules-bench", help="Directory with sigma/, yara/, ioc/ (scripts/rules/fetch_corpus.py).")
    p.add_argument("--output-dir", default="target/rustinel-bench-realistic")
    p.add_argument("--idle-secs", type=int, default=60)
    p.add_argument("--warmup-secs", type=int, default=30)
    p.add_argument("--steady-secs", type=int, default=300)
    p.add_argument("--ramp", type=float, nargs="*", default=[2, 4, 8, 16], help="Rate multipliers for the stress steps.")
    p.add_argument("--ramp-step-secs", type=int, default=45)
    p.add_argument("--skip-ramp", action="store_true")
    p.add_argument("--canary-interval", type=float, default=10.0)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--no-dns", dest="dns", action="store_false", help="Do not send DNS queries to the real resolver.")
    p.add_argument("--skip-drain", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
