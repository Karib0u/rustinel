#!/usr/bin/env python3
"""Regression tests for the degradation detection in ebpf_load_smoke.py."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


def load_smoke():
    path = Path(__file__).with_name("ebpf_load_smoke.py")
    spec = importlib.util.spec_from_file_location("ebpf_load_smoke", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = load_smoke()
TS = "2026-10-14T14:22:35.030912Z"

HEALTHY = f"""\
{TS}  INFO rustinel::sensor::linux::ebpf: loading eBPF object from embedded bytes
{TS}  INFO rustinel::sensor::linux::ebpf: eBPF tracepoints attached
"""

DNS_READ_BROKEN = (
    f'{TS}  WARN rustinel::sensor::linux::ebpf: eBPF hook failed to attach '
    'program="handle_dns_read" reason=attach ksys_read: the BPF_PROG_LOAD syscall failed\n'
)


class DegradationTests(unittest.TestCase):
    def test_healthy_log_has_no_degradation(self):
        self.assertEqual(smoke.find_degradations(HEALTHY), set())

    def test_each_documented_warning_is_detected(self):
        lines = {
            f'{TS}  WARN x: eBPF hook failed to attach program="handle_dns_write" reason=r': "eBPF hook failed to attach|handle_dns_write",
            f'{TS}  WARN x: eBPF hook is unavailable program="handle_open" category="syscalls" name="sys_enter_openat"': "eBPF hook is unavailable|handle_open",
            f'{TS}  WARN x: eBPF hook may miss syscalls on some CPUs program="handle_connect" reason=r': "eBPF hook may miss syscalls on some CPUs|handle_connect",
            f"{TS}  WARN x: kernel socket tuple unavailable; using connect syscalls reason=r": "kernel socket tuple unavailable|",
            f"{TS}  WARN x: kernel file identity unavailable; file events remain enabled reason=r": "kernel file identity unavailable|",
            f"{TS}  WARN x: DNS over read/write is not captured reason=r": "DNS over read/write is not captured|",
            f"{TS}  WARN x: kernel process identity field disabled diagnostic=task.cred reason=r": "kernel process identity field disabled|task.cred",
        }
        for line, expected in lines.items():
            with self.subTest(expected=expected):
                self.assertEqual(smoke.find_degradations(line + "\n"), {expected})

    def test_broken_hook_among_healthy_lines(self):
        found = smoke.find_degradations(HEALTHY + DNS_READ_BROKEN)
        self.assertEqual(found, {"eBPF hook failed to attach|handle_dns_read"})

    def test_unexpected_degradation_fails_assertion(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            with self.assertRaisesRegex(
                AssertionError, "unexpected degraded eBPF hooks"
            ):
                smoke.assert_degradations(HEALTHY + DNS_READ_BROKEN, set(), run_dir)
            self.assertIn(
                "handle_dns_read", (run_dir / "degradations.txt").read_text()
            )

    def test_expected_degradation_passes_and_new_one_fails(self):
        expected = {"eBPF hook failed to attach|handle_dns_read"}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            smoke.assert_degradations(DNS_READ_BROKEN, expected, run_dir)
            other = DNS_READ_BROKEN.replace("handle_dns_read", "handle_dns_write")
            with self.assertRaises(AssertionError):
                smoke.assert_degradations(DNS_READ_BROKEN + other, expected, run_dir)

    def test_expected_file_ignores_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "expected.txt"
            path.write_text("# note\n\nDNS over read/write is not captured|\n")
            self.assertEqual(
                smoke.read_expected_degradations(path),
                {"DNS over read/write is not captured|"},
            )
            self.assertEqual(smoke.read_expected_degradations(None), set())


if __name__ == "__main__":
    unittest.main()
