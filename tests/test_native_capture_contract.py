#!/usr/bin/env python3
"""Regression tests for native capture fixtures and path assertions."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "native_capture_contract", Path(__file__).with_name("native_capture_contract.py")
)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


@unittest.skipUnless(os.name == "posix", "requires POSIX symlinks and process paths")
class LinuxContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.image = self.root / "sleep"
        self.image.touch()
        self.cwd = self.root / "relative"
        self.cwd.mkdir()
        (self.cwd / "sleep").symlink_to(self.image)
        self.expected = {
            "absolute": (101, self.image, self.root),
            "relative": (102, self.image, self.cwd),
            "fork": (103, 104, Path(contract.sys.executable).resolve()),
        }
        self.events = [
            self.event(101, Image=str(self.image), CurrentDirectory=str(self.root)),
            self.event(102, Image="./sleep", CurrentDirectory=str(self.cwd)),
            self.event(103, ParentProcessId="104", ParentImage=str(self.expected["fork"][2])),
        ]

    @staticmethod
    def event(pid, **fields):
        return {"category": "Process", "fields": {"ProcessId": str(pid), **fields}}

    def test_relative_image_resolves_from_child_directory(self):
        contract.assert_linux(self.events, self.expected)

    def test_enriched_absolute_image_is_also_valid(self):
        self.events[1]["fields"]["Image"] = str(self.image)
        contract.assert_linux(self.events, self.expected)

    def test_wrong_image_is_rejected(self):
        other = self.cwd / "other"
        other.touch()
        self.events[1]["fields"]["Image"] = "./other"
        with self.assertRaises(AssertionError):
            contract.assert_linux(self.events, self.expected)

    def test_wrong_directory_is_rejected(self):
        self.events[1]["fields"]["CurrentDirectory"] = str(self.root)
        with self.assertRaises(AssertionError):
            contract.assert_linux(self.events, self.expected)

    def test_fixture_preserves_multicall_utility_name_and_symlink(self):
        multicall = self.root / "multicall"
        multicall.write_text(
            '#!/bin/sh\ncase "$0" in */sleep) exit 0;; *) exit 64;; esac\n',
            encoding="utf-8",
        )
        multicall.chmod(0o755)
        self.image.unlink()
        self.image.symlink_to(multicall)
        fixture_root = self.root / "fixture"
        fixture_root.mkdir()
        expected = {}
        with mock.patch.object(contract.shutil, "which", return_value=str(self.image)):
            contract.run_linux_cases(expected, fixture_root)
        self.assertEqual(expected["absolute"][1], multicall)
        self.assertEqual(expected["relative"][1], multicall)
        self.assertEqual((fixture_root / "relative" / "sleep").resolve(strict=True), multicall)


if __name__ == "__main__":
    unittest.main()
