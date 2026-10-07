#!/usr/bin/env python3
"""Release-package check for the portable first run.

Usage: portable_package_ownership.py PACKAGE.tar.gz [--run]

Always asserts the archive ships no pre-created output directory, because an
existing directory owned by the installing user is rejected once the runtime
starts as root.
With --run, extracts the package as the invoking user, starts the documented
elevated `sudo ./rustinel run`, and asserts the runtime created `logs`
itself (owned by root, mode 0700) so no manual ownership repair is needed.
"""
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import time


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    package = pathlib.Path(args[0])

    with tarfile.open(package) as archive:
        shipped = [m.name for m in archive.getmembers() if "/logs" in "/" + m.name]
    if shipped:
        print(f"package ships an output directory: {shipped}", file=sys.stderr)
        return 1
    print("package ships no logs directory")

    if "--run" not in sys.argv:
        return 0
    if os.geteuid() == 0:
        print("--run must start as an ordinary user", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(package) as archive:
            archive.extractall(tmp)
        root = next(pathlib.Path(tmp).iterdir())
        proc = subprocess.Popen(["sudo", "./rustinel", "run"], cwd=root)
        deadline = time.time() + 30
        logs = root / "logs"
        while time.time() < deadline and not logs.exists() and proc.poll() is None:
            time.sleep(0.5)
        time.sleep(2)
        subprocess.run(["sudo", "pkill", "-INT", "-f", str(root / "rustinel")], check=False)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "pkill", "-KILL", "-f", str(root / "rustinel")], check=False)
        # logs is root 0700, so inspect it through sudo.
        listing = subprocess.run(
            ["sudo", "stat", "-c", "%u %a", str(logs)], capture_output=True, text=True
        )
        if listing.returncode != 0 or listing.stdout.split() != ["0", "700"]:
            print(f"logs was not created as root 0700: {listing.stdout}{listing.stderr}", file=sys.stderr)
            return 1
        print("elevated first run created logs/ with the right ownership")
        subprocess.run(["sudo", "rm", "-rf", str(root)], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
