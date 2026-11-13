#!/usr/bin/env python3
"""Audit both lockfiles using the advisory exceptions in their deny.toml files."""

from pathlib import Path
import shlex
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    failed = False
    for directory in (ROOT, ROOT / "ebpf"):
        with (directory / "deny.toml").open("rb") as source:
            policy = tomllib.load(source)

        command = ["cargo", "audit", "--file", "Cargo.lock", "--deny", "warnings"]
        for exception in policy.get("advisories", {}).get("ignore", []):
            advisory_id = exception if isinstance(exception, str) else exception["id"]
            command.extend(["--ignore", advisory_id])

        print(f"Auditing {directory.relative_to(ROOT) / 'Cargo.lock'}", flush=True)
        print(shlex.join(command), flush=True)
        result = subprocess.run(command, cwd=directory, check=False)
        failed |= result.returncode != 0

    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
