#!/usr/bin/env python3
"""
Build a Rustinel benchmark rule corpus from public community sources.

The script intentionally uses only the Python standard library so it can run on
Windows and Linux without a virtualenv.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


SIGMA_ZIP_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
YARA_FORGE_RELEASE_API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
FEODO_RECOMMENDED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
FEODO_30D_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT_CSV_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"

USER_AGENT = "rustinel-bench-corpus/1.0"


def log(message: str) -> None:
    print(message, flush=True)


def request(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None) -> bytes:
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"HTTP {err.code} while fetching {url}: {body}") from err
    except urllib.error.URLError as err:
        raise RuntimeError(f"Failed to fetch {url}: {err}") from err


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def append_unique(path: Path, values: set[str], header: str) -> None:
    lines = [header]
    for value in sorted(values):
        lines.append(value)
    write_text(path, "\n".join(lines) + "\n")


def clean_output_dir(output: Path, force: bool) -> None:
    if output.exists():
        if not force:
            raise SystemExit(f"{output} already exists. Pass --force to replace it.")
        shutil.rmtree(output)
    (output / "sigma").mkdir(parents=True)
    (output / "yara").mkdir(parents=True)
    (output / "ioc").mkdir(parents=True)
    (output / "sources").mkdir(parents=True)


def is_sigma_candidate(member_name: str) -> bool:
    parts = member_name.split("/")
    if len(parts) < 3:
        return False
    top_level = parts[1]
    filename = parts[-1].lower()
    if not filename.endswith((".yml", ".yaml")):
        return False
    if top_level in {"deprecated", "unsupported", "tests", "documentation"}:
        return False
    return top_level == "rules" or top_level.startswith("rules-")


def fetch_sigma(output: Path, metadata: dict[str, object]) -> int:
    log("Fetching SigmaHQ community rules...")
    data = request(SIGMA_ZIP_URL)
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir() or not is_sigma_candidate(info.filename):
                continue
            parts = info.filename.split("/")
            relative = Path(*parts[1:])
            target = output / "sigma" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info))
            count += 1
    metadata["sigma"] = {
        "source": SIGMA_ZIP_URL,
        "files": count,
        "included": "rules* directories, excluding deprecated/unsupported/tests/documentation",
    }
    log(f"Sigma files: {count}")
    return count


def latest_yara_forge_asset(ruleset: str) -> tuple[str, str, str]:
    release = json.loads(request(YARA_FORGE_RELEASE_API).decode("utf-8"))
    assets = release.get("assets", [])
    candidates = []
    for asset in assets:
        name = str(asset.get("name", ""))
        download = asset.get("browser_download_url")
        lower = name.lower()
        if download and lower.endswith(".zip") and ruleset.lower() in lower:
            candidates.append((name, download))
    if not candidates:
        asset_names = ", ".join(str(asset.get("name", "")) for asset in assets)
        raise RuntimeError(
            f"Could not find a YARA Forge {ruleset!r} zip asset in latest release. Assets: {asset_names}"
        )
    name, download = sorted(candidates, key=lambda item: len(item[0]))[0]
    return str(release.get("tag_name", "")), name, str(download)


def fetch_yara_forge(output: Path, ruleset: str, metadata: dict[str, object]) -> int:
    log(f"Fetching YARA Forge {ruleset} rules...")
    tag, asset_name, url = latest_yara_forge_asset(ruleset)
    data = request(url)
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith((".yar", ".yara")):
                continue
            # Rustinel's YARA loader currently reads only the top-level rules
            # directory, so flatten package files into unique filenames.
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", info.filename).strip("_")
            target = output / "yara" / safe_name
            target.write_bytes(zf.read(info))
            count += 1
    metadata["yara_forge"] = {
        "source": YARA_FORGE_RELEASE_API,
        "release": tag,
        "asset": asset_name,
        "ruleset": ruleset,
        "files": count,
    }
    log(f"YARA files: {count}")
    return count


def parse_feodo_ips(text: str, source_name: str) -> set[str]:
    ips = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.upper() == "END":
            continue
        token = line.split()[0].strip()
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        ips.add(f"{token};{source_name}")
    return ips


def fetch_feodo(output: Path, mode: str, metadata: dict[str, object]) -> set[str]:
    if mode == "off":
        metadata["feodo"] = {"enabled": False}
        return set()
    url = FEODO_RECOMMENDED_URL if mode == "recommended" else FEODO_30D_URL
    log(f"Fetching Feodo Tracker IP IOCs ({mode})...")
    ips = parse_feodo_ips(request(url).decode("utf-8", "replace"), f"feodo:{mode}")
    metadata["feodo"] = {"source": url, "mode": mode, "ips": len(ips)}
    log(f"Feodo IP IOCs: {len(ips)}")
    return ips


def clean_domain(value: str) -> str | None:
    value = value.strip().lower().strip(".")
    if not value or "/" in value or " " in value:
        return None
    if "." not in value:
        return None
    return value


def clean_hash(value: str) -> str | None:
    value = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value):
        return value
    return None


def parse_ioc_value(ioc: str, ioc_type: str, comment: str) -> tuple[str, str] | None:
    ioc = ioc.strip()
    ioc_type = ioc_type.lower()
    if ioc_type in {"ip:port", "ipv4:port", "ipv6:port"}:
        ioc = ioc.rsplit(":", 1)[0]
        ioc_type = "ip"
    if ioc_type in {"ip", "ipv4", "ipv6"}:
        try:
            return "ip", f"{ipaddress.ip_address(ioc)};{comment}"
        except ValueError:
            return None
    if ioc_type in {"domain", "hostname"}:
        domain = clean_domain(ioc)
        return ("domain", f"{domain};{comment}") if domain else None
    if ioc_type in {"url"}:
        host = urllib.parse.urlparse(ioc).hostname
        domain = clean_domain(host or "")
        return ("domain", f"{domain};{comment}") if domain else None
    if ioc_type in {"md5_hash", "sha1_hash", "sha256_hash", "hash"}:
        digest = clean_hash(ioc)
        return ("hash", f"{digest};{comment}") if digest else None
    return None


def fetch_threatfox(
    auth_key: str | None,
    days: int,
    min_confidence: int,
    metadata: dict[str, object],
) -> tuple[set[str], set[str], set[str]]:
    if not auth_key:
        metadata["threatfox"] = {"enabled": False, "reason": "missing auth key"}
        return set(), set(), set()
    log(f"Fetching ThreatFox recent IOCs ({days} days, confidence >= {min_confidence})...")
    payload = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    body = request(
        THREATFOX_API_URL,
        data=payload,
        headers={"Auth-Key": auth_key, "Content-Type": "application/json"},
    )
    parsed = json.loads(body.decode("utf-8"))
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    for item in parsed.get("data", []) or []:
        confidence = int(item.get("confidence_level") or 0)
        if confidence < min_confidence:
            continue
        malware = str(item.get("malware_printable") or item.get("malware") or "unknown")
        comment = f"threatfox:{malware}:confidence={confidence}"
        converted = parse_ioc_value(str(item.get("ioc", "")), str(item.get("ioc_type", "")), comment)
        if converted is None:
            continue
        kind, value = converted
        if kind == "ip":
            ips.add(value)
        elif kind == "domain":
            domains.add(value)
        elif kind == "hash":
            hashes.add(value)
    metadata["threatfox"] = {
        "source": THREATFOX_API_URL,
        "days": days,
        "min_confidence": min_confidence,
        "ips": len(ips),
        "domains": len(domains),
        "hashes": len(hashes),
    }
    log(f"ThreatFox IOCs: {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes")
    return ips, domains, hashes


def maybe_unzip(data: bytes) -> bytes:
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [name for name in zf.namelist() if not name.endswith("/")]
            if not names:
                return b""
            return zf.read(names[0])
    return data


def fetch_urlhaus(auth_key: str | None, metadata: dict[str, object]) -> set[str]:
    if not auth_key:
        metadata["urlhaus"] = {"enabled": False, "reason": "missing auth key"}
        return set()
    log("Fetching URLhaus recent URL dataset...")
    url = URLHAUS_RECENT_CSV_URL.format(auth_key=urllib.parse.quote(auth_key, safe=""))
    data = maybe_unzip(request(url))
    text = data.decode("utf-8", "replace")
    domains: set[str] = set()
    reader = csv.DictReader(line for line in text.splitlines() if not line.startswith("#"))
    for row in reader:
        raw_url = row.get("url") or row.get("URL") or row.get("urlhaus_reference") or ""
        host = urllib.parse.urlparse(raw_url).hostname
        domain = clean_domain(host or "")
        if domain:
            domains.add(f"{domain};urlhaus:recent")
    metadata["urlhaus"] = {"source": URLHAUS_RECENT_CSV_URL.replace(auth_key, "<auth-key>"), "domains": len(domains)}
    log(f"URLhaus domains: {len(domains)}")
    return domains


def count_files(path: Path, suffixes: tuple[str, ...]) -> int:
    return sum(1 for child in path.rglob("*") if child.is_file() and child.name.lower().endswith(suffixes))


def write_empty_ioc_files(output: Path) -> None:
    headers = {
        "hashes.txt": "# IOC Type: Hashes\n# Format: VALUE;COMMENT\n",
        "ips.txt": "# IOC Type: IPs\n# Format: VALUE;COMMENT\n",
        "domains.txt": "# IOC Type: Domains\n# Format: VALUE;COMMENT\n",
        "paths_regex.txt": "# IOC Type: Path Regex\n# Format: VALUE;COMMENT\n",
    }
    for name, header in headers.items():
        path = output / "ioc" / name
        if not path.exists():
            write_text(path, header)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch community rules for Rustinel benchmark corpora.")
    parser.add_argument("--output", default="rules-bench", help="Output corpus directory.")
    parser.add_argument("--force", action="store_true", help="Replace the output directory if it already exists.")
    parser.add_argument("--skip-sigma", action="store_true", help="Do not fetch SigmaHQ rules.")
    parser.add_argument("--skip-yara-forge", action="store_true", help="Do not fetch YARA Forge.")
    parser.add_argument("--yara-forge-set", choices=["core", "extended", "full"], default="core")
    parser.add_argument("--feodo", choices=["off", "recommended", "30d"], default="recommended")
    parser.add_argument("--threatfox-auth-key", default=os.getenv("THREATFOX_AUTH_KEY"))
    parser.add_argument("--threatfox-days", type=int, default=7)
    parser.add_argument("--threatfox-min-confidence", type=int, default=70)
    parser.add_argument("--urlhaus-auth-key", default=os.getenv("URLHAUS_AUTH_KEY"))
    parser.add_argument("--include-urlhaus", action="store_true", help="Fetch URLhaus recent URLs and extract domains.")
    args = parser.parse_args()

    if not 1 <= args.threatfox_days <= 7:
        raise SystemExit("--threatfox-days must be between 1 and 7")
    if not 0 <= args.threatfox_min_confidence <= 100:
        raise SystemExit("--threatfox-min-confidence must be between 0 and 100")

    output = Path(args.output)
    clean_output_dir(output, args.force)

    metadata: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "output": str(output),
    }

    if not args.skip_sigma:
        fetch_sigma(output, metadata)
    else:
        metadata["sigma"] = {"enabled": False}

    if not args.skip_yara_forge:
        fetch_yara_forge(output, args.yara_forge_set, metadata)
    else:
        metadata["yara_forge"] = {"enabled": False}

    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()

    ips |= fetch_feodo(output, args.feodo, metadata)
    threatfox_ips, threatfox_domains, threatfox_hashes = fetch_threatfox(
        args.threatfox_auth_key,
        args.threatfox_days,
        args.threatfox_min_confidence,
        metadata,
    )
    ips |= threatfox_ips
    domains |= threatfox_domains
    hashes |= threatfox_hashes

    if args.include_urlhaus:
        domains |= fetch_urlhaus(args.urlhaus_auth_key, metadata)
    else:
        metadata["urlhaus"] = {"enabled": False}

    append_unique(output / "ioc" / "ips.txt", ips, "# IOC Type: IPs\n# Format: VALUE;COMMENT")
    append_unique(output / "ioc" / "domains.txt", domains, "# IOC Type: Domains\n# Format: VALUE;COMMENT")
    append_unique(output / "ioc" / "hashes.txt", hashes, "# IOC Type: Hashes\n# Format: VALUE;COMMENT")
    write_empty_ioc_files(output)

    summary = {
        "sigma_files": count_files(output / "sigma", (".yml", ".yaml")),
        "yara_files": count_files(output / "yara", (".yar", ".yara")),
        "ioc_ips": len(ips),
        "ioc_domains": len(domains),
        "ioc_hashes": len(hashes),
    }
    metadata["summary"] = summary
    write_text(output / "sources" / "metadata.json", json.dumps(metadata, indent=2, sort_keys=True) + "\n")

    log("")
    log("Corpus ready:")
    log(f"  Sigma files: {summary['sigma_files']}")
    log(f"  YARA files:  {summary['yara_files']}")
    log(f"  IOC IPs:     {summary['ioc_ips']}")
    log(f"  IOC domains: {summary['ioc_domains']}")
    log(f"  IOC hashes:  {summary['ioc_hashes']}")
    log(f"  Output:      {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
