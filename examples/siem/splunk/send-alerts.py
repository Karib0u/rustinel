#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def post_event(url: str, token: str, event: dict) -> None:
    payload = {
        "source": "rustinel",
        "sourcetype": "_json",
        "index": "main",
        "event": event,
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status >= 300:
            raise RuntimeError(f"HEC returned HTTP {response.status}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send Rustinel ECS NDJSON alerts to Splunk HEC."
    )
    parser.add_argument("alert_file", help="Path to logs/alerts.json.<date>")
    parser.add_argument(
        "--url",
        default=os.environ.get(
            "SPLUNK_HEC_URL", "http://localhost:8088/services/collector/event"
        ),
        help="Splunk HEC event endpoint",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SPLUNK_HEC_TOKEN", "rustinel-demo-token"),
        help="Splunk HEC token",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Keep reading new lines after sending the current file contents",
    )
    args = parser.parse_args()

    sent = 0
    with open(args.alert_file, "r", encoding="utf-8") as handle:
        while True:
            line = handle.readline()
            if not line:
                if not args.follow:
                    break
                time.sleep(0.5)
                continue

            stripped = line.strip()
            if not stripped:
                continue

            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                print(f"Skipping invalid JSON line: {exc}", file=sys.stderr)
                continue

            try:
                post_event(args.url, args.token, event)
            except (urllib.error.URLError, RuntimeError) as exc:
                print(f"Failed to send event: {exc}", file=sys.stderr)
                return 1

            sent += 1

    print(f"Sent {sent} Rustinel alert event(s) to Splunk HEC.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
