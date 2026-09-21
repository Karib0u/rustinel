# Alert and recording format

| Output | Default location | Written by |
| --- | --- | --- |
| Alerts (ECS NDJSON) | `logs/alerts.json.<date>` | `run` |
| Alerts (HTTP POST) | each configured [webhook](#webhooks) | `run` |
| Operational log | `logs/rustinel.log.<date>` | every command |
| Recordings | `captures/rustinel-capture-<timestamp>.ndjson` | `capture` |
| Replay results | console, or `--output` | `replay` |

On Linux and macOS these files are readable by their owner only.

## Alerts

One JSON object per line, following ECS 9.5.0.

```json
{
  "@timestamp": "2026-08-16T21:00:05Z",
  "ecs.version": "9.5.0",
  "event.kind": "alert",
  "event.category": ["process"],
  "event.type": ["start"],
  "event.action": "process-start",
  "event.code": "1",
  "event.module": "edr",
  "event.dataset": "edr.process",
  "event.provider": "ebpf",
  "rule.name": "Example - Whoami Execution (Linux)",
  "rule.id": "sigma::d3b073c6-e265-4f40-a1c1-42e8f17a9c67",
  "edr.rule.severity": "Low",
  "edr.rule.engine": "Sigma",
  "host.os.type": "linux",
  "process.executable": "/usr/bin/whoami",
  "process.name": "whoami",
  "user.name": "root"
}
```

### Common fields

| Field | Value |
| --- | --- |
| `@timestamp` | Event time, UTC |
| `event.kind` | Always `alert` |
| `event.code` | Sysmon-style or native event ID |
| `event.dataset` | `edr.<family>`, see below |
| `event.provider` | The originating Rustinel sensor: `etw`, `windows_event_log`, `ebpf`, `esf`, or `bpf` |
| `event.sequence` | Native sequence number, when the source has one |
| `event.count` | Rollup alerts only: repeats suppressed by [deduplication](detection.md#deduplication) |
| `rule.name` | Rule title |
| `rule.id` | `sigma::<id>`, `yara::<id>`, or `ioc::<type>::<value>` |
| `edr.rule.severity` | `Informational`, `Low`, `Medium`, `High`, or `Critical` |
| `edr.rule.engine` | `Sigma`, `Yara`, or `Ioc` |
| `edr.yara.scan_source` | YARA alerts only: `file` or `process_memory` |
| `edr.event.ingest_seq` | Order in which Rustinel processed the event |
| `edr.event.provenance` | Populated fields with fidelity limitations, see below |
| `edr.match` | Why the rule matched, when `alerts.match_debug` is on |

Sigma alerts can also carry bounded rule metadata and ECS ATT&CK fields; see [Sigma metadata in alerts](detection.md#sigma-metadata-in-alerts).

### Field provenance

`edr.event.provenance` lists `{ "field": "Image", "fidelity": "derived" }` entries using the recorded field names.
It is omitted when no populated event field has a known fidelity limitation.
A missing value stays absent; provenance never supplies a value or turns unknown into `false`.

| Fidelity | Meaning |
| --- | --- |
| `derived` | Reconstructed from a process cache, account lookup, filesystem, or `/proc` |
| `best_effort` | Inferred, for example a connection event inferred from a captured SYN |
| `truncated` | Incomplete because a capture limit cut the value |
| `stale` | Retained evidence whose freshness is limited |

A field can have multiple entries, such as a truncated image copied from the process cache.
YARA and hash IOC alerts keep the entries for the image and PID of the process start that queued the scan.
A dedup rollup keeps every entry seen on a suppressed repeat, for fields the rollup reports.
Recordings retain these entries; Sigma matching does not expose them as fields or keywords.
`ImageSource`, `ImageTruncated`, and `PathTruncated` remain available to Sigma with their existing values.
A Linux short process name is carried as `process.name`, separately from `process.executable`, and does not fill a missing executable path.

### ECS version policy

Rustinel targets ECS 9.5.0.
The target advances only after every ECS field Rustinel emits has been checked against that release's schema and release notes.
A weekly CI check reports when the latest stable ECS release differs from the target.

`host.tags` is not emitted.
ECS defines it as operator-configured host metadata, and Rustinel has no host metadata or tag configuration.
Adding that product behavior is separate from tracking the schema version.

### Event families

| Dataset | Events |
| --- | --- |
| `edr.process` | Process start and exit |
| `edr.network` | Network connections |
| `edr.file` | File activity |
| `edr.dns` | DNS queries |
| `edr.registry` | Registry (Windows) |
| `edr.library` | Image load (Windows) |
| `edr.scripting` | PowerShell script blocks (Windows) |
| `edr.powershell_module` | PowerShell module logging (Windows) |
| `edr.powershell_classic_start` | Classic Windows PowerShell engine starts |
| `edr.wmi` | WMI activity (Windows) |
| `edr.service` | Service installs (Windows) |
| `edr.task` | Scheduled tasks (Windows) |
| `edr.security` | Security audit events (Windows) |

### Platform-specific fields

| Field | Platform | Value |
| --- | --- | --- |
| `edr.event_log.provider_name` | Windows | The provider that wrote an Event Log record. Sigma sees it as `Provider_Name` |
| `edr.powershell.data` | Windows | Raw classic Windows PowerShell event 400 engine-start description. Sigma sees it as `Data` |
| `edr.security` | Windows | The full decoded Security event, with Windows field names. Identity, address, process, and service values are also copied to ECS fields |
| `edr.process.windows_metadata` | Windows | Where the command line came from, the raw SID, and the session ID |
| `edr.process.image_source` | Linux | `execve`: the path as passed to `execve()` |
| `edr.process.image_truncated` | Linux | `true` when the executable path was cut |
| `edr.file.path_truncated` | Linux | Which side of a file path was cut |
| `edr.process.real_user_id`, `edr.process.real_group_id` | Linux | Real credentials |
| `edr.process.effective_user_id`, `edr.process.effective_group_id` | Linux | Effective credentials. `user.name` resolves the effective UID |
| `edr.process.cgroup_id` | Linux | Kernel cgroup ID at exec |
| `edr.process.cgroup_path` | Linux | Cgroup v2 path of `edr.process.cgroup_id`. Present without `container.id` on a host process |
| `container.id`, `container.runtime` | Linux | Container named by the process cgroup. The runtime is `docker`, `containerd`, `cri-o`, `podman`, or `lxc`, and is absent when the cgroup layout does not name one |
| `edr.process.mount_namespace`, `edr.process.pid_namespace`, `edr.process.network_namespace` | Linux | Namespace inode numbers |
| `edr.process.session_id`, `edr.process.controlling_tty` | Linux | Session ID and terminal as `major:minor` |
| `edr.process.kernel_start_boottime` | Linux | Process start time in nanoseconds since boot |

## Webhooks

Each [`[[alerts.webhook]]`](configuration.md#webhook-destinations) destination receives every alert written to the alert file, as one `POST` per alert.
The body is the same ECS JSON object as the file line, without the trailing newline.
The file is written first and does not depend on delivery: a slow, failing, or unreachable endpoint never delays or removes an alert from it.

| Header | Value |
| --- | --- |
| `Content-Type` | `application/json` |
| `User-Agent` | `rustinel/<version>` |
| `X-Rustinel-Delivery` | ID of this alert, the same on every retry and every destination |
| `X-Rustinel-Timestamp` | Unix time in seconds, when `secret` is set |
| `X-Rustinel-Signature` | `sha256=` and the hex HMAC-SHA256 of `<timestamp>.<body>` keyed with `secret`, when `secret` is set |

Configured `headers` are added to every request.
Configuration syntax errors report the file without source excerpts, and invalid values are omitted from type errors, so diagnostics cannot expose credentials.

### Delivery

- A `2xx` response is a delivery.
- Connection errors, timeouts, `408`, `425`, `429`, and `5xx` are retried.
  The delay starts at `retry_initial_ms`, doubles each time up to `retry_max_ms`, and is randomized within its upper half.
  A `Retry-After` in seconds raises the delay, up to `retry_max_ms`.
- Any other response, including redirects, is not retried.
- After `max_attempts` attempts the alert is given up for that destination.
- Each destination delivers one alert at a time, in order, from its own queue.
  When the queue is full, new alerts are dropped for that destination only.
- An alert larger than `max_payload_bytes` is not sent to that destination.
- At shutdown, queued alerts get 5 seconds to be delivered; the rest are counted as abandoned.

Delivery is at least once: a request that times out after the receiver processed it is sent again.
Discard repeats with `X-Rustinel-Delivery`.

Every outcome is counted in [`telemetry.json`](telemetry.md#alert_webhooks), and `rustinel doctor` warns under `alert_webhooks` when alerts went undelivered.
Failures are logged at most once a minute per destination, naming the destination by its `name` and host only.
The URL path, header values, and `secret` never appear in logs, telemetry, or doctor output.

### Deduplication

Webhooks receive exactly what the file receives.
With [deduplication](detection.md#deduplication) on, that is the first alert when it fires and, if it repeated, one rollup with `event.count` when the window closes.

### Receiver example

A receiver that checks the signature, in Python with only the standard library:

```python
import hashlib, hmac, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = b"change-me"

class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        timestamp = self.headers.get("X-Rustinel-Timestamp", "0")
        expected = "sha256=" + hmac.new(SECRET, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
        fresh = abs(time.time() - int(timestamp)) < 300
        if not (fresh and hmac.compare_digest(expected, self.headers.get("X-Rustinel-Signature", ""))):
            self.send_response(401)
            self.end_headers()
            return
        alert = json.loads(body)
        print(alert["rule.name"], alert.get("process.executable"))
        self.send_response(204)
        self.end_headers()

HTTPServer(("0.0.0.0", 8080), Receiver).serve_forever()
```

With this configuration:

```toml
[[alerts.webhook]]
url = "http://receiver.example:8080/"
secret = "change-me"
```

Use `https` for anything but a lab: over `http` the headers and the alert travel in clear text.

## Recordings

`rustinel capture` writes two files:

| File | Content |
| --- | --- |
| `<name>.ndjson` | One normalized event per line, in processing order |
| `<name>.manifest.json` | What the recording contains and whether it is complete |

```json
{"event_time":"2026-08-16T09:12:44.123456789Z","ingest_seq":42,"platform":"windows","provider":"etw","category":"Process","event_id":1,"opcode":1,"fields":{"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -EncodedCommand ...","ProcessId":"6132"}}
```

Events are recorded before any rule runs, so they carry no alert fields and are not deduplicated.

```json
{
  "schema_version": 2,
  "payload": "rustinel-capture-20260816T091240Z.ndjson",
  "rustinel_version": "1.6.0",
  "platform": "windows",
  "started_at": "2026-08-16T09:12:40Z",
  "ended_at": "2026-08-16T09:14:02Z",
  "status": "complete",
  "events": { "received": 1841, "written": 1841, "lost": 0, "source_lost": 0 },
  "payload_bytes": 612884,
  "payload_sha256": "9f2c…"
}
```

`status` is `complete` only when capture stopped cleanly with no lost events.
It stays `incomplete` when capture was killed, the writer fell behind (`lost`), or the OS dropped events first (`source_lost`).
Replay rejects incomplete recordings, and any payload whose checksum does not match.
Never edit a recording by hand.

## Replay results

By default `rustinel replay` prints a summary and one block per alert:

```text
Replay of /tmp/lab/run-42.ndjson
  recorded   1841 events on windows at 2026-08-16T09:12:40Z by Rustinel v1.6.0
  sigma      412 rules for windows from /opt/rustinel/rules/current/sigma
  ioc        37 inline indicators (IP, domain, and path)
  skipped    YARA and hash IOC checks; a recording holds events, not file artifacts
  response   disabled; replay never acts on the host it runs on
  dedup      disabled; every detector match is reported

[1] Medium Sigma Encoded PowerShell Command
    rule                 sigma::6f0d5a2c-7b41-4f2e-9d0a-1c8f3ab5e410
    time                 2026-08-16T09:12:44Z
    event                Process EventID 1 (windows/etw)
    Image                C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

1841 events replayed, 1 alerts (1 sigma, 0 ioc)
```

With `--output <PATH>`, alerts are written as ECS NDJSON, like live alerts plus an `edr.replay` object:

| Field | Value |
| --- | --- |
| `edr.replay.recording` | Recording file name |
| `edr.replay.platform` | Platform the recording was made on |
| `edr.replay.recorded_at` | When the recording started |

Replay refuses to write inside the configured alert directory, so replayed alerts never mix with live ones.
