# Alert and recording format

| Output | Default location | Written by |
| --- | --- | --- |
| Alerts (ECS NDJSON) | `logs/alerts.json.<date>` | `run` |
| Operational log | `logs/rustinel.log.<date>` | every command |
| Recordings | `captures/rustinel-capture-<timestamp>.ndjson` | `capture` |
| Replay results | console, or `--output` | `replay` |

On Linux and macOS these files are readable by their owner only.

## Alerts

One JSON object per line, following ECS 9.4.0.

```json
{
  "@timestamp": "2026-08-16T21:00:05Z",
  "ecs.version": "9.4.0",
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
| `event.provider` | The Rustinel sensor: `etw`, `windows_event_log`, `ebpf`, `esf`, `bpf`, or `yara-memory` |
| `event.sequence` | Native sequence number, when the source has one |
| `event.count` | Rollup alerts only: repeats suppressed by [deduplication](detection.md#deduplication) |
| `rule.name` | Rule title |
| `rule.id` | `sigma::<id>`, `yara::<id>`, or `ioc::<type>::<value>` |
| `edr.rule.severity` | `Low`, `Medium`, `High`, or `Critical` |
| `edr.rule.engine` | `Sigma`, `Yara`, or `Ioc` |
| `edr.event.ingest_seq` | Order in which Rustinel processed the event |
| `edr.event.provenance` | Fields Rustinel reconstructed rather than measured, marked `derived` |
| `edr.match` | Why the rule matched, when `alerts.match_debug` is on |

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
| `edr.wmi` | WMI activity (Windows) |
| `edr.service` | Service installs (Windows) |
| `edr.task` | Scheduled tasks (Windows) |
| `edr.security` | Security audit events (Windows) |

### Platform-specific fields

| Field | Platform | Value |
| --- | --- | --- |
| `edr.event_log.provider_name` | Windows | The provider that wrote an Event Log record. Sigma sees it as `Provider_Name` |
| `edr.security` | Windows | The full decoded Security event, with Windows field names. Identity, address, process, and service values are also copied to ECS fields |
| `edr.process.windows_metadata` | Windows | Where the command line came from, the raw SID, and the session ID |
| `edr.process.image_source` | Linux | `execve`: the path as passed to `execve()` |
| `edr.process.image_truncated` | Linux | `true` when the executable path was cut |
| `edr.file.path_truncated` | Linux | Which side of a file path was cut |
| `edr.process.real_user_id`, `edr.process.real_group_id` | Linux | Real credentials |
| `edr.process.effective_user_id`, `edr.process.effective_group_id` | Linux | Effective credentials. `user.name` resolves the effective UID |
| `edr.process.cgroup_id` | Linux | Kernel cgroup ID at exec |
| `edr.process.mount_namespace`, `edr.process.pid_namespace`, `edr.process.network_namespace` | Linux | Namespace inode numbers |
| `edr.process.session_id`, `edr.process.controlling_tty` | Linux | Session ID and terminal as `major:minor` |
| `edr.process.kernel_start_boottime` | Linux | Process start time in nanoseconds since boot |

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
