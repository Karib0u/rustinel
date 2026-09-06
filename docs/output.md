# Output Format

Rustinel emits four outputs:

- Operational logs for runtime state and troubleshooting
- ECS NDJSON alerts for detections
- Behavioral recordings, written only by `rustinel capture`
- Replay results, written only by `rustinel replay`

## Operational Logs

Location:

- Default: `logs/rustinel.log.<date>`

Content includes:

- Startup and shutdown lifecycle
- Sensor initialization
- Rule and IOC reload activity
- Detection hits
- Active response actions
- Warnings and errors

Example:

Field rendering varies by logger, but the message text is representative:

```text
9:00 PM INFO  rustinel: Rustinel (Linux eBPF)
9:00 PM INFO  rustinel: Loading Sigma rules
9:00:01 PM INFO  rustinel: YARA scanner initialized
9:00:05 PM INFO  engine: Detection triggered engine=Sigma severity=High rule="Encoded PowerShell Command" process="/tmp/test-process" pid=4242
9:00:05 PM INFO  response: Active response would terminate process pid=4242 image="/tmp/test-process" dry_run=true
```

## Security Alerts

Location:

- Default: `logs/alerts.json.<date>`

Format:

- One ECS JSON document per line
- ECS version `9.4.0`

### Important Fields

| Field               | Meaning                                                                                                                                                                                               |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `@timestamp`        | Event time in UTC                                                                                                                                                                                     |
| `ecs.version`       | Always `9.4.0`                                                                                                                                                                                        |
| `event.kind`        | Always `alert`                                                                                                                                                                                        |
| `event.category`    | ECS category array                                                                                                                                                                                    |
| `event.type`        | ECS type array                                                                                                                                                                                        |
| `event.action`      | Normalized action keyword                                                                                                                                                                             |
| `event.code`        | Sysmon-style or native event ID string                                                                                                                                                                |
| `event.module`      | Always `edr`                                                                                                                                                                                          |
| `event.dataset`     | `edr.<category>`                                                                                                                                                                                      |
| `event.provider`    | Sensor that collected the event: `etw` or `windows_event_log` (Windows), `ebpf` (Linux), `esf` / `bpf` (macOS), or `yara-memory` for memory-scan hits. Not the Windows provider that wrote the record — see `edr.event_log.provider_name`. |
| `rule.name`         | Detection rule title                                                                                                                                                                                  |
| `rule.id`           | Optional detection rule identifier, unique amongs the rustinel rules. Formatted as: `sigma::<uuid>` for Sigma, `yara::<id>` for YARA (if metadata ID is defined), or `ioc::<type>::<value>` for IOCs. |
| `edr.rule.severity` | Low, Medium, High, or Critical                                                                                                                                                                        |
| `edr.rule.engine`   | `Sigma`, `Yara`, or `Ioc`                                                                                                                                                                             |
| `edr.process.image_source` | Linux process image provenance: `proc` when resolved from `/proc/<pid>/exe`, or `execve` when the raw invocation string was used after that lookup lost the process lifetime race. |
| `event.count`       | *(rollup only)* Number of suppressed repeats this rollup represents, i.e. occurrences within the dedup window excluding the first. Absent on the live first emission, which represents a single event. Summing `event.count` across lines (absent = 1) gives the true event volume. |

### Windows Process Alert Example

```json
{
  "@timestamp": "<date>T21:00:05Z",
  "ecs.version": "9.4.0",
  "event.kind": "alert",
  "event.category": ["process"],
  "event.type": ["start"],
  "event.action": "process-start",
  "event.code": "1",
  "event.module": "edr",
  "event.dataset": "edr.process",
  "event.provider": "etw",
  "rule.name": "Example - Whoami Execution (CommandLine + Image)",
  "rule.id": "sigma::9b92f7e7-ee12-4fb3-b4d2-f674514a3821",
  "edr.rule.severity": "Low",
  "edr.rule.engine": "Sigma",
  "host.os.type": "windows",
  "host.os.family": "windows",
  "process.executable": "C:\\Windows\\System32\\whoami.exe",
  "process.command_line": "whoami"
}
```

### Linux Process Alert Example

```json
{
  "@timestamp": "<date>T21:00:05Z",
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
  "host.os.family": "linux",
  "process.executable": "/usr/bin/whoami",
  "edr.process.image_source": "proc",
  "process.name": "whoami",
  "user.name": "root"
}
```

## Event Families

| Internal category | ECS dataset |
| --- | --- |
| Process | `edr.process` |
| Network | `edr.network` |
| File | `edr.file` |
| Registry | `edr.registry` |
| DNS | `edr.dns` |
| Image load | `edr.library` |
| Scripting | `edr.scripting` |
| PowerShell module | `edr.powershell_module` |
| WMI | `edr.wmi` |
| Service | `edr.service` |
| Task | `edr.task` |
| Security channel | `edr.security` |

The full field set depends on event type and platform. Windows alerts can include PE metadata, registry details, PowerShell content, and service or task context. Linux and macOS alerts currently focus on process, network, file, and DNS fields.

Alerts on events read from the Windows Event Log carry
`edr.event_log.provider_name`, the provider that wrote the record
(`Service Control Manager` for service installations). It is a different thing
from `event.provider`, which names the Rustinel sensor, and it is what Sigma
sees as `Provider_Name`.

Windows Security channel alerts additionally carry `edr.security`, a nested
object holding the decoded audit record under its own Windows field names
(`ObjectName`, `ShareName`, `AttributeValue`, ...). The fields that map onto ECS
— identity, source address, process, service — are also lifted into the standard
ECS fields, so `edr.security` is the lossless copy rather than the only one. It
is nested rather than flattened so a Windows field name can never collide with
an ECS one.

## Behavioral Recordings

A recording is the endpoint-behavior analogue of a packet capture: the normalized
events Rustinel's detectors consume, saved so the same activity can be evaluated
again later without re-running the sample that produced it. Recordings are
produced only by `rustinel capture`; an ordinary `run` never writes one.

Location:

- Default: `captures/rustinel-capture-<UTC timestamp>.ndjson`, configurable with
  `capture.directory`

A recording is two files:

| File | Content |
| --- | --- |
| `<name>.ndjson` | The payload: one normalized event per line, in observed order |
| `<name>.manifest.json` | The sidecar describing the payload and whether it is complete |

The payload holds canonical normalized events, recorded immediately after
normalization. It is not alert output: no rule ever ran against these events,
and they carry no alert-only process-context enrichment. Repeated events are
kept as-is, because capture does not deduplicate.

```json
{"timestamp":"2026-08-16T09:12:44Z","platform":"windows","provider":"etw","category":"Process","event_id":1,"opcode":1,"fields":{"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -EncodedCommand ...","ProcessId":"6132","ParentImage":"C:\\Windows\\explorer.exe"}}
```

The manifest records what the payload contains and whether it can be trusted:

```json
{
  "schema_version": 1,
  "payload": "rustinel-capture-20260816T091240Z.ndjson",
  "rustinel_version": "1.3.0",
  "platform": "windows",
  "started_at": "2026-08-16T09:12:40Z",
  "ended_at": "2026-08-16T09:14:02Z",
  "status": "complete",
  "events": { "received": 1841, "written": 1841, "lost": 0, "source_lost": 0 },
  "payload_bytes": 612884,
  "payload_sha256": "9f2c…"
}
```

`status` is the field that matters. The manifest is written as `incomplete` when
the session starts and is only rewritten as `complete` at clean shutdown with
every received event accounted for. A recording is therefore `incomplete`
whenever the process was killed before it could finalize, events were lost
because the writer could not keep up, or the source reported loss before the
events reached the sensor. `received` always equals `written + lost`;
`source_lost` is separate because those events were never received. On Windows,
`source_lost` is the cumulative `EventsLost` count across both ETW sessions.

Recordings are as sensitive as alerts, and often more so: they contain full
command lines, file paths, network destinations, and user names for *all*
observed activity, not only what a rule matched. They are written owner-only
(`0600`, in a `0700` directory on Unix) and are kept separate from alert and
operational log output. Treat sharing a recording the way you would treat
sharing a memory dump from the same host.

## Replay Results

`rustinel replay` evaluates a recording against the detectors and reports what
matched. Its results are not a record of what happened on the endpoint running
the replay, so they are kept away from the live alert output: replay never writes
to `logs/alerts.json.<date>`, and refuses an `--output` path inside the
configured alert directory.

By default the results go to stdout as a human-readable list, headed by the
recording and the effective detector configuration:

```text
Replay of /tmp/lab/run-42.ndjson
  recorded   1841 events on windows at 2026-08-16T09:12:40Z by Rustinel v1.3.0
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
    ProcessId            6132
    CommandLine          powershell.exe -EncodedCommand ...

1841 events replayed, 1 alerts (1 sigma, 0 ioc)
Replay results: not live detections, and not written to the alert log.
```

`--output <PATH>` writes the same alerts as ECS NDJSON instead, in the same
format as live alerts plus one extra object:

| Field | Meaning |
| --- | --- |
| `edr.replay.recording` | File name of the recording payload that was replayed |
| `edr.replay.platform` | Platform whose sensors produced the recorded events |
| `edr.replay.recorded_at` | When the recording was started |

`edr.replay` is present on replayed alerts and absent on live ones, which is what
tells the two apart once a SIEM has ingested both. Replay output files are
written owner-only (`0600`), like alerts and recordings.

Every value in the report comes from the recording or the loaded rules, and
nothing reads the clock, so replaying one recording twice against one
configuration produces byte-identical output.

## SIEM Shipping

Any log shipper that can tail NDJSON works. For runnable Filebeat, Elastic, and
Splunk configurations, see [SIEM Demos](siem-demos.md).
