# Output Format

Rustinel emits two outputs:

- Operational logs for runtime state and troubleshooting
- ECS NDJSON alerts for detections

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
9:00 PM INFO  rustinel: Rustinel v1.0.0 (Linux eBPF)
9:00 PM INFO  rustinel: Loading Sigma rules
9:00:01 PM INFO  rustinel: YARA scanner initialized
9:00:05 PM INFO  engine: Sigma detection triggered
9:00:05 PM INFO  response: Active response would terminate process pid=4242 image="/usr/bin/whoami" dry_run=true
```

## Security Alerts

Location:

- Default: `logs/alerts.json.<date>`

Format:

- One ECS JSON document per line
- ECS version `9.3.0`

### Important Fields

| Field | Meaning |
| --- | --- |
| `@timestamp` | Event time in UTC |
| `ecs.version` | Always `9.3.0` |
| `event.kind` | Always `alert` |
| `event.category` | ECS category array |
| `event.type` | ECS type array |
| `event.action` | Normalized action keyword |
| `event.code` | Sysmon-style or native event ID string |
| `event.module` | Always `edr` |
| `event.dataset` | `edr.<category>` |
| `event.provider` | `etw` on Windows, `ebpf` on Linux |
| `rule.name` | Detection rule title |
| `edr.rule.severity` | Low, Medium, High, or Critical |
| `edr.rule.engine` | `Sigma`, `Yara`, or `Ioc` |

### Linux Process Alert Example

```json
{
  "@timestamp": "<date>T21:00:05Z",
  "ecs.version": "9.3.0",
  "event.kind": "alert",
  "event.category": ["process"],
  "event.type": ["start"],
  "event.action": "process-start",
  "event.code": "1",
  "event.module": "edr",
  "event.dataset": "edr.process",
  "event.provider": "ebpf",
  "rule.name": "Example - Whoami Execution (Linux)",
  "edr.rule.severity": "Low",
  "edr.rule.engine": "Sigma",
  "host.os.type": "linux",
  "host.os.family": "linux",
  "process.executable": "/usr/bin/whoami",
  "process.name": "whoami",
  "user.name": "root"
}
```

### Windows Process Alert Example

```json
{
  "@timestamp": "<date>T21:00:05Z",
  "ecs.version": "9.3.0",
  "event.kind": "alert",
  "event.category": ["process"],
  "event.type": ["start"],
  "event.action": "process-start",
  "event.code": "1",
  "event.module": "edr",
  "event.dataset": "edr.process",
  "event.provider": "etw",
  "rule.name": "Example - Whoami Execution (CommandLine + Image)",
  "edr.rule.severity": "Low",
  "edr.rule.engine": "Sigma",
  "host.os.type": "windows",
  "host.os.family": "windows",
  "process.executable": "C:\\Windows\\System32\\whoami.exe",
  "process.command_line": "whoami /all"
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
| WMI | `edr.wmi` |
| Service | `edr.service` |
| Task | `edr.task` |

The full field set depends on event type and platform. Windows alerts can include PE metadata, registry details, PowerShell content, and service or task context. Linux alerts currently focus on process, network, file, and DNS fields.

## SIEM Shipping

Any log shipper that can tail NDJSON works. Example Filebeat input:

```yaml
filebeat.inputs:
- type: filestream
  paths:
    - /opt/rustinel/logs/alerts.json.*
  parsers:
    - ndjson:
        target: ""
```

For a runnable local Elastic or Splunk trial, see [SIEM Demos](siem-demos.md).
