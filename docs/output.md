# Output Format

Rustinel produces two types of output: operational logs and security alerts.

## Operational Logs

**Location:** `logs/rustinel.log.YYYY-MM-DD`

**Format:** Plain text with timestamps

**Rotation:** Daily

**Content:**
- Startup/shutdown messages
- Detection triggers
- Errors and warnings
- Debug information (if enabled)
- Active response actions (dry-run or termination)

**Example:**

```
2025-01-15T14:32:10Z INFO  rustinel: Starting Rustinel EDR agent
2025-01-15T14:32:10Z INFO  collector: Registered 9 ETW providers
2025-01-15T14:32:10Z INFO  engine: Loaded 42 Sigma rules
2025-01-15T14:32:15Z INFO  engine: Detection: Whoami Execution
2025-01-15T14:32:16Z INFO  response: Active response would terminate process pid=4242 image="C:\\Temp\\evil.exe" dry_run=true
```

## Security Alerts

**Location:** `logs/alerts.json.YYYY-MM-DD`

**Format:** ECS NDJSON (one JSON object per line)

**Rotation:** Daily

**ECS version:** `9.3.0` (emitted as `ecs.version`)

### Alert Structure

```json
{
  "@timestamp": "2025-01-15T14:32:10Z",
  "ecs.version": "9.3.0",
  "event.kind": "alert",
  "event.category": ["process"],
  "event.type": ["start"],
  "event.action": "process-start",
  "event.code": "1",
  "event.severity": 75,
  "event.module": "edr",
  "event.dataset": "edr.process",
  "event.provider": "edr-rust",
  "rule.name": "Whoami Execution",
  "edr.rule.severity": "Low",
  "edr.rule.engine": "Sigma",
  "process.executable": "C:\\Windows\\System32\\whoami.exe",
  "process.name": "whoami.exe",
  "process.command_line": "whoami /all",
  "process.pid": 1234,
  "process.parent.executable": "C:\\Windows\\System32\\cmd.exe",
  "process.parent.pid": 5678,
  "user.name": "username",
  "user.domain": "DOMAIN",
  "related.user": ["username"]
}
```

### Core ECS Fields

- `@timestamp` - Event time (ISO 8601 UTC)
- `ecs.version` - ECS version, always `9.3.0`
- `event.kind` - Always `alert`
- `event.category` - ECS category array (see table below)
- `event.type` - ECS type array (see table below)
- `event.action` - Action keyword (for example `process-start`)
- `event.code` - Source event ID (Sysmon or Windows ID)
- `event.severity` - Numeric severity (Low=25, Medium=50, High=75, Critical=100)
- `event.module` - Always `edr`
- `event.dataset` - `edr.<category>` (for example `edr.process`)
- `event.provider` - Always `edr-rust`
- `rule.name` - Detection rule name

### Event Categorization (ECS 9.3.0)

| Internal Category | event.category | event.type (typical) | event.dataset |
| --- | --- | --- | --- |
| Process | process | start, end, info | edr.process |
| Network | network | connection | edr.network |
| File | file | creation, deletion, change | edr.file |
| Registry | registry | creation, deletion, change | edr.registry |
| DNS | network | protocol | edr.dns |
| ImageLoad | library | start | edr.library |
| Scripting | process | info | edr.scripting |
| WMI | api | info | edr.wmi |
| Service | configuration | creation, change | edr.service |
| Task | configuration | creation, change | edr.task |

### Process Context

- `process.executable`, `process.name`, `process.command_line`, `process.pid`
- `process.parent.executable`, `process.parent.name`, `process.parent.command_line`, `process.parent.pid`
- `process.working_directory`
- `process.pe.original_file_name`, `process.pe.product`, `process.pe.description`
- `edr.process.integrity_level`
- `winlog.logon.id`, `winlog.logon.guid`
- `user.name`, `user.domain`, `user.id`

### Network Context

- `source.ip`, `source.port`
- `destination.ip`, `destination.port`, `destination.domain`
- `network.transport` (tcp or udp)
- `network.type` (ipv4 or ipv6)
- `network.protocol` (dns for DNS events)
- `network.direction` (egress for network and dns events)

### File and Library Context

- `file.path`, `file.name`, `file.extension`, `file.created`
- `file.pe.original_file_name`, `file.pe.product`, `file.pe.description`
- `file.code_signature.exists`, `file.code_signature.subject_name`
- `dll.name`, `dll.path` (ImageLoad events)

### Registry Context

- `registry.path`, `registry.hive`, `registry.key`, `registry.value`
- `registry.data.strings`
- `edr.registry.event_type`, `edr.registry.new_name`

### DNS Context

- `dns.question.name`
- `dns.answers` (array of objects with `data`)
- `dns.resolved_ip`
- `dns.response_code`

### Service and Task Context

- `service.name`
- `edr.service.executable`, `edr.service.type`, `edr.service.start_type`, `edr.service.account_name`
- `edr.task.name`, `edr.task.content`, `edr.task.user_name`

### PowerShell, WMI, Remote Thread

- `edr.powershell.script_block_text`, `edr.powershell.script_block_id`
- `edr.wmi.operation`, `edr.wmi.query`, `edr.wmi.namespace`, `edr.wmi.event_type`
- `edr.remote_thread.target_pid`, `edr.remote_thread.target_image`, `edr.remote_thread.start_address`, `edr.remote_thread.start_module`, `edr.remote_thread.start_function`
- `edr.process.target_image`

### Related Fields

- `related.ip` - Source, destination, and DNS resolved IPs
- `related.user` - User name and SID when available

### EDR Extensions

Fields not covered by ECS are emitted with the `edr.` prefix. The `edr.*` list above is authoritative for current output.

## SIEM Integration

Alerts are designed for direct ingestion into:
- Elasticsearch or OpenSearch
- Splunk
- Any SIEM supporting ECS or NDJSON

**Example Filebeat config:**

```yaml
filebeat.inputs:
- type: log
  paths:
    - C:\\Rustinel\\logs\\alerts.json.*
  json.keys_under_root: true
```
