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

**Example:**
```
2025-01-15T14:32:10Z INFO  rustinel: Starting Rustinel EDR agent
2025-01-15T14:32:10Z INFO  collector: Registered 9 ETW providers
2025-01-15T14:32:10Z INFO  engine: Loaded 42 Sigma rules
2025-01-15T14:32:15Z INFO  engine: Detection: Whoami Execution
```

## Security Alerts

**Location:** `logs/alerts.json.YYYY-MM-DD`

**Format:** ECS NDJSON (one JSON object per line)

**Rotation:** Daily

### Alert Structure

```json
{
  "@timestamp": "2025-01-15T14:32:10Z",
  "event.kind": "alert",
  "event.category": "process",
  "event.action": "process_creation",
  "rule.name": "Whoami Execution",
  "rule.severity": "low",
  "rule.engine": "Sigma",
  "process.executable": "C:\\Windows\\System32\\whoami.exe",
  "process.command_line": "whoami /all",
  "process.pid": "1234",
  "process.parent.executable": "C:\\Windows\\System32\\cmd.exe",
  "process.parent.pid": "5678",
  "process.parent.command_line": "cmd.exe",
  "user.name": "DOMAIN\\username"
}
```

### ECS Fields

**Core:**
- `@timestamp` - Event time (ISO 8601 UTC)
- `event.kind` - Always `alert`
- `event.category` - Event type (process, network, file, etc.)
- `event.action` - Specific action

**Rule:**
- `rule.name` - Detection rule name
- `rule.severity` - Alert severity level
- `rule.engine` - Detection engine (Sigma or YARA)

**Process Context:**
- `process.executable` - Full path to executable
- `process.command_line` - Command line arguments
- `process.pid` - Process ID
- `process.parent.*` - Parent process details

**Network Context (when applicable):**
- `destination.ip` - Target IP address
- `destination.port` - Target port
- `source.ip` - Source IP
- `source.port` - Source port

**File Context (when applicable):**
- `file.path` - File path

**Registry Context (when applicable):**
- `registry.path` - Registry key path
- `registry.value` - Registry value

**User Context:**
- `user.name` - Domain\Username

## SIEM Integration

Alerts are designed for direct ingestion into:
- Elasticsearch / OpenSearch
- Splunk
- Any SIEM supporting ECS or NDJSON

**Example Filebeat config:**
```yaml
filebeat.inputs:
- type: log
  paths:
    - C:\Rustinel\logs\alerts.json.*
  json.keys_under_root: true
```
