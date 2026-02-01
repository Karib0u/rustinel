# Detection

Rustinel uses two detection engines: Sigma for behavioral rules and YARA for file scanning.

## Sigma Rules

### Supported Categories

| Category | Description |
|----------|-------------|
| `process_creation` | Process start events |
| `network_connection` | TCP/UDP connections |
| `file_event` | File create, delete, rename |
| `registry_event` | Registry operations |
| `dns_query` | DNS lookups |
| `image_load` | DLL/module loading |
| `ps_script` | PowerShell scripts |
| `wmi_event` | WMI operations |
| `service_creation` | Service installation |
| `task_creation` | Scheduled tasks |

### Rule Format

```yaml
title: Suspicious Process
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\suspicious.exe'
  filter:
    User|contains: 'SYSTEM'
  condition: selection and not filter
level: high
```

### Detection Logic

- Boolean operators: `and`, `or`, `not`
- Parentheses for grouping
- Aggregation: `1 of selection*`, `all of them`

### Modifiers

**String Matching:**
- `contains` - Substring match
- `startswith` - Prefix match
- `endswith` - Suffix match
- `all` - All values must match
- `cased` - Case-sensitive

**Pattern Matching:**
- `re` - Regular expression
- `cidr` - IP range matching

**Encoding:**
- `base64` - Base64 encoded
- `base64offset` - Base64 with offset
- `wide` / `utf16` - UTF-16 encoded

**Comparison:**
- `lt`, `gt`, `le`, `ge` - Numeric comparison
- `exists` - Field presence check
- `fieldref` - Reference another field

**Other:**
- `windash` - Windows dash normalization (`-` and `/`)

### Available Fields

**Process Events:**
- `Image`, `CommandLine`, `User`, `ParentImage`, `ParentCommandLine`
- `OriginalFileName`, `Product`, `Description`
- `ProcessId`, `ParentProcessId`

**Network Events:**
- `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`
- `DestinationHostname`

**File Events:**
- `TargetFilename`, `Image`

**Registry Events:**
- `TargetObject`, `Details`, `Image`

**DNS Events:**
- `QueryName`, `QueryResults`

## YARA Rules

### Rule Format

```yara
rule ExampleDetection {
  meta:
    description = "Detects example malware"
    severity = "high"

  strings:
    $s1 = "malicious_string" nocase
    $s2 = { 4D 5A 90 00 }

  condition:
    $s1 or $s2
}
```

### Behavior

- Rules loaded from `rules/yara/` at startup
- Scans triggered on process creation events
- File scanning runs in background (non-blocking)
- Matches generate alerts with rule name

### Supported File Types

Files are scanned by extension:
- `.yar`
- `.yara`

## Severity Levels

Both engines map rule severity to alert levels:

| Level | Description |
|-------|-------------|
| `informational` | Low-priority, FYI |
| `low` | Minor concern |
| `medium` | Moderate threat |
| `high` | Significant threat |
| `critical` | Immediate attention required |
