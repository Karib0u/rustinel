# Detection

Rustinel uses three detection engines: Sigma for behavioral rules, YARA for file scanning, and an atomic IOC engine for indicator matching.

## Sigma Rules

### Logsource Categories (Required)

Rustinel routes rules by `logsource.category` and only loads rules that are relevant to the current Windows ETW pipeline.
If `category` is missing or unsupported, the rule is skipped at load time.

`product` and `service` are validated at load time:
- `product`: empty or `windows` is accepted; others are skipped.
- `service`: empty or supported Windows services are accepted; unsupported values are skipped.

Supported categories:

- `process_creation`
- `network_connection`
- `file_event`
- `file_create`
- `file_delete`
- `registry_event`
- `registry_add`
- `registry_set`
- `registry_delete`
- `dns_query`
- `image_load`
- `ps_script`
- `wmi_event`
- `service_creation`
- `task_creation`

Named-pipe Sigma category `pipe_created` is intentionally unsupported. A dedicated PoC confirmed that the current ETW pipeline does not reliably emit named-pipe object names (`\\.\pipe\...` / `\Device\NamedPipe\...`) in decoded output.

### Rule Format

```yaml
title: Suspicious Process
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\suspicious.exe'
  filter:
    User|contains: 'SYSTEM'
  condition: selection and not filter
level: high
```

### Detection Logic

- Boolean operators: `and`, `or`, `not`
- Parentheses for grouping
- Aggregation: `1 of selection*`, `all of them`
- Conditions are transpiled and precompiled at startup (no parsing in the hot event path)

### Supported Modifiers

| Modifier | Meaning |
|----------|---------|
| `contains` | Substring match |
| `startswith` | Prefix match |
| `endswith` | Suffix match |
| `all` | All values must match |
| `cased` | Case-sensitive match |
| `re` | Regular expression |
| `i`, `m`, `s` | Regex flags for `re` (case-insensitive, multiline, dotall) |
| `windash` | Windows dash normalization (`-` and `/`) |
| `fieldref` | Reference another field in the same event |
| `exists` | Field presence check |
| `cidr` | IP range matching |
| `base64` | Base64-encoded matching |
| `base64offset` | Base64 with offset variations |
| `wide`, `utf16`, `utf16le`, `utf16be` | UTF-16 transformations |
| `lt`, `gt`, `le`, `lte`, `ge`, `gte` | Numeric comparison |

Wildcard characters `*` and `?` are supported in string patterns.

### Common Fields

Process events:

- `Image`, `CommandLine`, `User`, `ParentImage`, `ParentCommandLine`
- `OriginalFileName`, `Product`, `Description`
- `ProcessId`, `ParentProcessId`, `IntegrityLevel`, `CurrentDirectory`
- `TargetImage`, `LogonId`, `LogonGuid`

Network events:

- `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`
- `DestinationHostname`, `Image`, `ProcessId`, `User`

File events:

- `TargetFilename`, `Image`, `ProcessId`, `User`
- `CreationUtcTime`, `PreviousCreationUtcTime`

Registry events:

- `TargetObject`, `Details`, `EventType`, `NewName`
- `Image`, `ProcessId`, `User`

DNS events:

- `QueryName`, `QueryResults`, `QueryStatus`
- `Image`, `ProcessId`

Image load events:

- `ImageLoaded`, `Image`, `OriginalFileName`, `Product`, `Description`
- `Signed`, `Signature`, `User`, `ProcessId`

PowerShell script events:

- `ScriptBlockText`, `ScriptBlockId`, `Path`
- `Image`, `ProcessId`, `User`

WMI events:

- `Operation`, `Query`, `EventNamespace`, `EventType`
- `DestinationHostname`, `Image`, `ProcessId`, `User`

Service creation events:

- `ServiceName`, `ServiceFileName`, `ServiceType`, `StartType`, `AccountName`
- `Image`, `ProcessId`, `User`

Task creation events:

- `TaskName`, `TaskContent`, `UserName`
- `Image`, `ProcessId`, `User`

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
- Files under allowlisted path prefixes are skipped before queueing and again in the worker
- Matches generate alerts with the rule name

### Supported Rule Files

- `.yar`
- `.yara`

## Atomic IOC Detection

The IOC engine matches atomic indicators against live events. It supports four indicator types.

### Hash IOCs (`rules/ioc/hashes.txt`)

One hash per line, optionally followed by `;comment`. Hash type is auto-detected by length:

- 32 hex chars → MD5
- 40 hex chars → SHA1
- 64 hex chars → SHA256

```
0c2674c3a97c53082187d930efb645c2;DEEP PANDA Sakula
c03318cb12b827c03d556c8747b1e323225df97bdc4258c2756b0d6a4fd52b47;Operation SMN
```

Hash checking triggers on **process creation only** and runs in a dedicated blocking worker thread.
Files under allowlisted paths (shared `allowlist.paths` by default, or `ioc.hash_allowlist_paths` override) are skipped.
Files exceeding `max_file_size_mb` (default: 50 MB) are also skipped.
A file identity cache avoids re-hashing unchanged binaries.

### IP/CIDR IOCs (`rules/ioc/ips.txt`)

One IP or CIDR per line:

```
203.0.113.1;C2 endpoint
10.10.0.0/16;Lab range
```

Checked against `DestinationIp`, `SourceIp` (network events) and `QueryResults` (DNS events).

### Domain IOCs (`rules/ioc/domains.txt`)

One domain per line. Prefix with `.` or `*.` for suffix matching:

```
evil.example.com;Exact match
*.example.org;All subdomains
```

Checked against `QueryName` (DNS), `DestinationHostname` (network/WMI).

### Path Regex IOCs (`rules/ioc/paths_regex.txt`)

One regex per line, compiled case-insensitive:

```
^C:\\Users\\Public\\.*\.exe$;Suspicious drop path
.*\\AppData\\Roaming\\.*\\update\.exe$;Common malware pattern
# Note: use \\ for path separators (literal backslash), \. for literal dot
```

Checked against `Image`, `TargetFilename`, `ImageLoaded`, `ServiceFileName`, and PowerShell `Path` fields.
Patterns are compiled into a `RegexSet` for efficient multi-pattern matching.

### IOC File Format

All IOC files share the same format:

- Lines starting with `#` or `//` are comments
- Empty lines are ignored
- Values and comments are separated by `;`

### IOC Alerts

IOC alerts use `rule.engine: "Ioc"` and follow the naming convention `ioc:<type>:<indicator>`.
The default severity is configurable via `ioc.default_severity` (default: `high`).

## Severity Levels

Sigma `level` values map to alert severity as follows:

- `critical` -> Critical
- `high` -> High
- `medium` -> Medium
- Any other value -> Low

YARA matches are always treated as Critical.
