# Active Response

Rustinel includes an optional response engine that can terminate processes when
an alert reaches the configured minimum severity. It is disabled by default and
should be tested in dry-run mode first.

Active response currently runs on **Windows and Linux only**. macOS support is
detection-only.

## Modes

1. Disabled: no response work is queued.
2. Dry-run: Rustinel logs what it would do.
3. Prevention: Rustinel terminates eligible processes.

## Platform Behavior

| Platform | Action |
| --- | --- |
| Windows | Uses process termination APIs |
| Linux | Sends `SIGKILL` |
| macOS | Not supported; detection only |

## Severity Handling

- Sigma uses the rule `level`
- YARA is always treated as `critical`
- IOC uses `ioc.default_severity`

`response.min_severity` is applied after those mappings.

## Allowlists

Rustinel will not act on processes that match either of these:

- `allowlist_images`: image basenames or full paths
- `allowlist_paths`: trusted path prefixes

By default, `response.allowlist_paths` inherits `allowlist.paths`, whose per-platform defaults are listed once in [Configuration -> Default Trusted Paths](configuration.md#default-trusted-paths).

## Example Configuration

### Windows

```toml
[allowlist]
paths = [
  "C:\\Windows\\",
  "C:\\Program Files\\",
  "C:\\Program Files (x86)\\",
]

[response]
enabled = true
prevention_enabled = false
min_severity = "critical"
allowlist_images = []
```

### Linux

```toml
[allowlist]
paths = [
  "/usr/bin/",
  "/usr/sbin/",
]

[response]
enabled = true
prevention_enabled = false
min_severity = "critical"
allowlist_images = []
```

## Logging

Response actions are logged in the operational log:

```text
response: Active response would terminate process pid=4242 image="/tmp/evil" dry_run=true
response: Active response terminated process pid=4242 image="/tmp/evil"
response: Active response skipped: allowlisted pid=4321 image="/usr/bin/bash"
```

## Safety Checks

The response engine skips termination when:

- PID is missing
- PID is in the protected low system range (PIDs 0-4 on both platforms)
- The target is the Rustinel process itself
- The process image path is not known
- The image or path is allowlisted

## Safe Test Flow

### Cross-Platform YARA Demo

1. Enable dry-run mode:

```toml
[response]
enabled = true
prevention_enabled = false
```

2. Start Rustinel.
3. Build and run the sample binary:

```bash
rustc ./examples/yara_demo.rs -o ./examples/yara_demo
./examples/yara_demo
```

On Windows:

```powershell
rustc .\examples\yara_demo.rs -o .\examples\yara_demo.exe
.\examples\yara_demo.exe
```

4. Confirm the operational log shows a dry-run response decision.
5. After validation, switch `prevention_enabled = true` and repeat.

### Sigma Demo

Windows:

```powershell
whoami
```

Linux:

```bash
whoami
```

These are safe ways to validate the alert-to-response pipeline with the bundled demo rules before introducing custom high-severity content.
