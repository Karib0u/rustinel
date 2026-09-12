# Use active response

Active response kills the process behind an alert.
It is off by default.
Test it in dry-run mode first.

## How it works

When an alert's severity is at least `response.min_severity`, Rustinel kills the process: `TerminateProcess` on Windows, `SIGKILL` on Linux and macOS.
It acts after the event, so the process may already have done its work.

Severity comes from the rule: the Sigma `level`, always `critical` for YARA, and `ioc.default_severity` for indicators.

Rustinel never kills:

- processes under an allowlisted path or with an allowlisted name,
- PIDs 0 to 4, or Rustinel itself,
- a process whose PID or executable path is unknown.

macOS refuses to kill SIP-protected processes even as root.
The failure is logged and the alert is still written.

## 1. Turn on dry run

```toml
[response]
enabled = true
prevention_enabled = false   # log only
min_severity = "critical"
```

Changes to `[response]` apply without a restart.

## 2. Trigger a test

Build and run the YARA demo binary from the repository.
It contains a string that the bundled YARA rule matches:

=== "Linux and macOS"

    ```bash
    rustc examples/yara_demo.rs -o examples/yara_demo
    ./examples/yara_demo
    ```

=== "Windows"

    ```powershell
    rustc .\examples\yara_demo.rs -o .\examples\yara_demo.exe
    .\examples\yara_demo.exe
    ```

The operational log shows what would have happened:

```text
response: Active response would terminate process pid=4242 image="/home/me/rustinel/examples/yara_demo" dry_run=true
```

The bundled `whoami` rule is not a good test: `whoami` lives in a trusted system folder, so the expected log line is `Active response skipped: allowlisted`.

## 3. Turn on prevention

```toml
[response]
enabled = true
prevention_enabled = true
```

Repeat the test.
The log now shows `Active response terminated process`.

## Allowlists

```toml
[response]
allowlist_images = ["backup-agent", "/opt/tools/scanner"]   # names or full paths
allowlist_paths = ["/opt/trusted/"]                         # path prefixes
```

`allowlist_paths` starts as a copy of the global `allowlist.paths`.
Setting it replaces that list for response only.
See [Configuration](configuration.md#response).
