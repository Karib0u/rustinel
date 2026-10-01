# Use active response

Active response kills the process behind an alert.
It is off by default.
Test it in dry-run mode first.

## How it works

When an alert's severity is at least `response.min_severity`, Rustinel kills the process: `TerminateProcess` on Windows, `SIGKILL` on Linux and macOS.
It acts after the event, so the process may already have done its work.

Response uses the alert's [severity](detection.md#severity), including YARA rule metadata for file and process-memory matches.
`low` is the least severe response threshold; `informational` alerts are written normally but never trigger active response.
With `scanner.sigma_match_mode = "all"`, every emitted Sigma alert is considered independently, so overlapping rules may request a response for the same process.
Response safeguards and the configured severity threshold still apply.

Rustinel never kills:

- processes under an allowlisted path or with an allowlisted name,
- PIDs 0 to 4, or Rustinel itself,
- a process whose PID or executable path is unknown.

macOS refuses to kill SIP-protected processes even as root.
The failure is logged and the alert is still written.

## Process identity safety

Before termination, response checks the executable path and compares the start time and command-line hash when available in both the alert and the live process.
If identity cannot be queried or does not match, response skips termination and logs the reason.
When the alert has no start time or command-line hash, only the available identity fields can be checked.

| Platform | Guarantee between validation and termination |
| --- | --- |
| Linux | Response opens a `pidfd`, reads identity from `/proc`, and confirms the pinned process is still live after the reads. It sends `SIGKILL` through that same `pidfd`, so PID reuse cannot redirect termination to a replacement. |
| Windows | Response opens one handle with query and terminate rights, reads identity through it, and calls `TerminateProcess` on that same handle. PID reuse cannot redirect termination to a replacement. |
| macOS | Response checks identity before sending `SIGKILL` by PID. A small window remains in which the process can exit and its PID can be reused before the signal is sent. |

Linux response requires working `pidfd_open` and `pidfd_send_signal` system calls.
If the kernel or security policy prevents their use, response logs the failure and does not fall back to killing by PID.

## 1. Turn on dry run

```toml
[response]
enabled = true
prevention_enabled = false   # log only
min_severity = "high"
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
