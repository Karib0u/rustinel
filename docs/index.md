<p align="center">
  <img src="images/logo-rustinel.png" alt="Rustinel logo" width="240">
</p>

# Rustinel

Rustinel is an open-source endpoint detection agent for Windows, Linux, and macOS.
It reads the telemetry each OS already exposes (ETW, eBPF, Endpoint Security), evaluates your Sigma, YARA, and IOC rules against it, and writes alerts as ECS NDJSON files.

## Install

=== "Linux and macOS"

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh
    ```

=== "Windows"

    ```powershell
    irm https://rustinel.io/install.ps1 | iex
    ```

Then follow the [Quickstart](getting-started.md) to trigger your first alert.

## Features

- **Your rules.**
  Sigma for behavior, YARA for executables and process memory, and IOC lists for hashes, IPs, domains, and paths.
  Rules reload without a restart.
- **One event model.**
  The same Sysmon-style field names on all three platforms.
  What each platform collects is listed in [Platform coverage](coverage.md).
- **Local.**
  The agent sends nothing home and needs no account.
  Alerts are files you forward with your own pipeline.
- **Capture and replay.**
  Record endpoint activity once, then test rule changes against the recording on any machine.
- **Visible gaps.**
  `rustinel doctor` reports rules that can never fire and events dropped under load.

## What it is not

Rustinel is not a replacement for a commercial EDR.
It has no kernel self-protection, no pre-execution blocking, no anti-tamper, and no management console.
A privileged attacker can stop it.
See [Limitations](limitations.md).

## Where to go next

| I want to... | Go to |
| --- | --- |
| See a first alert | [Quickstart](getting-started.md) |
| Deploy on an endpoint | [Run as a service](operations.md) |
| Write or test a rule | [Write and test rules](rule-development.md) |
| Forward alerts to Elastic or Splunk | [Send alerts to a SIEM](siem-demos.md) |
| Look up a command or option | [CLI](cli.md), [Configuration](configuration.md) |
| Fix a problem | [Troubleshooting](troubleshooting.md) |
