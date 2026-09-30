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

Rustinel is not a replacement for a commercial EDR: it has no anti-tamper, no pre-execution blocking, and no management console.
See [Security model](security.md).

## Where to go next

| I want to... | Go to |
| --- | --- |
| See a first alert | [Quickstart](getting-started.md) |
| Deploy on an endpoint | [Deploy on an endpoint](operations.md) |
| Write a rule | [Write rules](rule-development.md) |
| Test rules against recorded activity | [Test rules with replay](replay.md) |
| Forward alerts to Elastic, Splunk, or a webhook | [Forward alerts](siem-demos.md) |
| Know what a platform can detect | [Platform coverage](coverage.md) |
| Look up a command or option | [CLI](cli.md), [Configuration](configuration.md) |
| Fix a problem | [Troubleshooting](troubleshooting.md) |
