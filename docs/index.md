<p align="center">
  <img src="images/logo-rustinel.png" alt="Rustinel logo" width="280">
</p>

# Rustinel

**Rustinel is an open-source endpoint detection engine for Windows, Linux, and macOS.**

It collects native host telemetry (**ETW** on Windows, **eBPF** on Linux,
**Endpoint Security** plus `/dev/bpf` on macOS), normalizes it into one shared
event model, evaluates **Sigma**, **YARA**, and **IOC** detections against that
model, and writes alerts as **ECS NDJSON**.

It is built for blue teams, detection engineers, and researchers who want a
detection engine they can read, run, test, and extend.

## Start here

| I want to… | Page |
| --- | --- |
| Install it and see a first alert | [Getting Started](getting-started.md) |
| Run the Linux sensor in a container on a Linux host | [Docker](docker.md) |
| Ship alerts to Elastic or Splunk | [SIEM Demos](siem-demos.md) |
| Change rule paths, logging, or allowlists | [Configuration](configuration.md) |
| Look up a command or flag | [CLI Reference](cli.md) |
| Write, test, or debug a rule | [Detection](detection.md) |
| Know how much of SigmaHQ actually fires | [Sigma Coverage](coverage.md) |
| Fix something that is not working | [Troubleshooting](troubleshooting.md) |
| Know what it cannot do | [Limitations](limitations.md) |

## What it does today

- Native telemetry: ETW and Windows Event Log, Linux eBPF, macOS Endpoint Security and `/dev/bpf`
- One normalized event model shared across all three platforms
- Sigma for behavior, YARA for files and process memory, IOC matching for hashes, IPs, domains, and path regexes
- ECS NDJSON alerts that any log shipper can forward
- Hot reload for rules and indicators, with no restart
- `capture` and `replay` for offline rule development against recorded behavior
- Optional active response (process termination) on all three platforms, off by default

Windows coverage is the broadest. Linux and macOS cover process, network, file,
and DNS telemetry. macOS support is experimental while signed release packaging
is validated across supported versions.

## What it is not

Rustinel is not a drop-in replacement for a mature commercial EDR. It provides
no kernel-level self-protection, no pre-execution blocking, no anti-tamper
guarantees, and no managed response or enterprise console. A sufficiently
privileged attacker can interfere with user-mode telemetry.

That trade is deliberate. Rustinel uses telemetry the operating system already
exposes rather than shipping a kernel driver, which costs visibility and
enforcement points but keeps the agent transparent, portable, and inspectable.
Exactly where that boundary sits is documented in
[Limitations](limitations.md), including the cases where a rule can silently
fail to fire.

## Project

- [Architecture](architecture.md): how the runtime is put together
- [Development](development.md): build, sign, and test from source
- [Benchmarking](benchmarking.md): measure agent overhead on your own hardware
- [Milestones](https://github.com/Karib0u/rustinel/milestones) and
  [open issues](https://github.com/Karib0u/rustinel/issues): what is planned
  and in progress

The main project home is [rustinel.io](https://rustinel.io/).
