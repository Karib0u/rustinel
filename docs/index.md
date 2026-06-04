<p align="center">
  <img src="images/logo-rustinel.png" alt="Rustinel logo" width="280">
</p>

# Rustinel Documentation

**Rustinel** is an open-source endpoint detection project for Windows, Linux, and macOS.

It collects native host telemetry using **ETW** on Windows, **eBPF** on Linux, and **Endpoint Security** plus **`/dev/bpf`** on macOS, normalizes events into a shared model, evaluates **Sigma**, **YARA**, and **IOC** detections, and writes alerts as **ECS NDJSON**.

Rustinel is designed for blue teams, detection engineers, researchers, and anyone who wants a transparent endpoint detection engine they can inspect, run, test, and extend.

Visit the [official Rustinel site](https://rustinel.io/) for the main project home.

## Start here

- [Getting Started](getting-started.md) — install and run Rustinel
- [Configuration](configuration.md) — configure telemetry, rules, alerts, and response
- [Detection](detection.md) — understand Sigma, YARA, and IOC matching
- [Architecture](architecture.md) — understand how Rustinel works internally
- [Benchmarking](benchmarking.md) — collect repeatable performance and latency evidence
- [Troubleshooting](troubleshooting.md) — fix common issues

## Project background

- [Why Rustinel](why-rustinel.md)
- [Limitations](limitations.md)
- [Roadmap](roadmap.md)

## What Rustinel does today

Rustinel currently provides:

- Windows telemetry collection through ETW
- Linux telemetry collection through eBPF
- macOS telemetry collection through Endpoint Security and `/dev/bpf`
- A shared event model across supported platforms
- Sigma rule evaluation on normalized events
- YARA scanning on process creation
- IOC matching for file hashes, IPs, domains, and path regexes
- ECS NDJSON alert output
- Hot reload for rules and indicator files
- Optional active response with dry-run and allowlists

macOS support is experimental while the project waits for the required Endpoint Security Framework entitlement.

## What Rustinel is not

Rustinel is not a full replacement for every capability of a mature commercial EDR.

It does not currently provide the same kernel-level self-protection, pre-execution blocking, anti-tamper guarantees, or managed response capabilities that commercial EDR products may provide.

Rustinel is designed as a transparent open-source detection engine focused on telemetry collection, rule-based detection, alert generation, and research.
