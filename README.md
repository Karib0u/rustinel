<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Rustinel logo" width="280">
</p>

# Rustinel

**Open-source endpoint detection for Windows, Linux, and macOS**

<p align="center">
  <a href="https://github.com/Karib0u/rustinel/actions/workflows/ci-cd.yml"><img src="https://github.com/Karib0u/rustinel/actions/workflows/ci-cd.yml/badge.svg?style=flat-square" alt="CI"></a>
  <a href="https://github.com/Karib0u/rustinel/releases/latest"><img src="https://img.shields.io/github/v/release/Karib0u/rustinel?style=flat-square&color=ff8a3d" alt="Latest release"></a>
  <a href="https://github.com/Karib0u/rustinel/releases"><img src="https://img.shields.io/github/downloads/Karib0u/rustinel/total?style=flat-square&color=ff8a3d" alt="Downloads"></a>
  <a href="https://github.com/Karib0u/rustinel/stargazers"><img src="https://img.shields.io/github/stars/Karib0u/rustinel?style=flat-square&color=ff8a3d" alt="Stars"></a>
  <br>
  <img src="https://img.shields.io/badge/platform-Windows%20ETW-blue?style=flat-square&logo=windows" alt="Platform Windows ETW">
  <img src="https://img.shields.io/badge/platform-Linux%20eBPF-orange?style=flat-square&logo=linux" alt="Platform Linux eBPF">
  <img src="https://img.shields.io/badge/platform-macOS%20ESF-black?style=flat-square&logo=apple" alt="Platform macOS ESF">
  <a href="https://docs.rustinel.io/"><img src="https://img.shields.io/badge/docs-rustinel.io-d97835?style=flat-square" alt="Docs"></a>
  <img src="https://img.shields.io/badge/license-Apache%202.0-ff8a3d?style=flat-square" alt="License">
</p>

[Official site](https://rustinel.io/) · [Documentation](https://docs.rustinel.io/) · [GitHub Releases](https://github.com/Karib0u/rustinel/releases)

Rustinel is an open-source endpoint detection project for **Windows**, **Linux**, and **macOS**.

It collects native host telemetry using **ETW** on Windows, **eBPF** on Linux, and **Endpoint Security** plus **`/dev/bpf`** on macOS, normalizes events into a shared model, evaluates **Sigma**, **YARA**, and **IOC** detections, writes **ECS NDJSON** alerts, and can optionally terminate malicious processes.

The goal is simple: give blue teams, researchers, and detection engineers a transparent endpoint detection engine they can inspect, run, test, and extend.

<p align="center">
  <img src="docs/images/demo.gif" alt="Rustinel Demo" width="900">
</p>

---

## Why Rustinel exists

Rustinel was created because there was a real gap in the open-source endpoint detection space.

The project aims to combine:

- Native Windows telemetry through **ETW**
- Native Linux telemetry through **eBPF**
- A single cross-platform detection pipeline
- Support for community detection formats like **Sigma** and **YARA**
- IOC matching for hashes, IPs, domains, and path regexes
- ECS NDJSON alert output for SIEM-friendly ingestion
- A performant, memory-safe implementation in **Rust**

Some tools solve parts of this problem, but Rustinel brings these pieces together in one transparent and extensible agent.

Rustinel is not trying to hide behind a black box. The project is designed so defenders can understand exactly what telemetry is collected, how detections are evaluated, and where the current limits are.

---

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
- Windows service support
- Linux foreground execution under root or a supervisor of your choice
- macOS foreground execution under root, or a launchd daemon

---

## Architecture

```text
Windows hosts        Linux hosts        macOS hosts
   ETW                  eBPF             ESF + /dev/bpf
    |                    |                    |
    +--------------------+--------------------+
                    |
          Normalized event model
                    |
        +-----------+-----------+
        |           |           |
      Sigma        YARA        IOC
   behavior     process      hashes,
   rules        creation     IPs,
                scanning     domains,
                             path regexes
        |           |           |
        +-----------+-----------+
                    |
             ECS NDJSON alerts
                    |
          Optional active response
```

---

## Detection model

Rustinel combines three detection layers.

### Sigma

Sigma is used for behavioral detections on normalized endpoint events.

Examples include:

- Suspicious PowerShell activity
- WMI execution
- Service creation
- Scheduled task creation
- Suspicious process execution
- Linux process, network, file, and DNS query activity

Sigma support makes Rustinel practical for detection engineers because existing community rules can be reused and adapted instead of being rewritten into a proprietary format.

### YARA

YARA is used for file and tooling detection.

Today, Rustinel scans executables on process creation. This provides a practical high-signal scanning point without trying to behave like a full antivirus engine scanning everything on disk all the time.

YARA memory scanning is also supported, targeting private executable regions to detect packed, obfuscated, or runtime-unpacked payloads.

### IOC matching

IOC matching provides fast deterministic checks against:

- File hashes
- IP addresses
- Domains
- Path regexes

IOC matching is useful for threat intelligence and incident response, but it is strongest when combined with behavioral detections and YARA scanning. Domain IOCs can match DNS `QueryName` on Windows, Linux, and macOS; Linux covers outbound plaintext DNS queries observed by eBPF, and macOS covers plaintext DNS queries observed via `/dev/bpf` capture.

---

## Platform support

| Platform | Sensor | Current coverage | Runtime model |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task | Foreground run or built-in Windows service commands |
| Linux 5.8+ with BTF | eBPF | Process, network, file, DNS | Foreground run under root or your supervisor of choice |
| macOS 11+ | Endpoint Security + `/dev/bpf` | Process, file, network, DNS | Experimental; foreground run under root (signed/entitled or SIP relaxed) or a launchd daemon |

Windows telemetry coverage is broader today. Linux and macOS support currently focus on process, network, file, and DNS telemetry. Linux DNS events include outbound plaintext DNS `QueryName`; DNS response answers (`QueryResults`) are not parsed yet. macOS collects process and file events through Endpoint Security and network and DNS through `/dev/bpf` capture; network events are attributed to a process on a best-effort basis.

macOS support is experimental while the project waits for the required Endpoint Security Framework entitlement.

---

## 60-second demo

Download Rustinel, start the agent, trigger a test command, and inspect the generated alert.

### Windows

```powershell
cd .\rustinel-<version>-x86_64-pc-windows-msvc
.\rustinel.exe run
whoami /all
type .\logs\alerts.json.*
```

### Linux

```bash
cd rustinel-<version>-x86_64-unknown-linux-musl
sudo ./rustinel run
whoami
cat logs/alerts.json.*
```

### macOS

```bash
cd rustinel-<version>-aarch64-apple-darwin
sudo ./rustinel run
whoami
cat logs/alerts.json.*
```

Creating an Endpoint Security client requires root and the
`com.apple.developer.endpoint-security.client` entitlement on signed,
notarized builds. For local testing you can run with SIP/AMFI relaxed. See the
[development docs](docs/development.md) for ad-hoc signing steps.

The bundled demo rules are intended to validate that telemetry collection, rule evaluation, and alert output are working.

---

## Quick start

Download the release package for your platform from [GitHub Releases](https://github.com/Karib0u/rustinel/releases) and extract it.

### Windows

Download:

```text
rustinel-<version>-x86_64-pc-windows-msvc.zip
```

Extract it, then run:

```powershell
cd .\rustinel-<version>-x86_64-pc-windows-msvc
.\rustinel.exe run
whoami /all
```

The bundled Sigma demo rule should write an alert to:

```text
logs/alerts.json.<date>
```

### Linux

Choose the archive that matches your architecture:

```text
rustinel-<version>-x86_64-unknown-linux-musl.tar.gz
rustinel-<version>-aarch64-unknown-linux-musl.tar.gz
```

Extract and run:

```bash
tar xzf rustinel-<version>-x86_64-unknown-linux-musl.tar.gz
cd rustinel-<version>-x86_64-unknown-linux-musl
sudo ./rustinel run
whoami
```

If startup fails with `tracefs not found`, mount the tracing filesystems and retry:

```bash
mount -t tracefs tracefs /sys/kernel/tracing
mount -t debugfs debugfs /sys/kernel/debug
```

The bundled Sigma demo rule should write an alert to:

```text
logs/alerts.json.<date>
```

### macOS

Choose the archive that matches your architecture:

```text
rustinel-<version>-aarch64-apple-darwin.tar.gz
rustinel-<version>-x86_64-apple-darwin.tar.gz
```

Extract and run as root:

```bash
tar xzf rustinel-<version>-aarch64-apple-darwin.tar.gz
cd rustinel-<version>-aarch64-apple-darwin
sudo ./rustinel run
```

If startup fails with `NotPrivileged`, the Endpoint Security client could not be
created: run as root with a signed, entitled build, or relax SIP/AMFI for local
testing. A `com.rustinel.agent.plist` LaunchDaemon is included for persistent
deployment.

---

## Build from source

If you prefer to build locally instead of using a published release, use `cargo build --release`.

### Windows

```powershell
cargo build --release
.\target\release\rustinel.exe run
```

### Linux

```bash
cargo build --release
sudo ./target/release/rustinel run
```

### macOS

```bash
cargo build --release
codesign --force --sign - \
  --entitlements packaging/macos/rustinel.entitlements \
  target/release/rustinel
sudo ./target/release/rustinel run
```

Ad-hoc signing with the entitlement only takes effect when SIP/AMFI is relaxed;
distributable builds require a Developer ID and notarization.

For full release setup, source-build prerequisites, and validation steps, see the [Getting Started](https://docs.rustinel.io/getting-started/) documentation.

---

## Output

Rustinel writes operational logs and alerts to disk.

```text
logs/rustinel.log.<date>
logs/alerts.json.<date>
```

Alert format:

```text
ECS 9.3.0 NDJSON
```

This makes Rustinel alerts easy to ingest into SIEM and log pipelines.

---

## Best for

Rustinel is currently best suited for:

- Lab deployments and evaluations
- Detection engineering
- Rule development and testing
- Blue teams that want transparent host telemetry
- Cross-platform detection research
- SIEM pipeline testing
- Learning how ETW, eBPF, Sigma, YARA, and IOCs can fit together

---

## What Rustinel is not

Rustinel is not a full replacement for every capability of a mature commercial EDR.

Today, Rustinel does not try to provide the same kernel-level self-protection, pre-execution blocking, anti-tamper guarantees, or managed response capabilities that commercial EDR products may provide.

A sufficiently privileged attacker may be able to interfere with user-mode components or telemetry sources. Kernel-level threats, telemetry tampering, and heavily obfuscated activity may require additional controls or future Rustinel capabilities.

Rustinel is designed as a transparent open-source detection engine focused on telemetry collection, rule-based detection, alert generation, and research.

---

## Roadmap

Near-term focus is on first-run experience, a curated detection pack, and deployment reliability. Telemetry expansion and advanced EDR capabilities come after the basics are solid.

See the [full roadmap](docs/roadmap.md) for details.

---

## Documentation

- [Official Site](https://rustinel.io/)
- [Documentation Home](https://docs.rustinel.io/)
- [Getting Started](https://docs.rustinel.io/getting-started/)
- [Configuration](https://docs.rustinel.io/configuration/)
- [Detection](https://docs.rustinel.io/detection/)
- [Architecture](https://docs.rustinel.io/architecture/)
- [Development](https://docs.rustinel.io/development/)
- [Operations and Upgrade Guide](https://docs.rustinel.io/operations/)
- [Troubleshooting](https://docs.rustinel.io/troubleshooting/)
- [FAQ](https://docs.rustinel.io/faq/)

---

## Contributing

Contributions, testing, feedback, and detection ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).
