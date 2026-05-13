<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Rustinel logo" width="280">
</p>

# Rustinel

**Open-source endpoint detection for Windows and Linux**

<p align="center">
  <a href="https://github.com/Karib0u/rustinel/actions/workflows/ci-cd.yml"><img src="https://github.com/Karib0u/rustinel/actions/workflows/ci-cd.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Karib0u/rustinel/releases/latest"><img src="https://img.shields.io/github/v/release/Karib0u/rustinel" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20ETW-blue?logo=windows" alt="Platform Windows ETW">
  <img src="https://img.shields.io/badge/platform-Linux%20eBPF-orange?logo=linux" alt="Platform Linux eBPF">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License">
</p>

Rustinel is an open-source endpoint detection project for **Windows** and **Linux**.

It collects native host telemetry using **ETW** on Windows and **eBPF** on Linux, normalizes events into a shared model, evaluates **Sigma**, **YARA**, and **IOC** detections, writes **ECS NDJSON** alerts, and can optionally terminate malicious processes.

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
- A shared event model across supported platforms
- Sigma rule evaluation on normalized events
- YARA scanning on process creation
- IOC matching for file hashes, IPs, domains, and path regexes
- ECS NDJSON alert output
- Hot reload for rules and indicator files
- Optional active response with dry-run and allowlists
- Windows service support
- Linux foreground execution under root or a supervisor of your choice

---

## Architecture

```text
Windows hosts                      Linux hosts
   ETW                                eBPF
    |                                  |
    +---------------+------------------+
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

IOC matching is useful for threat intelligence and incident response, but it is strongest when combined with behavioral detections and YARA scanning. Domain IOCs can match DNS `QueryName` on both Windows and Linux; Linux support covers outbound plaintext DNS queries observed by eBPF.

---

## Platform support

| Platform | Sensor | Current coverage | Runtime model |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task | Foreground run or built-in Windows service commands |
| Linux 5.8+ with BTF | eBPF | Process, network, file, DNS | Foreground run under root or your supervisor of choice |

Windows telemetry coverage is broader today. Linux support currently focuses on process, network, file, and DNS telemetry through eBPF. Linux DNS events include outbound plaintext DNS `QueryName`; DNS response answers (`QueryResults`) are not parsed yet.

---

## 60-second demo

Download Rustinel, start the agent, trigger a test command, and inspect the generated alert.

### Windows

```powershell
cd .\rustinel-<version>-x86_64-pc-windows-msvc
.\rustinel.exe run --console
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
.\rustinel.exe run --console
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

---

## Build from source

If you prefer to build locally instead of using a published release, use `cargo build --release`.

### Windows

```powershell
cargo build --release
.\target\release\rustinel.exe run --console
```

### Linux

```bash
cargo build --release
sudo ./target/release/rustinel run
```

For full release setup, source-build prerequisites, and validation steps, see the [Getting Started](https://karib0u.github.io/rustinel/getting-started/) documentation.

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

- [Documentation Home](https://karib0u.github.io/rustinel/)
- [Getting Started](https://karib0u.github.io/rustinel/getting-started/)
- [Configuration](https://karib0u.github.io/rustinel/configuration/)
- [Detection](https://karib0u.github.io/rustinel/detection/)
- [Architecture](https://karib0u.github.io/rustinel/architecture/)
- [Development](https://karib0u.github.io/rustinel/development/)
- [Operations and Upgrade Guide](https://karib0u.github.io/rustinel/operations/)
- [Troubleshooting](https://karib0u.github.io/rustinel/troubleshooting/)
- [FAQ](https://karib0u.github.io/rustinel/faq/)

---

## Contributing

Contributions, testing, feedback, and detection ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).
