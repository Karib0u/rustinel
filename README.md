<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Rustinel" width="240">
</p>

<h1 align="center">Rustinel</h1>

<p align="center">
  <b>Open-source endpoint detection for Windows, Linux, and macOS.</b><br>
  Native telemetry to Sigma, YARA, IOC detection, and SIEM-ready alerts. Written in Rust.
</p>

<p align="center">
  <a href="https://github.com/Karib0u/rustinel/actions/workflows/ci.yml"><img src="https://github.com/Karib0u/rustinel/actions/workflows/ci.yml/badge.svg?style=flat-square" alt="CI"></a>
  <a href="https://github.com/Karib0u/rustinel/releases/latest"><img src="https://img.shields.io/github/v/release/Karib0u/rustinel?style=flat-square&color=ff8a3d" alt="Latest release"></a>
  <a href="https://github.com/Karib0u/rustinel/releases"><img src="https://img.shields.io/github/downloads/Karib0u/rustinel/total?style=flat-square&color=ff8a3d" alt="Downloads"></a>
  <a href="https://github.com/Karib0u/rustinel/stargazers"><img src="https://img.shields.io/github/stars/Karib0u/rustinel?style=flat-square&color=ff8a3d" alt="Stars"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-ff8a3d?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="https://rustinel.io/">Website</a> |
  <a href="https://docs.rustinel.io/">Docs</a> |
  <a href="https://github.com/Karib0u/rustinel/releases/latest">Download</a> |
  <a href="docs/siem-demos.md">SIEM demos</a>
</p>

<p align="center">
  <img src="docs/images/demo.gif" alt="Rustinel demo" width="860">
</p>

---

## Get Your First Alert

Rustinel ships release archives with a binary, default config, demo rules, and a
`logs/` directory.

**Windows** - from an elevated PowerShell:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.ps1 -OutFile install-rustinel.ps1
powershell -ExecutionPolicy Bypass -File .\install-rustinel.ps1 -Run
```

**Linux**

```bash
curl -fsSL https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh | sh -s -- --run
```

**macOS** (experimental)

```bash
curl -fsSL https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh | sh
cd rustinel
```

macOS requires a one-time Full Disk Access approval before Endpoint Security can
start. Follow the [Getting Started](https://docs.rustinel.io/getting-started/)
macOS notes before using it beyond a first test.

```bash
sudo ./rustinel run
```

With the agent running, trigger the bundled demo rule:

```bash
whoami
```

Alerts are written to `logs/alerts.json.<date>` as ECS NDJSON.

Prefer to inspect first? Download the [install script](scripts/install/install.sh)
or a package from the [latest release](https://github.com/Karib0u/rustinel/releases/latest).
Installers only download published release binaries.

---

## Why Rustinel

A transparent endpoint detection engine you can read, run, test, and extend.

- **Native telemetry:** ETW on Windows, eBPF on Linux, Endpoint Security and `/dev/bpf` on macOS.
- **Detection formats:** Sigma for behavior, YARA for files and memory, IOC matching for hashes, IPs, domains, and path regexes.
- **Rule reuse:** bring existing Sigma and YARA rules instead of rewriting them into a proprietary format.
- **SIEM output:** ECS 9.4.0 NDJSON alerts for Elastic, Splunk, and other log pipelines.
- **Operations:** hot reload for rules and IOCs, optional active response on Windows and Linux only; macOS is detection-only today. Includes Windows service support and launchd packaging notes.

---

## Platform support

| Platform | Sensor | Telemetry | Status |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task | Stable |
| Linux 5.8+ (BTF) | eBPF | Process, network, file, DNS | Stable |
| macOS 11+ | Endpoint Security + `/dev/bpf` | Process, file, network, DNS | Experimental |

Windows coverage is the broadest today. Linux and macOS focus on process,
network, file, and DNS telemetry. macOS remains experimental. Current gaps are
listed in [Limitations](https://docs.rustinel.io/limitations/).

---

## How detection works

```text
  ETW (Windows) | eBPF (Linux) | ESF + /dev/bpf (macOS)
                        │
              Normalized event model
                        │
        ┌───────────────┼───────────────┐
      Sigma            YARA             IOC
    behavior        files +         hashes, IPs,
      rules          memory         domains, paths
        └───────────────┼───────────────┘
                        │
                ECS NDJSON alerts
                        │
              Optional active response
```

See the [detection docs](https://docs.rustinel.io/detection/) for rule authoring, YARA memory scanning, and IOC formats.

---

## Detection packs

The bundled rules only prove that the pipeline works. For real coverage, load
curated content from **[rustinel-rules](https://github.com/Karib0u/rustinel-rules)**,
the official versioned detection repository.

```text
rustinel        ->  the engine that collects telemetry and evaluates rules
rustinel-rules  ->  the Sigma, YARA, and IOC packs it loads
```

Each pack materializes into folders you point `config.toml` straight at. Browse the [pack catalog](https://github.com/Karib0u/rustinel-rules) to get started.

---

## Good for / not for

**Use it for** detection engineering, rule development and testing, blue-team labs, cross-platform detection research, and SIEM pipeline validation.

**It is not** a drop-in replacement for a mature commercial EDR. Rustinel does
not provide kernel-level self-protection, pre-execution blocking, anti-tamper
guarantees, or managed response. A sufficiently privileged attacker may interfere
with user-mode telemetry.

---

## Build from source

```bash
cargo build --release
sudo ./target/release/rustinel run
```

macOS requires the app-like signed bundle described in [Getting Started](https://docs.rustinel.io/getting-started/).

---

## Documentation

[Website](https://rustinel.io/) |
[Docs home](https://docs.rustinel.io/) |
[Getting Started](https://docs.rustinel.io/getting-started/) |
[Configuration](https://docs.rustinel.io/configuration/) |
[Detection](https://docs.rustinel.io/detection/) |
[Architecture](https://docs.rustinel.io/architecture/) |
[Operations](https://docs.rustinel.io/operations/) |
[Troubleshooting](https://docs.rustinel.io/troubleshooting/) |
[FAQ](https://docs.rustinel.io/faq/) |
[Detection rules](https://github.com/Karib0u/rustinel-rules) |
[Roadmap](docs/roadmap.md)

---

## Contributing

Testing, feedback, and detection ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE).
