<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Rustinel" width="240">
</p>

<h1 align="center">Rustinel</h1>

<p align="center">
  <b>Open-source endpoint detection for Windows, Linux, and macOS.</b><br>
  Native telemetry → Sigma / YARA / IOC detection → SIEM-ready alerts. Written in Rust.
</p>

<p align="center">
  <a href="https://github.com/Karib0u/rustinel/actions/workflows/ci-cd.yml"><img src="https://github.com/Karib0u/rustinel/actions/workflows/ci-cd.yml/badge.svg?style=flat-square" alt="CI"></a>
  <a href="https://github.com/Karib0u/rustinel/releases/latest"><img src="https://img.shields.io/github/v/release/Karib0u/rustinel?style=flat-square&color=ff8a3d" alt="Latest release"></a>
  <a href="https://github.com/Karib0u/rustinel/releases"><img src="https://img.shields.io/github/downloads/Karib0u/rustinel/total?style=flat-square&color=ff8a3d" alt="Downloads"></a>
  <a href="https://github.com/Karib0u/rustinel/stargazers"><img src="https://img.shields.io/github/stars/Karib0u/rustinel?style=flat-square&color=ff8a3d" alt="Stars"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-ff8a3d?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="https://rustinel.io/">Website</a> ·
  <a href="https://docs.rustinel.io/">Docs</a> ·
  <a href="https://github.com/Karib0u/rustinel/releases/latest">Download</a> ·
  <a href="docs/siem-demos.md">SIEM demos</a>
</p>

<p align="center">
  <img src="docs/images/demo.gif" alt="Rustinel demo" width="860">
</p>

---

## Get your first alert in 60 seconds

Rustinel ships as a single binary with bundled demo rules. Install it, trigger a test command, and read the alert.

**Linux & macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh | sh -s -- --run
```

**Windows** — from an elevated PowerShell:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.ps1 -OutFile install-rustinel.ps1
powershell -ExecutionPolicy Bypass -File .\install-rustinel.ps1 -Run
```

With the agent running, fire the bundled demo rule — same command on every platform:

```bash
whoami
```

Your alert lands in `logs/alerts.json.<date>` as ECS NDJSON — ready to ship straight to a SIEM.

> **Prefer to read before you run?** Download the [install script](scripts/install/install.sh) and inspect it, or grab a binary from the [latest release](https://github.com/Karib0u/rustinel/releases/latest). The installer only pulls published release binaries. macOS support is experimental and needs root plus user approval for the signed Endpoint Security client; see [Getting Started](https://docs.rustinel.io/getting-started/).

---

## Why Rustinel

A transparent endpoint detection engine you can read, run, test, and extend — no black box.

- **Native telemetry** — ETW on Windows, eBPF on Linux, Endpoint Security + `/dev/bpf` on macOS, normalized into one shared event model.
- **Three detection layers** — Sigma for behavior, YARA for files and memory, IOC matching for hashes, IPs, domains, and path regexes.
- **Reuse community rules** — bring existing Sigma and YARA rules instead of rewriting them into a proprietary format.
- **SIEM-ready output** — ECS 9.4.0 NDJSON alerts that drop into Elastic, Splunk, and friends.
- **Operational basics** — hot-reload for rules and IOCs, optional active response with dry-run + allowlists, Windows service and launchd support.

---

## Platform support

| Platform | Sensor | Telemetry | Status |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task | Stable |
| Linux 5.8+ (BTF) | eBPF | Process, network, file, DNS | Stable |
| macOS 11+ | Endpoint Security + `/dev/bpf` | Process, file, network, DNS | Experimental |

Windows coverage is the broadest today; Linux and macOS focus on process, network, file, and DNS. macOS remains experimental while signed and notarized release packaging is validated across supported versions. Full notes are in the [platform docs](https://docs.rustinel.io/architecture/).

---

## How detection works

```text
  ETW (Windows) · eBPF (Linux) · ESF + /dev/bpf (macOS)
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

The bundled rules just prove the pipeline works. For real coverage, load curated content from **[rustinel-rules](https://github.com/Karib0u/rustinel-rules)** — the official, versioned, CI-tested detection repository.

```text
rustinel        →  the engine that collects telemetry and evaluates rules
rustinel-rules  →  the Sigma / YARA / IOC packs it loads  (no conversion step)
```

Each pack materializes into folders you point `config.toml` straight at. Browse the [pack catalog](https://github.com/Karib0u/rustinel-rules) to get started.

---

## Good for / not for

**Use it for** detection engineering, rule development and testing, blue-team labs, cross-platform detection research, and SIEM pipeline validation.

**It is not** a drop-in replacement for a mature commercial EDR. Rustinel does not provide kernel-level self-protection, pre-execution blocking, or anti-tamper guarantees, and a sufficiently privileged attacker may interfere with user-mode telemetry. It is a transparent detection engine — not a managed response platform.

---

## Build from source

```bash
cargo build --release
sudo ./target/release/rustinel run
```

macOS requires the app-like signed bundle described in [Getting Started](https://docs.rustinel.io/getting-started/).

---

## Documentation

[Website](https://rustinel.io/) ·
[Docs home](https://docs.rustinel.io/) ·
[Getting Started](https://docs.rustinel.io/getting-started/) ·
[Configuration](https://docs.rustinel.io/configuration/) ·
[Detection](https://docs.rustinel.io/detection/) ·
[Architecture](https://docs.rustinel.io/architecture/) ·
[Operations](https://docs.rustinel.io/operations/) ·
[Troubleshooting](https://docs.rustinel.io/troubleshooting/) ·
[FAQ](https://docs.rustinel.io/faq/) ·
[Detection rules](https://github.com/Karib0u/rustinel-rules) ·
[Roadmap](docs/roadmap.md)

---

## Contributing

Testing, feedback, and detection ideas are all welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE).
