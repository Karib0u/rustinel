<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Rustinel" width="240">
</p>

<h1 align="center">Rustinel</h1>

<p align="center">
  <b>Open-source endpoint detection. Three platforms. Your rules.</b><br>
  Run Sigma, YARA, and IOC detections on native Windows, Linux, and macOS telemetry.<br>
  Written in Rust, with local alerts and no cloud account required.
</p>

<p align="center">
  <a href="https://github.com/Karib0u/rustinel/actions/workflows/ci.yml"><img src="https://github.com/Karib0u/rustinel/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Karib0u/rustinel/releases/latest"><img src="https://img.shields.io/github/v/release/Karib0u/rustinel?style=flat-square&color=ff8a3d" alt="Latest release"></a>
  <a href="https://github.com/Karib0u/rustinel/releases"><img src="https://img.shields.io/github/downloads/Karib0u/rustinel/total?style=flat-square&color=ff8a3d" alt="Downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-ff8a3d?style=flat-square" alt="Apache 2.0 license"></a>
</p>

<p align="center">
  <a href="https://github.com/Karib0u/rustinel/releases/latest">Download</a> |
  <a href="https://docs.rustinel.io/">Documentation</a> |
  <a href="https://github.com/Karib0u/rustinel-rules">Detection packs</a> |
  <a href="https://rustinel.io/">Website</a>
</p>

<p align="center">
  <img src="docs/images/demo.gif" alt="Rustinel demo" width="860">
</p>

## Why Rustinel?

- **Use Sigma and YARA rules.**
  Sigma for behavior, YARA for executables and process memory, and IOC lists for hashes, IPs, domains, and paths.
- **Run on Windows, Linux, and macOS.**
  One engine, one config format, and the same Sysmon-style field names everywhere.
  Coverage varies by platform.
- **Keep your data.**
  The agent sends nothing home.
  Alerts are local ECS NDJSON files that Elastic, Splunk, or any log pipeline can ingest.
- **Test rules against recorded behavior.**
  Capture activity once, then replay it on any machine as your rules change.
- **See the gaps.**
  `rustinel doctor` reports rules that can never fire and events dropped under load.

## Quickstart

Install into a local `rustinel` folder, then start it.

**Linux** (kernel 5.8+):

```bash
curl -fsSL https://rustinel.io/install.sh | sh
cd rustinel && sudo ./rustinel run
```

**Windows**, in an elevated PowerShell:

```powershell
irm https://rustinel.io/install.ps1 | iex
Set-Location rustinel; .\rustinel.exe run
```

**macOS** (experimental) needs Full Disk Access first, see [macOS permissions](https://docs.rustinel.io/macos-permissions/):

```bash
curl -fsSL https://rustinel.io/install.sh | sh
cd rustinel && sudo ./rustinel run
```

Run `whoami` in another terminal.
The demo rule fires and the alert lands in `rustinel/logs/alerts.json.<date>`.

To install it as a service with a real rules pack, stop it with Ctrl-C and run `sudo ./rustinel setup --yes` from the `rustinel` folder (`.\rustinel.exe setup --yes` on Windows).
See [Run as a service](https://docs.rustinel.io/operations/).

## Capture once, replay as your rules improve

```bash
sudo ./rustinel capture --output ~/captures/session.ndjson   # Ctrl-C when done
sudo chown -R "$USER" ~/captures
./rustinel replay ~/captures/session.ndjson
./rustinel replay ~/captures/session.ndjson --config candidate.toml
```

Replay needs no privileges and works across platforms: a Windows recording replays on Linux.
See [Write and test rules](https://docs.rustinel.io/rule-development/).

## Platform support

| Platform | Sensors | Telemetry | Status |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW + Windows Event Log | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task, Security audit events | Stable |
| Linux 5.8+ | eBPF | Process, network, file, DNS | Stable |
| macOS 11+ | Endpoint Security + `/dev/bpf` | Process, file, network, DNS | Experimental |

Details: [Platform coverage](https://docs.rustinel.io/coverage/) and [Limitations](https://docs.rustinel.io/limitations/).

## Know the boundaries

Rustinel is built for endpoint monitoring, detection engineering, labs, and SIEM pipeline testing.
It is not a replacement for a commercial EDR: it has no kernel self-protection, pre-execution blocking, or anti-tamper, and a privileged attacker can stop it.

## Contribute

Bug reports, detection tests, and platform work are welcome.
Tell us what you monitor and where you get stuck.

[Contributing](CONTRIBUTING.md) | [Issues](https://github.com/Karib0u/rustinel/issues) | [Development guide](https://docs.rustinel.io/development/) | [Roadmap](https://github.com/Karib0u/rustinel/milestones)

## License

[Apache 2.0](LICENSE).
