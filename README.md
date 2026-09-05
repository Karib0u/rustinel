<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Rustinel" width="240">
</p>

<h1 align="center">Rustinel</h1>

<p align="center">
  <b>Open-source endpoint detection for Windows, Linux, and macOS.</b><br>
  Sigma, YARA, and IOC detections on native telemetry. No cloud, no account, nothing phoning home.<br>
  Capture endpoint behavior once, then replay it against your rules anywhere. Written in Rust.
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
  <a href="https://docs.rustinel.io/coverage/">Sigma coverage</a> |
  <a href="docs/siem-demos.md">SIEM demos</a>
</p>

<p align="center">
  <img src="docs/images/demo.gif" alt="Rustinel demo" width="860">
</p>

---

## Quick Start

### 1. Install

**Windows** - from PowerShell:

```powershell
irm https://rustinel.io/install.ps1 | iex
```

The Windows release binary requires the x64 Microsoft Visual C++ Redistributable.
See [Getting Started](https://docs.rustinel.io/getting-started/#windows) if the
process exits before printing output.

**Linux:**

```bash
curl -fsSL https://rustinel.io/install.sh | sh -s -- --run
```

**macOS** (experimental):

```bash
curl -fsSL https://rustinel.io/install.sh | sh
cd rustinel
sudo ./rustinel run
```

macOS requires a one-time Full Disk Access approval before Endpoint Security can
start. Follow the [Getting Started](https://docs.rustinel.io/getting-started/)
macOS notes before using it beyond a first test.

Prefer to inspect first? Download the [install script](scripts/install/install.sh)
or a package from the [latest release](https://github.com/Karib0u/rustinel/releases/latest).
Installers only download published release binaries.

### 2. Deploy

`setup` writes the managed configuration, installs the Essential rules pack,
registers the platform's native service, starts it, and runs health checks.

```powershell
rustinel setup --yes
rustinel doctor
```

```bash
sudo rustinel setup --yes
rustinel doctor
```

Use `--pack advanced` for the larger pack, or `--no-start` to register the
service without starting it.

### 3. See a first alert

With the agent running, trigger the bundled demo rule:

```bash
whoami
```

Alerts are ECS NDJSON, one object per line, written to `alerts.json.<date>`:

| Platform | Managed install | Archive `./rustinel run` |
| --- | --- | --- |
| Windows | `C:\ProgramData\Rustinel\logs\` | `logs\` |
| Linux | `/var/log/rustinel/` | `logs/` |
| macOS | `/Library/Logs/Rustinel/` | `logs/` |

---

## Why Rustinel

A transparent endpoint detection engine you can read, run, test, and extend.

- **Native telemetry:** ETW and Windows Event Log on Windows, eBPF on Linux, Endpoint Security and `/dev/bpf` on macOS. One normalized event model across all three.
- **Detection formats:** Sigma for behavior, YARA for files and process memory, IOC matching for hashes, IPs, domains, and path regexes.
- **Rule reuse:** bring existing Sigma and YARA rules instead of rewriting them into a proprietary format. **74% of the SigmaHQ Windows corpus can fire today** - measured against a pinned corpus commit, not estimated. See [Sigma coverage](https://docs.rustinel.io/coverage/).
- **Offline rule development:** `capture` a behavior once, then `replay` it against your rules as often as you like. No sensors, no privileges, no re-detonation.
- **Local by design:** the running agent makes no network connections. Alerts are files on disk - ship them with your own pipeline, or just read them where they land. Rules packs are the only exception, downloaded when you explicitly run `setup` or `rules install`.
- **SIEM output:** ECS 9.4.0 NDJSON alerts for Elastic, Splunk, and other log pipelines.
- **Operations:** hot reload for rules and IOCs, versioned rules packs, optional active response (process termination, off by default), and native service management via SCM, systemd, and launchd.

---

## Record once, replay anywhere

Detonating a sample to test one rule change is slow, and you cannot detonate on
the box where you write rules. `capture` records normalized telemetry to a file
without evaluating anything; `replay` runs that file through the same detector
code the live pipeline uses.

```bash
sudo rustinel capture --output run-42.ndjson   # start, run the sample, Ctrl-C
rustinel replay run-42.ndjson                  # iterate on rules, no sensors needed
```

A recording made on Windows replays on Linux or macOS, unprivileged, as often as
the rules change. Replay loads detectors once with hot reload and deduplication
off, so two replays of one recording against one configuration produce identical
output - which makes recordings usable as regression fixtures in CI.

YARA and hash IOC checks are skipped and reported as skipped: a recording holds
events, not files. Active response is never invoked. Recordings contain full
command lines, paths, and user names, so handle them as sensitive artifacts.

See the [CLI reference](https://docs.rustinel.io/cli/#replay) for details.

---

## Platform support

| Platform | Sensor | Telemetry | Status |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW + Windows Event Log | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task, Security channel (6 audited event IDs) | Stable |
| Linux 5.8+ (BTF) | eBPF | Process, network, file, DNS | Stable |
| macOS 11+ | Endpoint Security + `/dev/bpf` | Process, file, network, DNS | Experimental |

Windows coverage is the broadest today. Linux and macOS focus on process,
network, file, and DNS telemetry. macOS remains experimental. Current gaps are
listed in [Limitations](https://docs.rustinel.io/limitations/).

---

## How detection works

```text
   ETW + Event Log         eBPF             Endpoint Security
      (Windows)           (Linux)          + /dev/bpf (macOS)
          └──────────────────┴──────────────────────┘
                             │
                  Normalized event model
                             │
          ┌──────────────────┬──────────────────────┐
        Sigma              YARA                    IOC
      behavior           files and            hashes, IPs,
        rules             memory             domains, paths
          └──────────────────┴──────────────────────┘
                             │
                     ECS NDJSON alerts
                             │
                 Optional active response
```

The same event model feeds the offline loop:

```text
   Normalized event model ─── capture ──► recording (NDJSON + manifest)
              ▲                                         │
              └──────────────── replay ─────────────────┘
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

`rustinel setup` already installed the Essential pack. To see what else is
available for this platform and switch:

```bash
rustinel rules list
sudo rustinel rules install linux-essential
```

Packs are downloaded, SHA-256 verified, validated, and activated atomically, so
a failed download leaves the current rules in place. Browse the
[pack catalog](https://github.com/Karib0u/rustinel-rules) for what ships today.

---

## Who it's for

**Endpoint monitoring you control.** Workstations and servers where you want
real visibility without a cloud console, a vendor account, or an agent that
reports home. Install it, point it at a rules pack, and everything it observes
stays on the machine.

**Detection engineering.** Rule development and testing, blue-team labs,
cross-platform detection research, and SIEM pipeline validation - with `capture`
and `replay` for iterating on rules without re-running samples.

**What it is not.** A drop-in replacement for a mature commercial EDR. Rustinel
does not provide kernel-level self-protection, pre-execution blocking, anti-tamper
guarantees, or managed response. A sufficiently privileged attacker may interfere
with user-mode telemetry.

That trade is deliberate: Rustinel uses telemetry the operating system already
exposes rather than shipping a kernel driver. That costs visibility and
enforcement points, and keeps the agent transparent, portable, and inspectable.

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
[CLI reference](https://docs.rustinel.io/cli/) |
[Sigma coverage](https://docs.rustinel.io/coverage/) |
[Architecture](https://docs.rustinel.io/architecture/) |
[Operations](https://docs.rustinel.io/operations/) |
[Troubleshooting](https://docs.rustinel.io/troubleshooting/) |
[FAQ](https://docs.rustinel.io/faq/) |
[Detection rules](https://github.com/Karib0u/rustinel-rules) |
[Roadmap](https://github.com/Karib0u/rustinel/milestones)

---

## Contributing

Testing, feedback, and detection ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE).
