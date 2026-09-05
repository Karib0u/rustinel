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
  Bring your detection content, monitor your endpoints, and send alerts to the tools you already use.
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

Endpoint detection should work with the platforms you run and the rules you
already understand.

Rustinel brings native telemetry, established detection formats, and a common
alert format into one open-source engine.

- **Use Sigma and YARA rules.** Detect behavior with Sigma, scan files and process memory with YARA, and match hash, IP, domain, and path indicators.
- **Run across Windows, Linux, and macOS.** Use one engine with a shared configuration model and normalized events. Sensors and detection coverage vary by platform.
- **Keep control of your data.** The live agent makes no outbound network connections. Alerts are local files you can inspect or forward yourself.
- **Connect your existing tools.** ECS 9.4.0 NDJSON output works with Elastic, Splunk, and other log pipelines.
- **Test detections against recorded behavior.** Capture telemetry once and replay it as your rules change, without repeating the activity.
- **Inspect and extend the engine.** Written in Rust and licensed under Apache 2.0.

## Get your first alert

Release archives include a binary, default configuration, and demo rules so you
can verify detection before deploying a service.

### Linux

Requires Linux 5.8+ with BTF support.

```bash
curl -fsSL https://rustinel.io/install.sh | sh
cd rustinel
sudo ./rustinel run
```

### Windows

Run in an elevated PowerShell:

```powershell
irm https://rustinel.io/install.ps1 | iex
Set-Location rustinel
.\rustinel.exe run
```

Requires the x64 Microsoft Visual C++ Redistributable. See
[Windows prerequisites](https://docs.rustinel.io/getting-started/#windows).

### macOS

macOS support is experimental. Complete the
[signing and Full Disk Access setup](https://docs.rustinel.io/getting-started/)
before starting the sensor.

```bash
curl -fsSL https://rustinel.io/install.sh | sh
cd rustinel
sudo ./rustinel run
```

### Trigger the demo rule

While Rustinel is running, open another terminal and run:

```bash
whoami
```

The bundled demo rule detects the process. Find the alert in
`logs/alerts.json.<date>` inside the extracted release directory.

The demo rules verify that the pipeline works. For broader coverage, install a
detection pack or add your own rules.

Prefer a manual installation? Browse the
[release archives](https://github.com/Karib0u/rustinel/releases/latest) or inspect
the [install scripts](scripts/install).

## Deploy for ongoing monitoring

Stop the foreground agent with Ctrl-C, then run setup from the extracted release
directory.

**Linux and macOS:**

```bash
sudo ./rustinel setup --yes
./rustinel doctor
```

**Windows, in an elevated PowerShell:**

```powershell
.\rustinel.exe setup --yes
.\rustinel.exe doctor
```

Setup writes the managed configuration, installs the Essential rules pack,
registers the native service, starts it, and checks its health.

Use `--pack advanced` for the larger pack or `--no-start` to register the service
without starting it.

| Platform | Service manager | Managed alert directory |
| --- | --- | --- |
| Windows | SCM | `C:\ProgramData\Rustinel\logs\` |
| Linux | systemd | `/var/log/rustinel/` |
| macOS | launchd | `/Library/Logs/Rustinel/` |

Rules and IOCs support hot reload. Optional process termination is available and
disabled by default.

[Configuration](https://docs.rustinel.io/configuration/) |
[Operations](https://docs.rustinel.io/operations/) |
[SIEM examples](docs/siem-demos.md)

## Your rules, with documented coverage

Use your own detection content or start with
**[rustinel-rules](https://github.com/Karib0u/rustinel-rules)**, the official
versioned Sigma, YARA, and IOC packs.

Packs are downloaded, SHA-256 verified, validated, and activated atomically. A
failed download leaves the current rules in place.

Rule compatibility depends on the telemetry and fields available on each
platform. A Windows rule does not automatically become a Linux detection.

We publish [Sigma coverage measurements](https://docs.rustinel.io/coverage/)
against a pinned SigmaHQ corpus, including missing collectors and unavailable
fields. These measure whether rules have the data needed to fire, not whether
they will detect every attack.

[Rule authoring](https://docs.rustinel.io/detection/) |
[Pack catalog](https://github.com/Karib0u/rustinel-rules) |
[Coverage and gaps](https://docs.rustinel.io/coverage/)

## Capture once. Replay as your rules improve.

Record endpoint activity, then evaluate the same events against new rules without
repeating the activity or running sensors on your development machine.

From the release directory on Linux or macOS:

```bash
# Start recording, perform the activity, then press Ctrl-C.
sudo ./rustinel capture --output session.ndjson

# Evaluate the recording without elevated privileges.
./rustinel replay session.ndjson

# Compare another configuration.
./rustinel replay session.ndjson --config candidate.toml

# Export results for automated comparison.
./rustinel replay session.ndjson --output results.ndjson
```

On Windows, use `.\rustinel.exe` and an elevated PowerShell for capture.

A Windows recording can replay on Linux or macOS. Replay uses the recorded
platform for Sigma routing and produces reproducible results for the same
recording and configuration.

Keep the recording and its `.manifest.json` sidecar together. Recordings contain
sensitive endpoint data, including command lines, paths, network destinations,
and user names.

Replay evaluates Sigma and IP, domain, and path IOC checks. YARA and hash checks
are skipped because recordings contain events rather than file contents. Active
response never runs during replay.

[Capture and replay reference](https://docs.rustinel.io/cli/)

## Platform support

| Platform | Sensors | Telemetry | Status |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW + Windows Event Log | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task, selected Security events | Stable |
| Linux 5.8+ with BTF | eBPF | Process, network, file, DNS | Stable |
| macOS 11+ | Endpoint Security + `/dev/bpf` | Process, file, network, DNS | Experimental |

Windows has the broadest coverage today. See
[requirements](https://docs.rustinel.io/getting-started/) and
[limitations](https://docs.rustinel.io/limitations/) for platform-specific details.

## Local operation, explicit downloads

The live agent collects and evaluates telemetry locally. It does not send
telemetry home or require a vendor account.

Installers download published releases. `setup`, `rules list`, and `rules install`
fetch the rules catalog; setup and rule installation also download packs.

Alerts remain on the endpoint unless you forward them through your own pipeline.

## Know the boundaries

Rustinel supports endpoint monitoring, detection engineering, security labs, and
SIEM pipeline validation.

It is not a drop-in replacement for a mature commercial EDR. It does not provide
kernel-level self-protection, pre-execution blocking, anti-tamper guarantees, or
managed response. A sufficiently privileged attacker may interfere with
user-mode telemetry.

Read the [current limitations](https://docs.rustinel.io/limitations/) when
evaluating it for your environment.

## Contribute

Help improve platform coverage, test detections, report bugs, or make setup
easier.

If you use Rustinel, tell us what you monitor, which rules matter to you, and
where you get stuck. Real deployment feedback helps guide the project.

[Contributing](CONTRIBUTING.md) |
[Issues](https://github.com/Karib0u/rustinel/issues) |
[Development guide](https://docs.rustinel.io/development/) |
[Roadmap](https://github.com/Karib0u/rustinel/milestones)

## License

[Apache 2.0](LICENSE).
