# Rustinel
**High-performance, user-mode Windows EDR in Rust**

<p align="center">
  <a href="https://karib0u.github.io/rustinel/"><img src="https://img.shields.io/badge/docs-available-brightgreen" alt="Docs"></a>
  <img src="https://img.shields.io/badge/platform-Windows-blue?logo=windows" alt="Platform Windows">
  <img src="https://img.shields.io/badge/language-Rust-orange?logo=rust" alt="Language Rust">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License">
  <img src="https://img.shields.io/badge/status-Alpha-yellow" alt="Status">
</p>

Rustinel is a **high-throughput Windows EDR agent** written in **Rust**. It collects **kernel telemetry via ETW**, normalizes events into a **Sysmon-compatible schema**, detects threats using **Sigma** + **YARA**, and outputs alerts as **ECS NDJSON** for straightforward SIEM ingestion.

> ✅ No kernel driver  
> ✅ User-mode ETW pipeline  
> ✅ Sigma behavioral detection + YARA scanning  
> ✅ ECS NDJSON alerts + operational logs

<p align="center">
  <img src="docs/images/demo.gif" alt="Rustinel Demo" width="900">
</p>

---

## Why Rustinel?

Rustinel is built for defenders who want:
- **Kernel-grade telemetry** without kernel risk (ETW, user-mode)
- **Performance under volume** (async pipeline + caching + noise reduction)
- **Detection compatibility** (Sysmon-style normalization for Sigma)
- **Operational simplicity** (NDJSON alerts on disk, easy to ship to a SIEM)

---

## What it does

Rustinel monitors Windows endpoints by:
- Collecting kernel events via **ETW** (process, network, file, registry, DNS, PowerShell, WMI, services, tasks)
- Normalizing ETW events into **Sysmon-compatible** fields
- Detecting threats using **Sigma rules** and **YARA scanning**
- Writing alerts in **ECS NDJSON** format

---

## Key features

- **User-mode only**: no kernel driver required
- **Dual detection engines**:
  - **Sigma** for behavioral detection
  - **YARA** for file scanning on process start
- **Noise reduction**:
  - keyword filtering at the ETW session
  - router-level filtering for high-volume network events
  - optional network connection aggregation
- **Enrichment**:
  - NT → DOS path normalization
  - PE metadata extraction (OriginalFileName/Product/Description)
  - parent process correlation
  - SID → `DOMAIN\User` resolution
  - DNS caching and reverse mapping
- **Windows service support** (install/start/stop/uninstall)
- **ECS NDJSON alerts** for SIEM ingestion

---

## Requirements

- Windows 10/11 or Server 2016+
- Administrator privileges (ETW + service management)
- Rust 1.92+ (build from source)

---

## Quick start

> Run from an elevated PowerShell.

**Option 1: Download Release (Recommended)**
1. Download the latest release from [GitHub Releases](https://github.com/Karib0u/rustinel/releases).
2. Extract the archive.
3. Run from an elevated PowerShell:
   ```powershell
   .\rustinel.exe run --console
   ```

**Option 2: Build from Source**

```powershell
# Build
cargo build --release

# Run (console output)
.\target\release\rustinel.exe run --console
````

Running without arguments is equivalent to `rustinel run`.

---

## 2-minute demo

### Sigma demo

This repo ships with an example rule: `rules/sigma/example_whoami.yml`

1. Start Rustinel (admin shell):

```powershell
cargo run -- run --console
```

2. Trigger the rule:

```powershell
whoami /all
```

3. Verify an alert was written:

* `logs/alerts.json.YYYY-MM-DD`

---

### YARA demo

This repo ships with an example rule: `rules/yara/example_test_string.yar`

1. Build the demo binary:

```powershell
rustc .\examples\yara_demo.rs -o .\examples\yara_demo.exe
```

2. Run it:

```powershell
.\examples\yara_demo.exe
```

3. Verify an alert includes the rule name:

* `ExampleMarkerString`

---

## Service mode

```powershell
.\target\release\rustinel.exe service install
.\target\release\rustinel.exe service start
.\target\release\rustinel.exe service stop
.\target\release\rustinel.exe service uninstall
```

**Notes**

* `service install` registers the *current executable path* — run it from the final location.
* Config and rules paths resolve from the working directory; for services, prefer absolute paths or env overrides.

---

## Configuration

Configuration precedence:

1. Environment variables (highest)
2. `config.toml`
3. Built-in defaults

Example `config.toml`:

```toml
[scanner]
sigma_enabled = true
sigma_rules_path = "rules/sigma"
yara_enabled = true
yara_rules_path = "rules/yara"

[logging]
level = "info"
directory = "logs"
filename = "rustinel.log"
console_output = true

[alerts]
directory = "logs"
filename = "alerts.json"

[network]
aggregation_enabled = true
aggregation_max_entries = 20000
aggregation_interval_buffer_size = 50
```

Environment overrides:

```powershell
set EDR__LOGGING__LEVEL=debug
set EDR__SCANNER__SIGMA_RULES_PATH=C:\rules\sigma
```

---

## Rules

### Sigma

* Place `.yml` / `.yaml` files under `rules/sigma/`
* Supported categories include:
  `process_creation`, `network_connection`, `file_event`, `registry_event`,
  `dns_query`, `image_load`, `ps_script`, `wmi_event`, `service_creation`, `task_creation`

### YARA

* Place `.yar` / `.yara` files under `rules/yara/`
* Rules compile at startup
* Scans trigger on **process creation** (runs in a background worker)

---

## Output

Rustinel produces:

* **Operational logs**: `logs/rustinel.log.YYYY-MM-DD`
* **Security alerts** (ECS NDJSON): `logs/alerts.json.YYYY-MM-DD`

Example alert (one JSON object per line):

```json
{
  "@timestamp": "2025-01-15T14:32:10Z",
  "event.kind": "alert",
  "event.category": "process",
  "event.action": "process_creation",
  "rule.name": "Whoami Execution",
  "rule.severity": "low",
  "rule.engine": "Sigma",
  "process.executable": "C:\\Windows\\System32\\whoami.exe",
  "process.command_line": "whoami /all",
  "user.name": "DOMAIN\\username"
}
```

---

## Documentation

* 📚 Docs home: [https://karib0u.github.io/rustinel/](https://karib0u.github.io/rustinel/)
* Getting Started: [https://karib0u.github.io/rustinel/getting-started/](https://karib0u.github.io/rustinel/getting-started/)
* Configuration: [https://karib0u.github.io/rustinel/configuration/](https://karib0u.github.io/rustinel/configuration/)
* CLI Reference: [https://karib0u.github.io/rustinel/cli/](https://karib0u.github.io/rustinel/cli/)
* Architecture: [https://karib0u.github.io/rustinel/architecture/](https://karib0u.github.io/rustinel/architecture/)
* Detection: [https://karib0u.github.io/rustinel/detection/](https://karib0u.github.io/rustinel/detection/)
* Output Format: [https://karib0u.github.io/rustinel/output/](https://karib0u.github.io/rustinel/output/)
* Development: [https://karib0u.github.io/rustinel/development/](https://karib0u.github.io/rustinel/development/)

---

## Development

```powershell
# Unit tests
cargo test

# Format + lint
cargo fmt
cargo clippy

# Validate Sigma + YARA rules
cargo run --bin validate_rules
```

Project layout (high level):

```text
src/
├── collector/     # ETW collection + routing
├── normalizer/    # Sysmon-style normalization + enrichment
├── engine/        # Sigma engine
├── scanner/       # YARA scanning worker
├── state/         # caches (process/sid/dns/aggregation)
└── bin/validate_rules.rs
```

---

## Status

Rustinel is **Alpha**. It’s usable for experimentation, lab deployments, and iterative hardening.
Expect breaking changes while the schema + engines mature.

---

## License

Apache 2.0 — see `LICENSE`.