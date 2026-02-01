# Getting Started

## Installation

### From Source

```bash
git clone https://github.com/your-org/rustinel.git
cd rustinel
cargo build --release
```

The binary is located at `target/release/rustinel.exe`.

### Directory Structure

```
rustinel/
├── rustinel.exe
├── config.toml         # Optional configuration
├── rules/
│   ├── sigma/          # Sigma detection rules
│   └── yara/           # YARA scanning rules
└── logs/               # Created at runtime
    ├── rustinel.log.*  # Operational logs
    └── alerts.json.*   # Security alerts
```

## Running

### Console Mode

Run directly in the terminal with logs displayed:

```bash
.\rustinel.exe run --console
```

Press `Ctrl+C` to stop.

### Windows Service

Install and run as a background service:

```bash
# Install (runs at startup)
.\rustinel.exe service install

# Start
.\rustinel.exe service start

# Stop
.\rustinel.exe service stop

# Uninstall
.\rustinel.exe service uninstall
```

## Adding Rules

### Sigma Rules

Place `.yml` files in `rules/sigma/`:

```yaml
title: Whoami Execution
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\whoami.exe'
  condition: selection
level: low
```

### YARA Rules

Place `.yar` or `.yara` files in `rules/yara/`:

```yara
rule SuspiciousString {
  strings:
    $s = "malicious" nocase
  condition:
    $s
}
```

## Verifying Operation

Check that Rustinel is working:

1. Look for `logs/rustinel.log.*` for operational logs
2. Trigger a test detection (e.g., run `whoami.exe`)
3. Check `logs/alerts.json.*` for generated alerts
