# Rustinel

A high-performance Windows EDR agent written in Rust.

## What It Does

Rustinel monitors Windows endpoints by:

- Collecting kernel events via ETW (Event Tracing for Windows)
- Normalizing events to Sysmon-compatible format
- Detecting threats using Sigma rules and YARA scanning
- Outputting alerts in ECS NDJSON format for SIEM ingestion

## Key Features

- **Dual Detection Engines** - Sigma rules for behavioral detection, YARA for file scanning
- **User-Mode** - No kernel driver required
- **Memory-Safe** - Pure Rust implementation
- **High Performance** - Async event handling, intelligent caching
- **Windows Service** - Runs as a background service with auto-start

## Requirements

- Windows 10/11 or Server 2016+
- Administrator privileges
- Rust 1.92+ (to build from source)

## Quick Start

```bash
# Build
cargo build --release

# Run (requires Administrator)
.\target\release\rustinel.exe run --console
```

## Documentation

- [Getting Started](getting-started.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)
- [Detection](detection.md)
- [CLI Reference](cli.md)
- [Output Format](output.md)
- [Development](development.md)
