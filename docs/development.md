# Development

## Building

### Requirements

- Rust 1.92 or later
- Windows 10/11 or Server 2016+
- Visual Studio Build Tools (for Windows API bindings)

### Debug Build

```bash
cargo build
```

### Release Build

```bash
cargo build --release
```

Output: `target/release/rustinel.exe`

## Project Structure

```
src/
├── main.rs           # Entry point, CLI, service management
├── lib.rs            # Library interface
├── config.rs         # Configuration loading
├── alerts.rs         # Alert output sink
├── collector/        # ETW event collection
├── engine/           # Sigma detection engine
├── models/           # Data structures
├── normalizer/       # Event normalization
├── scanner/          # YARA scanning
├── state/            # Caching layer
├── utils/            # Helper functions
└── bin/
    └── validate_rules.rs  # Rule validation tool
```

## Testing

### Unit Tests

```bash
cargo test
```

### Rule Validation

Validate Sigma and YARA rules:

```bash
cargo run --bin validate_rules
```

This tool:
1. Loads and parses all Sigma rules
2. Compiles all YARA rules
3. Tests with synthetic events
4. Reports validation statistics

### Integration Tests

```bash
cargo test --test integration
```

## Code Style

Format code before committing:

```bash
cargo fmt
```

Run linter:

```bash
cargo clippy
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `ferrisetw` | ETW provider management |
| `tokio` | Async runtime |
| `yara-x` | YARA rule engine |
| `regex` | Pattern matching |
| `evalexpr` | Boolean expression evaluation |
| `serde` | Serialization |
| `tracing` | Structured logging |
| `clap` | CLI parsing |
| `windows` | Windows API bindings |
| `windows-service` | Service management |

## Adding Features

### New ETW Provider

1. Add provider GUID in `collector/mod.rs`
2. Create event handler in `engine/handler.rs`
3. Add normalization logic in `normalizer/mod.rs`
4. Update event category in `models/mod.rs`

### New Sigma Modifier

1. Add parsing in `engine/mod.rs`
2. Implement matching logic
3. Add tests

### New YARA Integration

1. Extend `scanner/mod.rs`
2. Add trigger conditions
3. Update alert generation

## Debugging

### Verbose Logging

```bash
set EDR__LOGGING__LEVEL=trace
rustinel run --console
```

### ETW Tracing

Use Windows Performance Analyzer or logman to trace ETW sessions:

```bash
logman query -ets
```

## License

Apache 2.0
