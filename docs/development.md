# Development

## Build Matrix

| Target | Tooling |
| --- | --- |
| Windows userspace build | Rust 1.92+, Visual Studio Build Tools |
| Linux userspace build | Rust 1.92+ |
| Linux eBPF object build | nightly Rust, `rust-src`, `bpf-linker` |
| macOS userspace build | Rust 1.92+, Xcode Command Line Tools |

## Fastest Local Build Paths

### Userspace

```bash
cargo check --workspace
cargo build
cargo build --release
```

On Windows, run the final binary from an elevated PowerShell. On Linux, run it as root or with the required eBPF capabilities.

### Linux eBPF Build

If `ebpf/rustinel-ebpf.o` already exists, a normal root `cargo build` embeds it and no nightly eBPF rebuild is needed.

If you need to rebuild the eBPF object from source:

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

cd ebpf
cargo +nightly build --release --bin rustinel-ebpf
cp target/bpfel-unknown-none/release/rustinel-ebpf rustinel-ebpf.o
cd ..
```

`build.rs` watches `ebpf/src`, `ebpf/Cargo.toml`, and `ebpf/rustinel-ebpf.o`. On Linux builds it embeds either the prebuilt object or a freshly compiled one.

## Recommended Dev Runs

### Windows

```powershell
cargo run -- run --console
```

### Linux

```bash
sudo cargo run -- run
```

### Linux With eBPF Override

Useful when iterating on `ebpf/` without rebuilding the full userspace binary:

```bash
sudo env RUSTINEL_EBPF_OBJECT=$PWD/ebpf/rustinel-ebpf.o ./target/release/rustinel run
```

### macOS

macOS telemetry uses Apple's Endpoint Security framework. Creating an ES client
(`es_new_client`) requires three things: running as root, the
`com.apple.developer.endpoint-security.client` entitlement, and user approval
(TCC). Without them the agent exits at startup with a `NotPrivileged` error.

For development and lab use you can avoid a provisioning profile by relaxing
system protections (in a VM or a dedicated test machine, never a production
host): disable SIP from Recovery (`csrutil disable`) and, if needed, disable
AMFI. Then ad-hoc sign the binary with the entitlement and run it as root:

```bash
cargo build --release
codesign --force --sign - \
  --entitlements packaging/macos/rustinel.entitlements \
  target/release/rustinel
sudo ./target/release/rustinel run
```

For distributable builds, request the Endpoint Security entitlement from Apple,
then sign with your Developer ID and notarize using the same entitlements file.
The entitlement lives in `packaging/macos/rustinel.entitlements`.

## Testing

### Unit and Integration Tests

```bash
cargo test --locked
cargo test --locked --test pipeline_sigma
cargo test --locked --test yara_disk
cargo test --locked --test yara_memory
```

Cargo auto-discovers the integration tests in `tests/*.rs`. The normal suite uses synthetic events and temporary Sigma, YARA, and IOC fixtures, so it does not require administrator/root privileges.

Ignored smoke tests cover live process memory scanning and active-response termination. Build the test target first, then opt in explicitly:

```bash
cargo build --locked --example memory_target
cargo test --locked --test yara_memory -- --include-ignored
cargo test --locked --test active_response -- --include-ignored
```

Those ignored tests may require administrator rights on Windows or a controlled Linux host with permissive process-memory access.

## Code Quality

```bash
cargo fmt
cargo clippy
```

## Project Structure

```text
src/
├── main.rs             # CLI entry point and platform bootstrapping
├── config.rs           # Config loading and defaults
├── alerts.rs           # ECS NDJSON alert sink
├── engine/             # Sigma rule parsing, classification, and evaluation
├── ioc/                # Atomic IOC loading and matching
├── models/             # Event, alert, and ECS data models
├── normalizer/         # Shared event normalization and enrichment
├── reload/             # Hot reload poller and worker
├── response/           # Optional process termination logic
├── scanner/            # YARA compilation and scanning
├── sensor/
│   ├── windows/        # ETW sensor implementation
│   ├── linux/          # eBPF userspace loader and event decoding
│   └── macos/          # Endpoint Security sensor
├── state/              # Process, DNS, SID, and network aggregation state
└── utils/              # Platform-specific helpers

ebpf/
└── src/                # Linux eBPF programs and event ABI definitions
```

## Logging Guidance

Use the existing logging contract when adding runtime logs:

- `trace`: high-volume internals
- `debug`: troubleshooting detail
- `info`: lifecycle and positive detections
- `warn` and `error`: degraded behavior or failures

If a line can fire on most normal events, it does not belong at `debug`.
