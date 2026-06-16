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
cargo run -- run
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
(`es_new_client`) requires three things, and each missing piece surfaces a
distinct startup error: running as root (`NotPrivileged` if not), the
`com.apple.developer.endpoint-security.client` entitlement (`NotEntitled` if
missing), and user approval via Full Disk Access / TCC (`NotPermitted` if not
granted).

After Apple approves the managed capability, enable Endpoint Security on the
explicit App ID used for the request and download a matching macOS provisioning
profile. Install the profile's signing certificate and private key in the login
keychain. Confirm that macOS can see the identity:

```bash
security find-identity -v -p codesigning
```

Build the binary, then create the app-like daemon bundle required for a
restricted entitlement:

```bash
cargo build --release

scripts/macos/package-app.sh \
  --binary target/release/rustinel \
  --output target/release/Rustinel.app \
  --profile "$HOME/Downloads/rustinel.provisionprofile" \
  --identity "Developer ID Application: Example (TEAMID)"
```

The script derives the bundle identifier from the profile, validates that the
profile authorizes Endpoint Security, embeds it at
`Contents/embedded.provisionprofile`, adds the profile App ID and Team ID to the
signed entitlements, enables the hardened runtime, and verifies the bundle.
On macOS, YARA-X uses Wasmtime's Pulley interpreter because Endpoint Security
clients cannot use hardened runtime relaxation entitlements for JIT executable
memory.

Grant `Rustinel.app` Full Disk Access in System Settings, then run:

```bash
sudo ./target/release/Rustinel.app/Contents/MacOS/rustinel run
```

In another terminal, trigger and inspect the bundled demo:

```bash
whoami
cat logs/alerts.json.*
```

For a SIP-disabled VM or dedicated test Mac, an ad-hoc bundle can still be
created without a profile:

```bash
scripts/macos/package-app.sh \
  --binary target/release/rustinel \
  --output target/release/Rustinel.app \
  --adhoc
```

Do not use the ad-hoc path on a normal SIP-enabled Mac. Release builds require
the Developer ID identity, the Endpoint Security provisioning profile, and a
successful notarization. CI expects `MACOS_SIGN_IDENTITY`,
`MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`,
`MACOS_PROVISIONING_PROFILE_BASE64`, `MACOS_NOTARY_APPLE_ID`,
`MACOS_NOTARY_TEAM_ID`, and `MACOS_NOTARY_PASSWORD`.

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
