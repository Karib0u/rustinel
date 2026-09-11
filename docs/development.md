# Development

## Toolchain

| Target | Needs |
| --- | --- |
| All platforms | Rust 1.92 or later (the repository pins stable) |
| Windows | Visual Studio Build Tools |
| macOS | Xcode Command Line Tools |
| Linux eBPF object | nightly Rust, `rust-src`, and `bpf-linker` |

## Build and run

```bash
cargo build
cargo build --release
```

Run the agent with the privileges it needs:

=== "Linux and macOS"

    ```bash
    sudo cargo run -- run
    ```

=== "Windows"

    From an elevated PowerShell:

    ```powershell
    cargo run -- run
    ```

On macOS, live Endpoint Security events also need a signed bundle, see [macOS](#macos).
Building and testing do not.

## Linux eBPF object

A Linux build embeds `ebpf/rustinel-ebpf.o` when it exists, and compiles it with nightly otherwise.
The file is ignored by Git, so a stale copy silently embeds old programs: rebuild it whenever `ebpf/src` changes.

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

cd ebpf
cargo +nightly build --release --bin rustinel-ebpf
cp target/bpfel-unknown-none/release/rustinel-ebpf rustinel-ebpf.o
```

To try a new object without rebuilding the agent:

```bash
sudo env RUSTINEL_EBPF_OBJECT=$PWD/ebpf/rustinel-ebpf.o ./target/release/rustinel run
```

For `cargo check`, `clippy`, or unit tests without the nightly toolchain, set `RUSTINEL_EBPF_STUB=1`.
The resulting binary cannot collect telemetry.

## macOS

Endpoint Security needs a bundle signed with the `com.apple.developer.endpoint-security.client` entitlement.
Build one with your Developer ID and an Endpoint Security provisioning profile:

```bash
cargo build --release
scripts/macos/package-app.sh \
  --binary target/release/rustinel \
  --output target/release/Rustinel.app \
  --profile "$HOME/Downloads/rustinel.provisionprofile" \
  --identity "Developer ID Application: Example (TEAMID)"
```

Grant the bundle Full Disk Access, then run `sudo ./target/release/Rustinel.app/Contents/MacOS/rustinel run`.

On a SIP-disabled test Mac, `--adhoc` replaces `--profile` and `--identity`.
Never use it on a normal Mac.

Release signing in CI reads `MACOS_SIGN_IDENTITY`, `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `MACOS_PROVISIONING_PROFILE_BASE64`, `MACOS_NOTARY_APPLE_ID`, `MACOS_NOTARY_TEAM_ID`, and `MACOS_NOTARY_PASSWORD`.

## Tests

```bash
cargo test --locked
cargo fmt --all
cargo clippy --locked --all-targets -- -D warnings
```

The normal suite uses synthetic events and needs no privileges.

### Live tests

Ignored by default.
Run them on a disposable machine:

| Test | Command | Needs |
| --- | --- | --- |
| Memory scanning | `cargo build --locked --example memory_target && cargo test --locked --test yara_memory -- --include-ignored` | Administrator, or root with process-memory access |
| Active response | `cargo test --locked --test active_response -- --include-ignored` | Same |
| Linux process identity | `cargo test --test linux_task_identity live_task_identity_matches_proc -- --ignored` | root, `RUSTINEL_EBPF_OBJECT` set |
| Linux socket fields | `cargo test --test linux_socket_tuple live_tuple_and_connection_churn -- --ignored` | root, `RUSTINEL_EBPF_OBJECT` set, a non-loopback interface |
| macOS collector loss | `sudo python3 scripts/macos/test-collector-loss.py <agent pid> <telemetry.json>` | A signed agent running as root. Suspends it for 10 seconds |

Linux kernel-dependent changes should be checked on several kernels, for example 5.10, 5.15, 6.1, and 6.8.
Tests that hide BTF must run in a VM or a private mount namespace, never on a shared host.

### SigmaHQ compatibility gate

CI loads every rule from the SigmaHQ commit pinned in `compatibility/sigmahq-baseline.json` and fails on parser errors or when the per-platform load counts drift from the baseline.
To run it locally, check out that commit and run:

```bash
RUSTINEL_EBPF_STUB=1 RUSTINEL_SIGMA_CORPUS_DIR=/path/to/sigma \
  cargo test --locked --test sigma_corpus_compatibility -- --include-ignored
```

### Replay fixture

`tests/fixtures/replay/` holds a Windows recording and the rules it must trigger.
`tests/replay_fixture.rs` replays it on every platform.
To regenerate it on a Windows lab machine:

1. `rustinel capture --output windows-powershell.ndjson`
2. Run `windows-powershell-fixture.ps1`, then press Ctrl-C.
3. Check the manifest says `"status": "complete"`.
4. Copy both files into `tests/fixtures/replay/`.
   Never edit a recording by hand: its checksum is verified.
5. Run `cargo test --test replay_fixture`.

### Detection gates

CI runs the [rustinel-rules](https://github.com/Karib0u/rustinel-rules) atomic suite against Linux and Windows builds: it performs safe actions and checks each produces its alert.
Release tags run it against every release artifact.

## Documentation

The docs use [Zensical](https://zensical.org/):

```bash
pip install zensical
zensical serve
```

Parts of the reference are generated from code.
After changing CLI flags, config options, or `FIELD_AVAILABILITY`, run:

```bash
cargo run --bin generate-docs
```

Tests fail when a generated section is out of date.
Writing rules are in [CONTRIBUTING.md](https://github.com/Karib0u/rustinel/blob/main/CONTRIBUTING.md#writing-documentation).

## Logging levels

| Level | For |
| --- | --- |
| `trace` | High-volume internals |
| `debug` | Troubleshooting detail. Nothing that fires on most events |
| `info` | Lifecycle and detections |
| `warn`, `error` | Degraded behavior and failures |
