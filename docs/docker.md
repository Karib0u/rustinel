# Docker

Rustinel ships a multi-stage `Dockerfile` that produces a small Alpine image
containing the statically linked musl binary, the demo rules, and a
container-ready `config.toml`. It builds for `linux/amd64` and `linux/arm64`,
and a glibc variant is available for environments that require one.

The container is a real endpoint sensor, not a sandboxed application: eBPF
telemetry is kernel-wide, so a container on a host observes the whole host. That
also means it needs host-level access to work. Read
[Detection Scope](#detection-scope) before deploying it as your Linux sensor.

## Build

```bash
docker build -t rustinel:local .
```

Build arguments:

| Argument | Default | Purpose |
| --- | --- | --- |
| `ALPINE_VERSION` | `3.22` | Base image for the build and runtime stages |
| `RUST_VERSION` | `1.97` | Rust toolchain used for both builder stages |
| `DEBIAN_SUITE` | `trixie` | Debian suite of the eBPF builder stage and the Debian runtime |
| `NIGHTLY_TOOLCHAIN` | `nightly-2026-08-11` | Nightly used for the eBPF object |
| `BPF_LINKER_VERSION` | `0.10.4` | `bpf-linker` version, pinned to the nightly LLVM |
| `CARGO_FEATURES` | `rsigma-engine` | Cargo features, matching the release workflow |
| `VERSION` | `1.3.0` | Value of the `org.opencontainers.image.version` label |

The eBPF stage is the only part of the build that does not run on Alpine.
`bpf-linker` resolves the LLVM C API at runtime from the shared LLVM library
that ships with the Rust toolchain, and musl host toolchains link LLVM
statically into `librustc_driver` without exporting those symbols, so the linker
aborts with `unable to find LLVM shared lib`. The stage therefore uses the same
glibc toolchain as the CI job that builds the same artifact. Its only output is
a `bpfel-unknown-none` ELF object, which has no libc dependency, so the Alpine
stages consume it unchanged.

If `ebpf/rustinel-ebpf.o` is already present in the build context - from a
previous local build or downloaded from CI - the stage reuses it and skips the
nightly build entirely.

### Architectures

`linux/amd64` and `linux/arm64` are both supported, matching the Linux binaries
the release workflow publishes. The eBPF programs attach to stable
`syscalls:sys_enter_*`, `sched:*`, and `vfs_create` hooks rather than
architecture-specific `__x64_sys_*` symbols, and the compiled object is
architecture neutral, so the same object serves both.

A plain `docker build` produces an image for the machine it runs on. For a
manifest list covering both architectures:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
    -t ghcr.io/karib0u/rustinel:1.3.0 --push .
```

Cross-building this way runs the userspace stage under QEMU, which is slow for a
Rust build of this size. Building each architecture on a native machine and
joining the results is much faster:

```bash
# On an x86_64 machine and again on an arm64 machine
docker buildx build -t ghcr.io/karib0u/rustinel:1.3.0-$(uname -m) --push .

# Then, from either machine
docker buildx imagetools create -t ghcr.io/karib0u/rustinel:1.3.0 \
    ghcr.io/karib0u/rustinel:1.3.0-x86_64 \
    ghcr.io/karib0u/rustinel:1.3.0-aarch64
```

The eBPF stage and the runtime filesystem stage are pinned to the build platform
because their output does not depend on the target architecture, so neither is
ever emulated.

### Base Image

Alpine is the default because the musl binary it ships is the same artifact the
release workflow publishes for Linux, nothing in the agent needs glibc, and the
image carries far fewer packages than a glibc base - 18 against 80 in the Debian
variant - which is a smaller surface to track for CVEs.

A glibc image is available for environments whose policy requires one:

```bash
docker build --target runtime-debian -t rustinel:local-debian .
```

It behaves identically but is roughly twice the size - 130 MB against 56 MB -
and its binary is not the one the release workflow publishes, so prefer the
default target unless a policy says otherwise.

## Run

The compose file carries a working configuration:

```bash
docker compose up -d --build
docker compose logs -f
```

The equivalent `docker run`:

```bash
docker run -d --name rustinel \
  --pid host \
  --network host \
  --cap-add BPF \
  --cap-add PERFMON \
  --cap-add NET_ADMIN \
  --cap-add SYS_RESOURCE \
  --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH \
  --security-opt apparmor=unconfined \
  --ulimit memlock=-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /etc/passwd:/etc/passwd:ro \
  -v rustinel-logs:/var/log/rustinel \
  rustinel:local run
```

Verify the deployment:

```bash
docker exec rustinel rustinel doctor
whoami                                   # on the host, triggers the demo rule
docker exec rustinel cat /var/log/rustinel/alerts.json.$(date +%F)
```

`--privileged` also works and is simpler, but it grants far more than the sensor
needs. Prefer the explicit capability list.

## What Each Setting Is For

| Setting | Why it is needed |
| --- | --- |
| `--pid host` | Process enrichment reads `/proc/<pid>/exe` and `/proc/<pid>/cmdline` for the PIDs the kernel reports. Without it, almost every event loses its image path and command line. |
| `-v /sys/kernel/tracing` | Tracepoint and kprobe attachment. Use `/sys/kernel/debug/tracing` on hosts without the standalone `tracefs` mount. |
| `CAP_BPF`, `CAP_PERFMON` | Load and attach the eBPF programs. `CAP_SYS_ADMIN` or `--privileged` also covers this. |
| `CAP_NET_ADMIN` | Network program attachment and socket metadata lookups. |
| `CAP_SYS_RESOURCE`, `--ulimit memlock=-1` | Raise the memlock limit for eBPF maps on kernels that still account them. |
| `CAP_SYS_PTRACE` | Read `/proc/<pid>/exe` and `/proc/<pid>/cmdline` for processes owned by other users. |
| `CAP_DAC_READ_SEARCH` | Read files for YARA scanning and IOC hashing. |
| `--network host` | Keeps socket metadata lookups in the same network namespace as the observed traffic. |
| `--security-opt apparmor=unconfined` | The default Docker AppArmor profile blocks parts of `/proc` and `/sys` that enrichment needs. |
| `-v /etc/passwd:/etc/passwd:ro` | Resolves UIDs to host user names. Without it, `user.name` stays numeric. |

Kernel BTF is read from `/sys/kernel/btf/vmlinux`, which is already available
through the sysfs mount every container gets.

## Detection Scope

Process, network, and DNS telemetry is host-wide, because it is collected in the
kernel. File-content detection is not: YARA disk scans and IOC hashing open the
path reported by the event, and that path is resolved in the container's mount
namespace.

To scan host files, bind-mount the host directories you care about at the
**same** path inside the container:

```bash
  -v /home:/home:ro \
  -v /opt:/opt:ro \
  -v /srv:/srv:ro \
  -v /tmp:/tmp:ro
```

Paths that clash with the image's own filesystem, such as `/usr` and `/etc`,
cannot be remapped this way. `YARA worker scan failure` warnings in the log name
the paths the container could not open. If complete file-content coverage
matters more than container packaging, install Rustinel on the host with
`rustinel setup` instead - see [Operations](operations.md).

Active response is disabled in the container config. Terminating host processes
from a container requires `--pid host` and `CAP_KILL`, which is a deliberate
decision rather than a default.

## Image Layout

The image uses the managed Linux layout, so the agent and `rustinel doctor`
resolve everything without extra flags:

```text
/usr/local/bin/rustinel              # the agent
/usr/local/bin/rustinel-healthcheck  # HEALTHCHECK probe
/etc/rustinel/config.toml            # from docker/config.toml
/var/lib/rustinel/rules/current/     # sigma/, yara/, ioc/
/var/log/rustinel/                   # rustinel.log.<date>, alerts.json.<date>
```

Override any of them by bind-mounting over the path, for example
`-v ./my-config.toml:/etc/rustinel/config.toml:ro`, or per setting with `EDR__`
environment variables such as `EDR__LOGGING__LEVEL=debug`. See
[Configuration](configuration.md).

## Rules

The image only carries the demo rules that prove the pipeline works. Install a
real pack into the mounted rules volume:

```bash
docker exec rustinel rustinel rules list
docker exec rustinel rustinel rules install linux-essential
```

Hot reload is enabled, so the running agent picks up the new content without a
restart. Keep `/var/lib/rustinel/rules` on a named volume or a bind mount so
installed packs survive image upgrades.

## Operations

**Health.** `HEALTHCHECK` runs `rustinel doctor --json` and ignores the checks
that cannot hold in a container. `native_service` is ignored by default, since
the container runtime is the supervisor instead of systemd. Extend the list with
`RUSTINEL_HEALTHCHECK_IGNORE="native_service linux_tracefs"`.

**Shutdown.** The agent shuts down gracefully on `SIGINT`, so the image sets
`STOPSIGNAL SIGINT`. `docker stop` drains the workers and exits 0 in about a
second.

**Logs.** `rustinel run` streams to stdout, so `docker logs` works out of the
box, and the same records are written to `/var/log/rustinel`. Point a shipper at
that volume to forward alerts - see [SIEM Demos](siem-demos.md).

**Upgrades.** Rebuild the image and recreate the container. Configuration,
rules, and alerts live on mounts, so nothing is lost.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `eBPF sensor failed to start` | Missing capabilities, kernel older than 5.8, or no BTF. Run `docker exec rustinel rustinel doctor`. |
| `linux_tracefs: tracefs is not mounted` | `/sys/kernel/tracing` was not bind-mounted, or the host exposes it at `/sys/kernel/debug/tracing`. |
| Events have no command line or image path | The container is not running with `--pid host`. |
| `user.name` is a number | `/etc/passwd` is not mounted. |
| `YARA worker scan failure` | The scanned path only exists on the host. See [Detection Scope](#detection-scope). |
| Container is `unhealthy` | Run the probe directly: `docker exec rustinel rustinel-healthcheck`. |

More symptoms are covered in [Troubleshooting](troubleshooting.md).
