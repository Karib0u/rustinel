# Rustinel container image.
#
# Stage 1 builds the Linux eBPF object with the pinned nightly toolchain and
# bpf-linker, stage 2 builds the statically linked musl userspace binary, and
# the final stage assembles a minimal Alpine runtime that uses the managed Linux
# layout (/etc/rustinel, /var/lib/rustinel, /var/log/rustinel).
#
# Alpine is the default because the musl binary it ships is the same artifact
# the release workflow publishes for Linux. A glibc/Debian variant is available
# for environments whose policy requires it.
#
# linux/amd64 and linux/arm64 are both supported, matching the released Linux
# binaries.
#
# Build:  docker build -t rustinel:local .
#         docker build --target runtime-debian -t rustinel:local-debian .
#         docker buildx build --platform linux/amd64,linux/arm64 -t rustinel:local .
# Run:    see docker-compose.yml or docs/docker.md

ARG ALPINE_VERSION=3.22
ARG RUST_VERSION=1.97
ARG DEBIAN_SUITE=trixie

# ---------------------------------------------------------------------------
# Stage 1 - eBPF object
#
# This is the one stage that cannot run on Alpine. bpf-linker resolves the LLVM
# C API at runtime from the shared LLVM library that ships with the Rust
# toolchain, and the musl host toolchains link LLVM statically into
# librustc_driver without exporting those symbols, so the linker aborts with
# "unable to find LLVM shared lib". A glibc toolchain is used here to match the
# CI job that produces the same artifact.
#
# The output is a bpfel-unknown-none ELF object with no libc dependency, and it
# is architecture neutral - the release workflow builds it once and feeds the
# same artifact to both the x86_64 and arm64 jobs. It is therefore pinned to the
# build platform so a cross-platform build never emulates this stage.
# ---------------------------------------------------------------------------
FROM --platform=${BUILDPLATFORM} rust:${RUST_VERSION}-slim-${DEBIAN_SUITE} AS ebpf-builder

# bpf-linker links against a specific LLVM, so it has to match the LLVM the
# nightly toolchain ships. Both pins move together - bumping one without the
# other breaks this stage. Keep them in sync with .github/workflows/ci.yml.
ARG NIGHTLY_TOOLCHAIN=nightly-2026-08-11
ARG BPF_LINKER_VERSION=0.10.4

RUN rustup toolchain install "${NIGHTLY_TOOLCHAIN}" --profile minimal --component rust-src

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo "+${NIGHTLY_TOOLCHAIN}" install bpf-linker --version "${BPF_LINKER_VERSION}" --locked

WORKDIR /src
COPY ebpf/ ebpf/

# Reuse a prebuilt object when the build context already carries one (CI
# artifact or a prior local build); otherwise compile it from source.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/ebpf/target,sharing=locked \
    if [ -f ebpf/rustinel-ebpf.o ]; then \
        echo "Using prebuilt ebpf/rustinel-ebpf.o from the build context"; \
    else \
        cd ebpf && \
        cargo "+${NIGHTLY_TOOLCHAIN}" build --release --bin rustinel-ebpf && \
        cp target/bpfel-unknown-none/release/rustinel-ebpf rustinel-ebpf.o; \
    fi

# ---------------------------------------------------------------------------
# Stage 2 - userspace binary (musl, default)
#
# Built for the target platform, so a cross-platform build runs this stage
# under emulation. Building each platform on a native machine and joining the
# results into a manifest list is much faster - see docs/docker.md.
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS builder

# Matches the release workflow, which ships musl binaries built with the
# RSigma backend enabled.
ARG CARGO_FEATURES=rsigma-engine

# Cargo writes every platform to target/release, so the cache mount is keyed by
# target platform to keep concurrent multi-platform builds apart.
ARG TARGETPLATFORM

# ring, wasmtime (YARA-X JIT) and tree-sitter need a C toolchain and musl headers.
RUN apk add --no-cache build-base

WORKDIR /src
COPY . .

# build.rs embeds this object instead of invoking the nightly eBPF build.
COPY --from=ebpf-builder /src/ebpf/rustinel-ebpf.o ebpf/rustinel-ebpf.o

# The target directory is a cache mount, so the binary is copied out inside the
# same RUN layer.
RUN --mount=type=cache,id=rustinel-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=rustinel-target-musl-${TARGETPLATFORM},target=/src/target,sharing=locked \
    cargo build --locked --release --features "${CARGO_FEATURES}" && \
    install -Dm755 target/release/rustinel /out/rustinel && \
    /out/rustinel --version

# ---------------------------------------------------------------------------
# Stage 3 - glibc userspace binary (Debian variant only)
#
# Only used by the `runtime-debian` target. `docker build` without --target does
# not reach this stage and never builds it.
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_SUITE} AS builder-glibc

ARG CARGO_FEATURES=rsigma-engine
ARG TARGETPLATFORM

WORKDIR /src
COPY . .
COPY --from=ebpf-builder /src/ebpf/rustinel-ebpf.o ebpf/rustinel-ebpf.o

RUN --mount=type=cache,id=rustinel-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=rustinel-target-gnu-${TARGETPLATFORM},target=/src/target,sharing=locked \
    cargo build --locked --release --features "${CARGO_FEATURES}" && \
    install -Dm755 target/release/rustinel /out/rustinel && \
    /out/rustinel --version

# ---------------------------------------------------------------------------
# Stage 4 - runtime filesystem
#
# Everything except the binary, so both runtime images stay identical and
# cannot drift apart. The content is architecture neutral, so this runs on the
# build platform.
# ---------------------------------------------------------------------------
FROM --platform=${BUILDPLATFORM} alpine:${ALPINE_VERSION} AS layout

COPY docker/healthcheck.sh /rootfs/usr/local/bin/rustinel-healthcheck

# Managed Linux layout, so `rustinel doctor` and the default config resolution
# find everything without extra flags.
COPY docker/config.toml /rootfs/etc/rustinel/config.toml
COPY rules/sigma/ /rootfs/var/lib/rustinel/rules/current/sigma/
COPY rules/yara/ /rootfs/var/lib/rustinel/rules/current/yara/
COPY rules/ioc/ /rootfs/var/lib/rustinel/rules/current/ioc/
RUN mkdir -p /rootfs/var/log/rustinel && \
    chmod 755 /rootfs/usr/local/bin/rustinel-healthcheck

# ---------------------------------------------------------------------------
# Stage 5 - Debian runtime (opt-in: --target runtime-debian)
#
# For environments that require a glibc base. It is larger and carries more
# packages than the Alpine image, and its binary is not the one the release
# workflow publishes, so prefer the default target unless policy says otherwise.
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_SUITE}-slim AS runtime-debian

ARG DEBIAN_SUITE
ARG VERSION=1.3.0

LABEL org.opencontainers.image.title="Rustinel" \
      org.opencontainers.image.description="Open-source endpoint detection with Sigma, YARA, and IOC detection" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/Karib0u/rustinel" \
      org.opencontainers.image.documentation="https://docs.rustinel.io/docker/" \
      org.opencontainers.image.base.name="docker.io/library/debian:${DEBIAN_SUITE}-slim"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder-glibc /out/rustinel /usr/local/bin/rustinel
COPY --from=layout /rootfs/ /

WORKDIR /var/lib/rustinel

STOPSIGNAL SIGINT

HEALTHCHECK --interval=60s --timeout=15s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/rustinel-healthcheck"]

ENTRYPOINT ["/usr/local/bin/rustinel"]
CMD ["run"]

# ---------------------------------------------------------------------------
# Stage 6 - Alpine runtime (default target, must stay last)
# ---------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS runtime

ARG ALPINE_VERSION
ARG VERSION=1.3.0

LABEL org.opencontainers.image.title="Rustinel" \
      org.opencontainers.image.description="Open-source endpoint detection with Sigma, YARA, and IOC detection" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/Karib0u/rustinel" \
      org.opencontainers.image.documentation="https://docs.rustinel.io/docker/" \
      org.opencontainers.image.base.name="docker.io/library/alpine:${ALPINE_VERSION}"

# ca-certificates: rules catalog downloads over HTTPS (`rustinel rules install`).
# tzdata: correct local dates for the daily log and alert file rotation.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/rustinel /usr/local/bin/rustinel
COPY --from=layout /rootfs/ /

WORKDIR /var/lib/rustinel

# The agent shuts down gracefully on SIGINT; SIGTERM is not handled.
STOPSIGNAL SIGINT

# `rustinel doctor` minus the checks that cannot hold in a container.
HEALTHCHECK --interval=60s --timeout=15s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/rustinel-healthcheck"]

ENTRYPOINT ["/usr/local/bin/rustinel"]
CMD ["run"]
