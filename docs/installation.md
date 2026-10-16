# Installation

## Requirements

| Platform | Version | Privileges | Also needs |
| --- | --- | --- | --- |
| Windows | 10, 11, Server 2016+ (x64) | Administrator | [Visual C++ Redistributable](https://aka.ms/vc14/vc_redist.x64.exe) (x64) |
| Linux | Kernel 5.8+ (x86_64, arm64) | root, or the [capabilities below](#linux-capabilities) | `tracefs` mounted; BTF for process identity and socket fields |
| macOS | 11+ (Intel, Apple Silicon) | root | Full Disk Access, see [macOS permissions](macos-permissions.md) |

macOS support is experimental.

### Linux capabilities

Without root, Rustinel needs `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, and `CAP_SYS_RESOURCE` to load and attach its eBPF programs.
Three more keep the rest working on processes and files of other users:

| Capability | Without it |
| --- | --- |
| `CAP_SYS_PTRACE` | `/proc` enrichment, such as `Image` and `CurrentDirectory` fallbacks, and memory scanning fail |
| `CAP_DAC_READ_SEARCH` | Executables in private folders, such as `/home`, are not hashed or YARA-scanned |
| `CAP_KILL` | Active response cannot kill processes |

The service that `rustinel setup` installs grants all seven, and `rustinel doctor` checks them as `linux_service_capabilities`.

## Install script

The scripts download the latest published release into a folder by default.
They never build from source or change system settings.

=== "Linux and macOS"

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh
    ```

    | Option | Default | Effect |
    | --- | --- | --- |
    | `--dir PATH` | `./rustinel` | Install folder |
    | `--version VERSION` | latest | Release to install |
    | `--run` | off | Start Rustinel after installing |
    | `--force` | off | Replace an existing install folder |

    `RUSTINEL_INSTALL_DIR` and `RUSTINEL_VERSION` set the same defaults from the environment.

    To read the script first: `curl -fsSLO https://rustinel.io/install.sh`.

=== "Windows"

    ```powershell
    irm https://rustinel.io/install.ps1 | iex
    ```

    | Environment variable | Default | Effect |
    | --- | --- | --- |
    | `RUSTINEL_INSTALL_DIR` | `./rustinel` | Install folder |
    | `RUSTINEL_VERSION` | latest | Release to install |
    | `RUSTINEL_RUN` | off | Start Rustinel after installing |
    | `RUSTINEL_FORCE` | off | Replace an existing install folder |

The folder contains the binary, a default `config.toml`, demo rules, and the SIEM examples.
It has no `logs/` folder: the first elevated run creates it, see [Quickstart](getting-started.md#2-start-rustinel).
On macOS the binary is inside a signed `Rustinel.app` with a `rustinel` symlink next to it.

## Manual download

Archives for every platform are on [GitHub Releases](https://github.com/Karib0u/rustinel/releases).
Each release publishes SHA-256 checksums.

## Nix

The flake packages the prebuilt Linux release binary (`x86_64-linux`, `aarch64-linux`):

```bash
nix run github:Karib0u/rustinel -- --version
```

- The overlay `rustinel.overlays.default` provides `pkgs.rustinel`.
- There is no NixOS module.
  Write the systemd unit yourself, or run `rustinel setup`.
- Rules in the Nix store are read-only.
  To use `rustinel rules install`, create `/etc/rustinel/config.toml` or set `RUSTINEL_CONFIG` to a writable config.

## From source

See [Development](development.md).

## Next steps

- [Quickstart](getting-started.md): trigger a first alert.
- [Deploy on an endpoint](operations.md): install the service and a rules pack.
