# Installation

## Requirements

| Platform | Version | Privileges | Also needs |
| --- | --- | --- | --- |
| Windows | 10, 11, Server 2016+ (x64) | Administrator | [Visual C++ Redistributable](https://aka.ms/vc14/vc_redist.x64.exe) (x64) |
| Linux | Kernel 5.8+ (x86_64, arm64) | root, or `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, and `CAP_SYS_RESOURCE` | `tracefs` mounted; BTF for process identity and socket fields |
| macOS | 11+ (Intel, Apple Silicon) | root | Full Disk Access, see [macOS permissions](macos-permissions.md) |

macOS support is experimental.

## Install script

The scripts download a published release into a folder.
They never build from source or change system settings.

=== "Linux and macOS"

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh
    ```

    Pass options after `sh -s --`:

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh -s -- --dir /opt/rustinel --version 1.6.0
    ```

    | Option | Default | Effect |
    | --- | --- | --- |
    | `--dir PATH` | `./rustinel` | Install folder |
    | `--version VERSION` | latest | Release to install |
    | `--run` | off | Start Rustinel after installing |
    | `--force` | off | Replace an existing install folder |

    To read the script first: `curl -fsSLO https://rustinel.io/install.sh`.

=== "Windows"

    ```powershell
    irm https://rustinel.io/install.ps1 | iex
    ```

    Set options with environment variables before running it:

    ```powershell
    $env:RUSTINEL_VERSION = "1.6.0"
    $env:RUSTINEL_INSTALL_DIR = "C:\Rustinel"
    irm https://rustinel.io/install.ps1 | iex
    ```

    Or download it and pass parameters: `.\install.ps1 -InstallDir C:\Rustinel -Version 1.6.0 [-Run] [-Force]`.

The folder contains the binary, a default `config.toml`, demo rules, and an empty `logs/` folder.
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
- [Run as a service](operations.md): install the service and a rules pack.
