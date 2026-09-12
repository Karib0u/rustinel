# Upgrade

`rustinel update` replaces the binary with the latest release.
Configuration, rules, logs, and recordings are kept.
Rule packs are updated separately, see [Manage rule packs](rule-packs.md).

## Managed install

=== "Linux and macOS"

    ```bash
    sudo rustinel update
    sudo rustinel service restart
    ```

    On macOS, the whole signed `Rustinel.app` is replaced, so Full Disk Access stays granted.

=== "Windows"

    In an elevated PowerShell:

    ```powershell
    rustinel update
    rustinel service restart
    ```

If the running service blocks the replacement, run `rustinel service stop`, then `rustinel update`, then `rustinel service start`.

## Release folder

Run `update` from the folder, then restart Rustinel:

```bash
sudo ./rustinel update
```

## What `update` does

It downloads the archive for this OS and architecture from GitHub Releases, verifies its SHA-256 checksum, and replaces the executable it was started from.
After setup, `rustinel` is the managed binary, so that is the one replaced.
If the installed version is already the latest, it does nothing.
It never restarts anything for you.

## After upgrading

```bash
rustinel doctor
```

Then trigger a known rule, such as the demo `whoami` rule, and check that the alert arrives.
