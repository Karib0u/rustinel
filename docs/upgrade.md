# Upgrade

`rustinel update` replaces the binary with the latest release.
Configuration, rules, logs, and recordings are kept.
Rule packs are updated separately, see [Manage rule packs](rule-packs.md).

## Windows path trust change

From v1.9.0, the default trusted paths under `C:\Windows\` are limited to `System32`, `SysWOW64`, and `WinSxS`. Known writable subfolders are excluded even when a broader trusted path is configured. Executables in `C:\Windows\Temp\`, `Tasks`, and `Tracing` are now eligible for YARA scanning, IOC hashing, and active response. Check `rustinel doctor` for the effective exclusions. To change them, set `allowlist.excluded_paths` in the configuration.

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

It downloads the archive for this OS and architecture from GitHub Releases, verifies the checksum file's Minisign signature with the public key built into Rustinel, checks the archive's SHA-256 checksum, and replaces the executable it was started from.
Missing or invalid signatures stop the update before extraction or replacement.
On macOS, the replacement app must also be signed by Apple Developer Team `37TYDYTJ3M`.
After setup, `rustinel` is the managed binary, so that is the one replaced.
If the installed version is already the latest, it does nothing.
It never restarts anything for you.

## Verify a release manually

Download the archive, its `rustinel-<version>-checksums-sha256.txt` file, and the matching `.minisig` file from the same release.
From the directory containing those files, run:

```bash
minisign -Vm rustinel-<version>-checksums-sha256.txt -p release-minisign.pub
sha256sum -c --ignore-missing rustinel-<version>-checksums-sha256.txt
```

Get [release-minisign.pub](https://github.com/Karib0u/rustinel/blob/main/release-minisign.pub) from the source repository.
On macOS, select the downloaded archive's line from the checksum file and pipe it to `shasum -a 256 -c -`.
To verify the rules catalog, download `index.json` and `index.json.minisig` from the same rules release and run `minisign -Vm index.json -p release-minisign.pub`.

The signing key is configured as `RELEASE_MINISIGN_KEY` in both release repositories.
During an authorized key rotation, update the embedded public key and both repository secrets together before publishing another release.
Existing binaries trust only the old key, so publish a transition release that trusts both keys first or require a manual install after rotation.
If the Apple signing team changes, update the pinned Team ID in the updater and macOS release validation in the same change, then publish a release signed by the existing Minisign key so installed clients can authenticate it.

## After upgrading

```bash
rustinel doctor
```

Then trigger a known rule, such as the demo `whoami` rule, and check that the alert arrives.
