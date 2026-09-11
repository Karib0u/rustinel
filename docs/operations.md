# Run as a service

`rustinel setup` turns a downloaded release into a permanent install: managed paths, a rules pack, and a native service that starts at boot.

## Set up

Run it from the install folder:

=== "Linux and macOS"

    ```bash
    sudo ./rustinel setup --yes
    ./rustinel doctor
    ```

=== "Windows"

    In an elevated PowerShell:

    ```powershell
    .\rustinel.exe setup --yes
    .\rustinel.exe doctor
    ```

`setup` writes the managed configuration, installs the Essential rules pack, copies the binary, makes `rustinel` available as a command, registers the service, starts it, and runs `doctor`.

- `--pack advanced` installs the larger pack.
- `--no-start` registers the service without starting it.
- An existing managed configuration is kept.
  `--force` replaces it.

On macOS, grant Full Disk Access to `/usr/local/var/rustinel/Rustinel.app` before the service starts.
See [macOS permissions](macos-permissions.md).

## Managed paths

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Service | SCM | systemd | launchd |
| Binary | `C:\Program Files\Rustinel\rustinel.exe` | `/opt/rustinel/rustinel` | `/usr/local/var/rustinel/Rustinel.app` |
| Config | `C:\ProgramData\Rustinel\config.toml` | `/etc/rustinel/config.toml` | `/Library/Application Support/Rustinel/config.toml` |
| Rules | `C:\ProgramData\Rustinel\rules` | `/var/lib/rustinel/rules` | `/Library/Application Support/Rustinel/rules` |
| Logs and alerts | `C:\ProgramData\Rustinel\logs` | `/var/log/rustinel` | `/Library/Logs/Rustinel` |
| Recordings | `C:\ProgramData\Rustinel\captures` | `/var/lib/rustinel/captures` | `/Library/Application Support/Rustinel/captures` |

When the managed config exists, every `rustinel` command uses it.

## The `rustinel` command

After setup, `rustinel` runs the managed binary from any folder:

- **Linux and macOS:** setup links `/usr/local/bin/rustinel` to the managed binary.
- **Windows:** setup adds `C:\Program Files\Rustinel` to the system `PATH`.
  Open a new terminal to pick it up.

If something named `rustinel` is already there, setup leaves it alone and says so in its summary.
If `sudo rustinel` reports "command not found", your sudo `secure_path` does not include `/usr/local/bin`: run `sudo /usr/local/bin/rustinel` instead.

## Manage the service

```bash
rustinel service status     # not-installed, stopped, starting, running, failed, unknown
rustinel service restart
rustinel service stop
rustinel service start
rustinel service uninstall  # keeps config, rules, and logs
```

Use `sudo` on Linux and macOS, and an elevated shell on Windows, for every action except `status`.

The service definitions are:

- **Linux:** `/etc/systemd/system/rustinel.service`.
  Read it with `systemctl cat rustinel`.
- **macOS:** `/Library/LaunchDaemons/com.rustinel.agent.plist`.
- **Windows:** the `Rustinel` service in the Service Control Manager.

## Check it is healthy

```bash
rustinel doctor
```

`doctor` exits `0` when every check passes, `1` on warnings, and `2` on failures.
Each check is explained in [Doctor checks](doctor.md).

## Without setup

You can also run the release folder under your own supervisor.
Keep the binary, `config.toml`, rules, and logs together, and start it with `rustinel run --config <absolute path to config.toml> --no-console`.
Relative paths in the file resolve from the file's folder, so the working directory does not matter.
See [Configuration](configuration.md#which-file-is-used).

## Next steps

- [Manage rule packs](rule-packs.md)
- [Upgrade](upgrade.md)
- [Send alerts to a SIEM](siem-demos.md)
