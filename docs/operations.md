# Deploy on an endpoint

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
  If the service is already running, setup leaves it running.
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
On Linux and macOS, a managed stop drains queued work and writes the final `telemetry.json` snapshot before exiting.
The service manager allows up to 30 seconds for shutdown.

The service definitions are:

- **Linux:** `/etc/systemd/system/rustinel.service`.
  Read it with `systemctl cat rustinel`.
- **macOS:** `/Library/LaunchDaemons/com.rustinel.agent.plist`.
- **Windows:** the `Rustinel` service in the Service Control Manager.

## Sensor callback failures

Release builds terminate the whole agent if a sensor callback panics.
The managed service restarts it using systemd, launchd, or Windows service recovery; a foreground run needs to be started again by its operator or supervisor.
An abort does not drain queues or write a final telemetry snapshot, so buffered events and alerts can be lost.

Development builds and tests, including tests run with `--release`, use unwinding:

| Callback | Panic behavior with unwinding |
| --- | --- |
| macOS Endpoint Security | Logs the panic, drops that event, and continues receiving events |
| Windows Event Log | Marks the affected channel failed and ignores later deliveries; the subscription worker propagates the failure, stops the Windows sensor, and the agent exits for service recovery |
| Windows ETW, including classic process and file rundown | The native callback guard catches the panic and exits the whole process with status 1 |

Malformed Event Log records return decode errors, increment `decode_errors`, and allow later records to continue.
Malformed or unsupported Endpoint Security and ETW events are skipped by their decoders; an unexpected panic follows the policy above.

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
- [Forward alerts](siem-demos.md)
