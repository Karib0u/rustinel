# Quickstart

Install Rustinel into a local folder, run it, and trigger the bundled demo rule.
Nothing is installed system-wide.

## 1. Install

=== "Linux"

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh
    ```

=== "Windows"

    In an elevated PowerShell:

    ```powershell
    irm https://rustinel.io/install.ps1 | iex
    ```

=== "macOS"

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh
    ```

    Before the first run, grant Full Disk Access to your terminal app, then quit and reopen it ([why](macos-permissions.md)).

The script downloads the latest release into a `rustinel` folder.
If something fails, check the [requirements](installation.md#requirements).

## 2. Start Rustinel

=== "Linux and macOS"

    ```bash
    cd rustinel
    sudo ./rustinel run
    ```

=== "Windows"

    ```powershell
    Set-Location rustinel
    .\rustinel.exe run
    ```

## 3. Trigger the demo rule

In a second terminal:

```bash
whoami
```

Rustinel prints the detection in its console.

## 4. Read the alert

Alerts are written to `logs/alerts.json.<date>` inside the install folder:

=== "Linux and macOS"

    The log folder is readable by root only:

    ```bash
    sudo sh -c 'cat rustinel/logs/alerts.json.*'
    ```

=== "Windows"

    ```powershell
    Get-Content .\rustinel\logs\alerts.json.*
    ```

Each line is one alert in [ECS format](output.md).

No alert?
Run `sudo ./rustinel doctor` (`.\rustinel.exe doctor` on Windows) and see [Troubleshooting](troubleshooting.md#no-alerts).

## Next steps

- [Run as a service](operations.md) to keep Rustinel running with a real rules pack.
- [Write and test rules](rule-development.md) to add your own detections.
- [Send alerts to a SIEM](siem-demos.md) to forward them.
