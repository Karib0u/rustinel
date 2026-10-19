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

It downloads the release for this OS and architecture from GitHub Releases, checks its signature and checksum, and replaces the executable it was started from.
A missing or invalid signature stops the update before anything is replaced, see [Downloads](security.md#downloads).
After setup, `rustinel` is the managed binary, so that is the one replaced.
If the installed version is already the latest, it does nothing.
It never restarts anything for you.

## What changes in alerts

Alerts with `edr.rule.engine: "Agent"` and `event.dataset: "edr.agent"` come from the agent, not from a rule.
Besides [sensor loss](output.md#sensor-loss-alerts), the agent now writes [`agent::lifecycle::stopping` and `agent::lifecycle::unclean_shutdown`](agent-health.md#lifecycle-alerts), and a [heartbeat file](agent-health.md#heartbeat), `heartbeat.json.<date>`, in the log directory.
Filters that assume every alert is a detection should exclude the `Agent` engine.
The first start after the upgrade writes no `unclean_shutdown`, because the previous version left no run-state file.

## After upgrading

```bash
rustinel doctor
```

Then trigger a known rule, such as the demo `whoami` rule, and check that the alert arrives.
