# FAQ

### Does Rustinel send data anywhere?

No.
The agent collects and evaluates locally and needs no account.
Network access happens only when you ask for it: the install scripts, `rustinel update`, and `rustinel setup` or `rustinel rules` downloading packs.

### Do I need Administrator or root?

Yes, to collect telemetry.
`rustinel replay` needs no privileges.
See [Requirements](installation.md#requirements).

### Why can't I read the alert file?

On Linux and macOS, the log folder is readable by root only.
Use `sudo`, or run your log shipper as root.

### Why is Rustinel looking in the wrong folder?

Relative paths in `config.toml` resolve from the folder containing that file, and a managed config from `rustinel setup` takes priority over a local one.
`rustinel doctor` shows which file was used.
See [Which file is used](configuration.md#which-file-is-used).

### Can I turn off Sigma, YARA, or IOC separately?

Yes: `scanner.sigma_enabled`, `scanner.yara_enabled`, and `ioc.enabled`.

### What changes apply without a restart?

Rule and indicator files, and the `[response]` section of the config.
See [What reloads](configuration.md#what-reloads).

### Why do I see fewer alerts than events?

Identical alerts are collapsed for 60 seconds.
Sum `event.count` for the real volume, see [Deduplication](detection.md#deduplication).

### Does Rustinel send alerts to my SIEM?

It writes files.
A shipper such as Filebeat forwards them, see [Send alerts to a SIEM](siem-demos.md).

### Can I use SigmaHQ rules?

Yes, but many are written for Windows telemetry.
See [Platform coverage](coverage.md) before loading a large set on Linux or macOS.
