# macOS permissions

macOS support is experimental.
Rustinel uses Apple's Endpoint Security framework, which needs three things:

1. **Root.**
   Run with `sudo`, or as a LaunchDaemon.
2. **A signed app with the Endpoint Security entitlement.**
   Release archives ship a signed and notarized `Rustinel.app`.
   Keep the whole bundle together: replacing only the binary inside it breaks the signature.
3. **Full Disk Access**, granted once in System Settings.

## Grant Full Disk Access

Open *System Settings > Privacy & Security > Full Disk Access*.

- **Running from a terminal with `sudo`:** add your terminal app (Terminal, iTerm, Ghostty, and so on), then quit and reopen it. macOS attributes the permission to the terminal, so Rustinel does not appear in the list.
- **Running as a service:** add `/usr/local/var/rustinel/Rustinel.app`, the bundle `rustinel setup` installs.
  On managed Macs, deploy a PPPC profile instead.

Install into a stable folder first. macOS may not keep the approval for an app started from a temporary path such as `/tmp`.

## Start-up errors

If Endpoint Security refuses the client, the error ends with one of these codes:

| Code | Cause | Fix |
| --- | --- | --- |
| `NotPrivileged` | Not running as root | Run with `sudo` |
| `NotPermitted` | Full Disk Access not granted | Grant it as above, then restart the terminal or service |
| `NotEntitled` | Binary not signed with the entitlement | Run the release `Rustinel.app`, not a copied binary |

`NotPermitted` on the first run is normal: it means signing is fine and only the approval is missing.

`rustinel doctor` checks these as `macos_endpoint_security`, `macos_full_disk_access`, and `macos_app_location`.

## Network and DNS

Network and DNS events come from packet capture on `/dev/bpf*`, which needs root.
Rustinel captures on every interface that is up when it starts.
If capture cannot start, Rustinel logs a warning and keeps collecting process and file events.

To limit capture to some interfaces, set `RUSTINEL_BPF_INTERFACE` to a comma-separated list such as `en0,utun0`.

## Build and sign your own bundle

See [Development](development.md#macos).
