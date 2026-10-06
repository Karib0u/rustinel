# Security model

What Rustinel protects, what it trusts, and what it does not defend against.
To report a vulnerability, see [SECURITY.md](https://github.com/Karib0u/rustinel/blob/main/SECURITY.md).

## Scope

Rustinel detects and reports.
It is not a replacement for a commercial EDR:

- No kernel self-protection or anti-tamper.
  A privileged attacker can stop the ETW trace, unload the eBPF programs, or kill the agent.
- No pre-execution blocking.
  [Active response](active-response.md) kills a process after its event was processed, so the process may already have done its work.
- No quarantine, file deletion, network isolation, or rollback.
- No management console.

## Network

The agent collects and evaluates locally and needs no account.
It connects out only when you ask it to:

| Action | Connects to |
| --- | --- |
| Install scripts, `rustinel update` | GitHub Releases |
| `rustinel setup`, `rustinel rules` | GitHub Releases of [rustinel-rules](https://github.com/Karib0u/rustinel-rules), or your `--catalog-url` |
| [Webhooks](output.md#webhooks) | The endpoints you configure |

## Downloads

`rustinel update` and `rustinel rules` accept only files signed with the Rustinel release key, which is built into the binary.
A missing or invalid signature stops the command before anything is replaced.

- `update` checks the Minisign signature of the release's checksum file, then the archive's SHA-256.
  On macOS the new `Rustinel.app` must also be signed by Apple Developer Team `37TYDYTJ3M`.
- `rules` checks the signature of the rules catalog, then each pack's SHA-256 against the catalog.
  `--catalog-url` must be a github.com release asset signed with the same key, such as a specific [rustinel-rules](https://github.com/Karib0u/rustinel-rules) release.

### Verify a release manually

Download the archive, its `rustinel-<version>-checksums-sha256.txt` file, and the matching `.minisig` file from the same release, and get [release-minisign.pub](https://github.com/Karib0u/rustinel/blob/main/release-minisign.pub) from the source repository.
From the folder containing them:

```bash
minisign -Vm rustinel-<version>-checksums-sha256.txt -p release-minisign.pub
sha256sum -c --ignore-missing rustinel-<version>-checksums-sha256.txt
```

On macOS, pipe the archive's line from the checksum file to `shasum -a 256 -c -` instead of `sha256sum`.
To verify a rules catalog, download `index.json` and `index.json.minisig` from the same rules release and run `minisign -Vm index.json -p release-minisign.pub`.

## Input trust

Rustinel runs privileged and acts on what it loads: a Sigma filter suppresses alerts, and the config file drives active response.
At startup and on every reload, it refuses the config file, the Sigma and YARA rule folders, and the IOC files when an untrusted account can change them.
The default policy below can be extended for an explicitly configured [integration](#integration-access).

- No account other than the owner, root, SYSTEM, or Administrators may be able to write any file or folder in the input.
- On Linux and macOS this means no group or other write bit, unless the group is root's own or the owner's private group with no other members.
  It applies to every parent folder too, except a world-writable parent with the sticky bit such as `/tmp`.
- On Windows it means no allow entry that grants write, delete, or permission changes to any other account.
- Under the managed layout that `rustinel setup` creates, inputs must also be owned by root, SYSTEM, Administrators, or the agent's account, and must not contain links.
  Elsewhere, such as a folder extracted for `sudo ./rustinel run`, any owner is accepted and links are followed and checked.

A refused rule or IOC input is skipped at startup, with a console message, and a refused reload keeps the previous rules.
An untrusted config file stops startup.
`rustinel doctor` reports refusals under `sigma_rules_parse`, `yara_rules_parse`, and `ioc_inputs_trust`.

To fix a refused input, remove write access for other accounts, for example `chmod -R go-w <path>`, or rerun `rustinel setup` for the managed layout.

## Files Rustinel writes

On Linux and macOS, new log, alert, and recording folders default to owner-only access (`0700`), and their files to `0600`.
Existing output directory permissions are preserved.
A non-root log shipper can use the explicit integration access described below.

Recordings contain command lines, paths, network destinations, and user names.
Handle them like the host's logs.

Webhook header values, `secret`, and URL paths are treated as credentials and never logged.
Keep the config file readable only by the agent.

## Integration access

An integration agent can update the config and read logs without running as root, SYSTEM, or Administrator, and without changing the service definition.
The Rustinel service keeps its privileges; the integration stays unprivileged.
Add the following to the existing configuration, naming a group or account that already exists:

```toml
[security]
integration_group = "rustinel-integration"
```

The administrator's filesystem permissions remain the authority for delegation, even though the option is in the writable file.
Rustinel never grants access itself, and the option cannot be enabled or changed through an environment override.

The integration can edit the config in place, but cannot rename or replace it through the protected parent folder.
Config write access delegates control over the entire configuration, including detection, response, output destinations, and credentials.
Treat it as root-equivalent: the integration can point inputs at files only Rustinel can read and see their contents in log diagnostics, and can make active response act on any process.
Use a dedicated group or account containing only trusted integration accounts.
Log access is read-only: forwarding logs does not require permission to modify or delete the originals.

### Linux and macOS

The config must be a root-owned regular file, assigned to this group, with no access for others and no hard links or symlinks.
Its parent directories must remain root-owned and not writable by the integration group or by others, unless sticky.
The group setting must match the file's existing filesystem group, so naming another group refuses the config.

For the managed Linux layout, an administrator can prepare access with:

```sh
chown root:rustinel-integration /etc/rustinel /etc/rustinel/config.toml
chmod 0750 /etc/rustinel
chmod 0660 /etc/rustinel/config.toml
install -d -o root -g rustinel-integration -m 2750 /var/log/rustinel
chgrp rustinel-integration /var/log/rustinel/*
```

The integration account must belong to this group.
Use the corresponding configured paths on macOS or for custom layouts.
Prepare both logging and alerts directories if they differ.
Log directories must already exist, be root-owned with this group, have the setgid bit, and allow group read and traverse but no group write or other access (`2750`).
The setgid bit gives new files the group: the managed systemd service has no `CAP_CHOWN` and cannot assign it.
For the same reason, change the group of existing log files once, as above, or Rustinel refuses to reopen them.
Current and newly rotated operational and alert logs receive `0640` and the selected group.
Older files are not changed; grant read access to those separately if needed.
Recordings and telemetry snapshots retain their existing private permissions.

### Windows

On Windows, `integration_group` names the account the integration runs as, usually its service SID, or a dedicated local or domain group.
Use a literal TOML string so the backslash is kept:

```toml
[security]
integration_group = 'NT SERVICE\ExampleAgent'
```

The config must be a regular file owned by SYSTEM, Administrators, or TrustedInstaller.
Only those accounts, the file's owner, and the named principal may have write access to it.
Naming another principal leaves the existing grant untrusted, so the config is refused.
Each parent folder must be owned by one of those accounts, must not be a link, and must not give any other account full control, delete-child, or permission-change rights.
Shared principals are refused: Everyone, Users, Guests, Authenticated Users, Interactive, Network, Local, Anonymous, `NT AUTHORITY\SERVICE`, and the Local Service and Network Service accounts.

An administrator can grant config write and log read access with:

```powershell
icacls "C:\Program Files\Example\config.toml" /grant "NT SERVICE\ExampleAgent:(R,W)"
icacls "C:\Program Files\Example\logs" /grant "NT SERVICE\ExampleAgent:(OI)(CI)RX"
```

Rustinel does not change permissions on log files it creates, so new and rotated logs inherit the read grant from their folder.
`rustinel setup` resets permissions under the managed `C:\ProgramData\Rustinel` tree, so reapply integration grants there after each setup or upgrade.

### Optional rules updates

Config access alone does not permit integration-writable detection inputs.
To also delegate rule updates, explicitly name one absolute directory:

```toml
[security]
integration_group = "rustinel-integration"
integration_rules_directory = "/var/lib/rustinel/rules"
```

The group can then create, edit, rename, and delete rule files and subdirectories within this tree.
Sigma, YARA, and IOC inputs inside it accept files created by the integration account, including on reload.
Links are refused.
Inputs outside this directory retain the normal trust policy.
Delegating rules updates allows the integration to change or suppress detections; only enable it for a trusted rule manager.

On Linux and macOS, that directory must be root-owned, assigned to the integration group, have the setgid bit, and have no access for others.
Its parents must remain root-controlled.
Files must belong to the selected group, or remain root-owned without group or other write access.
Hard-linked files, special files, and world-writable entries are refused.
For an existing managed Linux rule tree, an administrator can prepare it with:

```sh
chown root:rustinel-integration /var/lib/rustinel/rules
chgrp -R rustinel-integration /var/lib/rustinel/rules
chmod -R g+rwX,o-rwx /var/lib/rustinel/rules
find /var/lib/rustinel/rules -type d -exec chmod g+s {} +
```

On Windows, the directory follows the config rules above, and files inside it may also be owned by the named principal.
Remove inherited grants so no other account can write the tree:

```powershell
icacls "C:\Program Files\Example\rules" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" "NT SERVICE\ExampleAgent:(OI)(CI)M"
```

Restart Rustinel after changing either security option; hot reload updates active-response settings and rule contents, not the running process's integration policy.
Normal `rustinel setup` preserves a valid existing config.
`rustinel setup --force` replaces the config with private defaults, so reapply integration settings and permissions afterward.
