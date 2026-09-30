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
At startup and on every reload, it refuses the config file, the Sigma and YARA rule folders, and the IOC files when another account can change them.

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

On Linux and macOS, the log, alert, and recording folders are readable by their owner only (`0700`), and their files `0600`.
Log shippers must run as that owner, usually root.

Recordings contain command lines, paths, network destinations, and user names.
Handle them like the host's logs.

Webhook header values, `secret`, and URL paths are treated as credentials and never logged.
Keep the config file readable only by the agent.
