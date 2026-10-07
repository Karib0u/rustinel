# Manage rule packs

[rustinel-rules](https://github.com/Karib0u/rustinel-rules) publishes versioned Sigma and YARA detection packs for each platform.
The pack format also supports IOC sets; current packs contain no IOC indicators.
`rustinel setup` installs the Essential pack.
Use `rustinel rules` to change or update it.

## Choose a level

| Level | Use | Platforms |
| --- | --- | --- |
| Essential | High-confidence detections with low expected noise. Start here. | Windows, Linux, macOS |
| Advanced | Broader coverage with more environment-dependent false positives. | Windows, Linux, macOS |
| Hunting | Noisier leads for analysts. | Windows |

Packs are cumulative: Advanced includes Essential, and Hunting includes Advanced.
Load one pack per endpoint. macOS packs are experimental.

Content releases are independent of engine releases.
Each pack declares its minimum engine version, and Rustinel checks compatibility before installation.
Use the released catalog for current requirements and the [pack manifests](https://github.com/Karib0u/rustinel-rules/tree/main/packs) for source membership.

## List packs

```bash
rustinel rules list
```

Shows the packs for this platform and marks the active one.

## Install a pack

```bash
sudo rustinel rules install linux-essential
```

Use a pack ID from `rules list`.
Rustinel downloads the pack, verifies its SHA-256 checksum, validates it, and then swaps it into `rules/current` in one step.
If any step fails, the previous pack stays active.
Restart Rustinel to load the new pack:

```bash
sudo rustinel service restart
```

## Update the active pack

```bash
sudo rustinel rules update
sudo rustinel service restart
```

`update` installs only a newer version that is compatible with this platform and Rustinel version.
If there is nothing newer, it does nothing.

!!! warning "Updates replace `rules/current`"
    Local edits under `rules/current` are overwritten.
    Keep custom rules in their own folder, see [Write rules](rule-development.md#keep-custom-rules-safe-from-pack-updates).

## Why a restart is needed

Hot reload handles edits to individual rule files.
Replacing the whole pack folder can break the file watcher, so load a new pack with a restart.
For a coordinated change, stop the service, update, then start it again.
A failed update leaves the previous pack in place.

## Pack layout

```text
rules/
├── current/      active pack: pack.yml, sigma/, yara/, ioc/
├── staging/      downloads being verified
└── state.json    active pack ID and version
```

## Keep local rules next to a pack

`rules install` and `rules update` replace `rules/current` and nothing else.
Put your own detections in a sibling directory and list it, so the pack and your rules load together:

```text
rules/
├── current/      managed pack, replaced by install and update
├── local/        yours: sigma/ and yara/, never touched
├── staging/
└── state.json
```

```toml
[scanner]
sigma_local_rules_paths = ["/var/lib/rustinel/rules/local/sigma"]
yara_local_rules_paths = ["/var/lib/rustinel/rules/local/yara"]
```

The managed layout puts `rules` at `/var/lib/rustinel/rules` on Linux, `/Library/Application Support/Rustinel/rules` on macOS, and `C:\ProgramData\Rustinel\rules` on Windows.
Both options take a list, and a relative path is resolved against the config file.
The single `sigma_rules_path` and `yara_rules_path` keep working and still name the pack.

Each local directory is read recursively and held to the same [input trust](security.md) checks as the pack.
Hot reload watches them too.
If one local directory fails validation, the reload is rejected and the previous rules stay active, so fix or remove the directory named in the log.

A local rule wins over a pack rule that has the same Sigma `id` or the same YARA rule name.
The pack rule is dropped, and startup, the log, and `rustinel doctor` name the pack and local sources.
Rules without an `id` never collide.
`rustinel doctor` lists every directory with its rule count (`sigma_rules_dirs`, `yara_rules_dirs`) and reports collisions (`sigma_rules_collision`, `yara_rules_collision`).

Local directories apply to Sigma and YARA only.
IOC files keep a single path.

## Manual installation

Download a pack ZIP, `index.json`, and `index.json.minisig` from the same [rules release](https://github.com/Karib0u/rustinel-rules/releases/latest).
Verify the catalog as described below, check the ZIP against its `sha256` entry, then unzip it.
Use the paths in that pack's `engine` block in `index.json`:

```toml
[scanner]
sigma_rules_path = "linux-essential/sigma"
yara_rules_path = "linux-essential/yara"

[ioc]
hashes_path = "linux-essential/ioc/hashes.txt"
ips_path = "linux-essential/ioc/ips.txt"
domains_path = "linux-essential/ioc/domains.txt"
paths_regex_path = "linux-essential/ioc/paths_regex.txt"
```

Use absolute paths when running as a service, and restart after replacing a pack.
For scanner options, memory scanning, and allowlists, see [Configuration](configuration.md).

## Trust

Packs come from the `Karib0u/rustinel-rules` GitHub releases.
The catalog must carry a valid Rustinel release signature, and each pack must match the checksum in it.
`--catalog-url` selects another signed catalog, such as a specific release, see [Downloads](security.md#downloads).

Rules releases include a detached Minisign signature for `index.json`.
For manual verification, obtain the [public key](https://github.com/Karib0u/rustinel-rules/blob/main/release-minisign.pub) from a trusted checkout and run:

```bash
minisign -Vm index.json -p release-minisign.pub
```

Verify the catalog before trusting its pack checksums.

## Contribute detection content

See the [rules contribution guide](https://github.com/Karib0u/rustinel-rules/blob/main/CONTRIBUTING.md) for metadata, pack membership, validation, and release preparation.
See [Write rules](rule-development.md) for engine behavior and [Test rules with replay](replay.md) for local testing.
