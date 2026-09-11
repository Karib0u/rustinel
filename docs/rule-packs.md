# Manage rule packs

[rustinel-rules](https://github.com/Karib0u/rustinel-rules) publishes versioned Sigma, YARA, and IOC packs for each platform.
`rustinel setup` installs the Essential pack.
Use `rustinel rules` to change or update it.

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
    Keep custom rules in their own folder, see [Write and test rules](rule-development.md#keep-custom-rules-safe-from-pack-updates).

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

## Trust

Packs come from the `Karib0u/rustinel-rules` GitHub releases over HTTPS, and the checksum must match the released catalog.
The catalog itself is not signed.
To use your own catalog, pass `--catalog-url`.
