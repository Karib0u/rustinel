# Test rules with replay

Record endpoint activity once, then replay it after every rule change.
Replay needs no privileges, runs on any platform, and always gives the same result for the same recording and rules.

## Record

1. Start a recording, preferably in a disposable VM:

    === "Linux and macOS"

        ```bash
        sudo rustinel capture --output ~/captures/session.ndjson
        ```

    === "Windows"

        In an elevated PowerShell:

        ```powershell
        rustinel capture --output $HOME\captures\session.ndjson
        ```

    Give the recording its own folder: Rustinel makes that folder readable by its owner only.

2. Run the activity you want to detect in another terminal, then press Ctrl-C.

## Replay

On Linux and macOS the recording belongs to root.
Take ownership, then replay it without `sudo`:

```bash
sudo chown -R "$USER" ~/captures
rustinel replay ~/captures/session.ndjson
```

Edit your rules and replay again.
A recording made on one platform replays on any other.

## Compare rule sets

Point a second config at the other rule folders, or save the alerts to compare them:

```bash
rustinel replay ~/captures/session.ndjson --config candidate.toml
rustinel replay ~/captures/session.ndjson --output results.ndjson
```

`--output` never overwrites.
Replay refuses an existing file, and an output that aliases the recording or its manifest, before it reads any event.
Pick a new name or remove the old report yourself.

## What replay skips

- YARA and hash indicators, because a recording holds events, not files.
- Windows `Hashes` and `Imphash`, see [Deferred pass](detection.md#deferred-pass).
- Active response: replay never kills processes.

Recordings contain command lines, paths, network destinations, and user names.
Handle them like the host's logs.
The file formats are in [Recordings](output.md#recordings).
