# Write and test rules

Rustinel loads three kinds of rules from the folders set in `config.toml`:

| Kind | Default folder in a release | Checked against |
| --- | --- | --- |
| Sigma | `rules/sigma` | Every event |
| YARA | `rules/yara` | Executables when they start, and optionally their memory |
| IOC | `rules/ioc/*.txt` | Hashes of started executables, IPs, domains, paths |

After `rustinel setup`, the folders are under `rules/current` in the [managed rules folder](operations.md#managed-paths).

## Write a Sigma rule

Use standard Sigma with Sysmon-style field names:

```yaml
title: Whoami Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: '/whoami'
  condition: selection
level: low
```

Save it anywhere under the Sigma folder.
Subfolders are loaded too.

Before relying on a rule, check that the platform collects what it needs:

- [Sigma support](sigma.md) lists the logsources, fields, and modifiers.
- [Field availability](field-availability.md) lists fields a platform never fills.
  A rule that needs one of them loads but never fires.

## Write a YARA rule

```yara
rule ExampleMarkerString {
    strings:
        $a = "RUSTINEL_TEST_MARKER" ascii wide
    condition:
        $a
}
```

Files ending in `.yar` or `.yara` are loaded.
YARA scans an executable when it starts, so a file that is written but never run is not scanned.

## Add indicators

One indicator per line.
`#` and `//` start comments, and `;` starts an optional label:

```text
203.0.113.1;C2 endpoint
.example.org;Matches example.org and its subdomains
^/tmp/evil(/.*)?$;Staging path
```

Hashes can be MD5, SHA1, or SHA256.
Path patterns are case-insensitive regular expressions.

## Check that rules load

Rules reload a couple of seconds after you save them.
Then run:

```bash
rustinel doctor
```

`sigma_rules_parse`, `yara_rules_parse`, and `ioc_parse` report files that failed to load.
`sigma_rules_inert` counts rules that loaded but have no collector on this platform.
A reload that fails keeps the previous rules active and logs the error.

## Test against recorded activity

Record the behavior once, then replay it after every rule change.
Replay needs no privileges and runs on any platform.

1. Start a recording, preferably in a disposable VM:

    ```bash
    sudo rustinel capture --output ~/captures/session.ndjson
    ```

    Give the recording its own folder: Rustinel makes that folder readable by its owner only.

2. Run the activity you want to detect in another terminal, then press Ctrl-C.
3. The recording belongs to root.
   Take ownership, then replay it without `sudo`:

    ```bash
    sudo chown -R "$USER" ~/captures
    rustinel replay ~/captures/session.ndjson
    ```

4. Edit your rules and replay again.
   The same recording and rules always produce the same result.

On Windows, run `capture` from an elevated PowerShell.
A recording made on one platform replays on any other.

To compare two rule sets, point a second config at the other folders:

```bash
rustinel replay ~/captures/session.ndjson --config candidate.toml
rustinel replay ~/captures/session.ndjson --output results.ndjson
```

Replay evaluates Sigma and IP, domain, and path indicators.
It skips YARA and hash indicators because a recording holds events, not files.
Replay never kills processes.

Recordings contain command lines, paths, network destinations, and user names.
Handle them like the host's logs.

## Keep custom rules safe from pack updates

`rustinel rules update` replaces everything under `rules/current`.
Keep your own rules in a separate folder under version control, and either copy them in after an update or point `scanner.sigma_rules_path` at your folder.
