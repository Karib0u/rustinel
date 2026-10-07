# Write rules

Rustinel loads three kinds of rules from the folders set in `config.toml`:

| Kind | Default folder in a release | Checked against |
| --- | --- | --- |
| Sigma | `rules/sigma` | Every event |
| YARA | `rules/yara` | Executables when they start, Linux memfd memory, and optionally other process memory |
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
YARA scans an executable when it starts and qualifying files written to disk after a 250 ms settle delay.

## Add indicators

One indicator per line.
`#` and `//` start comments, and `;` starts an optional label:

```text
203.0.113.1;C2 endpoint
.example.org;Matches example.org and its subdomains
^/tmp/evil(/.*)?$;Staging path
```

Hashes can be MD5, SHA1, or SHA256 and match the image of a process that starts.
Dropping an EICAR file does not test this path because it never becomes a process image.
IPs accept individual addresses or CIDR ranges; domains accept exact names or a leading `.` or `*.` for subdomains.
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

## Keep custom rules safe from pack updates

`rustinel rules update` replaces everything under `rules/current`.
Keep your own rules in a separate folder and list it in `scanner.sigma_local_rules_paths` or `scanner.yara_local_rules_paths`.
Local directories load with the pack, reload with it, and are never touched by install or update.
See [local rules](rule-packs.md#keep-local-rules-next-to-a-pack).

## Contribute to the official packs

Keep reusable detections in [rustinel-rules](https://github.com/Karib0u/rustinel-rules), with stable IDs, ATT&CK mappings, and reproducible behavior.
The [contribution guide](https://github.com/Karib0u/rustinel-rules/blob/main/CONTRIBUTING.md) covers Sigma and YARA metadata, typed IOC sets, pack inheritance, and validation.
Its pinned field contract checks compatibility with the certified engine.

Rules that require unavailable telemetry stay in the repository's preview collection until they can fire.
Atomic tests exercise real telemetry and verify matching alerts; see the [atomic test guide](https://github.com/Karib0u/rustinel-rules/blob/main/tests/atomic/README.md).

## Next steps

- [Test rules with replay](replay.md) against recorded activity.
- [Check coverage](coverage.md#rules-that-load-but-never-fire) before relying on a rule.
