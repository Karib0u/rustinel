# FAQ

Short answers to recurring questions. Anything that needs more than a paragraph
lives on the page it belongs to.

### Do I need Administrator or root?

Yes, on every platform. Windows ETW needs Administrator; Linux eBPF needs root
or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN` (or `CAP_SYS_ADMIN`); macOS needs
root, Full Disk Access, and a signed bundle carrying the Endpoint Security
entitlement. See [Getting Started](getting-started.md#minimum-requirements).

### Why is Rustinel looking in the wrong directory for rules or logs?

Relative paths in `config.toml` resolve from the directory containing the
**selected** configuration file, not the working directory. Run `rustinel doctor`
to see which file was selected and where its paths resolved to. For production,
use absolute paths. See [Configuration](configuration.md).

### Where do logs and alerts go?

By default `logs/rustinel.log.<date>` and `logs/alerts.json.<date>`. Both are
configurable. See [Output Format](output.md).

### Can I disable Sigma, YARA, or IOC independently?

Yes: `scanner.sigma_enabled`, `scanner.yara_enabled`, and `ioc.enabled`.

### Does hot reload require a restart, and what exactly reloads?

No restart. With `reload.enabled = true` (the default), Sigma, YARA, and IOC
files reload automatically when they change. Both directories are watched
recursively. The configuration file is watched too, but only the `[response]`
section is hot-swapped; every other section needs a restart, as does changing
the binary, privileges, or deployment layout.

An invalid reload is rejected and the last valid detector set stays live. See
[Configuration](configuration.md#reload).

### How are severities assigned?

Sigma uses the rule `level`, YARA is always `critical`, and IOC uses
`ioc.default_severity`. `response.min_severity` is applied after that mapping.
See [Detection](detection.md#overall-severity-mapping).

### What does `alerts.match_debug` do?

It controls how much match metadata is attached to alerts: `off` for none,
`summary` for structured match information without values, `full` to include the
matched values and YARA string details. See
[Detection](detection.md#match-debug).

### Are allowlists shared across modules?

Yes, by default. `allowlist.paths` is the shared trusted-prefix list, and
`response.allowlist_paths`, `scanner.yara_allowlist_paths`, and
`ioc.hash_allowlist_paths` each inherit from it while they are empty. See
[Configuration](configuration.md#global-allowlist).

### Can I test active response safely?

Yes. Start in dry-run (`enabled = true`, `prevention_enabled = false`) and
trigger the bundled `whoami` rule. Because the system `whoami` is allowlisted by
default, the expected result is an `Active response skipped: allowlisted` log,
which confirms detection and the safety path at once. To validate actual
termination, use the YARA demo in
[Active Response](active-response.md#safe-test-flow).

### Does Rustinel ship alerts directly to a SIEM?

Not by itself. It writes ECS NDJSON files; a shipper such as Filebeat forwards
them. See [SIEM Demos](siem-demos.md).

### Something is not working and this page did not cover it

Start with `rustinel doctor`, then
[Troubleshooting](troubleshooting.md), which is organized by symptom.
