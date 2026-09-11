# Doctor checks

`rustinel doctor` runs read-only checks and prints `PASS`, `WARN`, or `FAIL` for each.
Fix failures first.
It exits `0` when everything passes, `1` on a warning, and `2` on a failure.
`--json` prints the same results, plus the raw counters from [telemetry.json](telemetry.md) under `telemetry`.

Run it with `sudo` or as Administrator to check platform prerequisites.

## Configuration and paths

| Check | Verifies |
| --- | --- |
| `config_discovery` | Which config file was found, see [Which file is used](configuration.md#which-file-is-used) |
| `config_parse` | The file is valid TOML with valid values |
| `logs_writable`, `alerts_writable` | The log and alert folders can be written |
| `required_privileges` | Administrator on Windows; root, or the four eBPF capabilities, on Linux; root on macOS |
| `platform_support` | The OS and CPU architecture are supported |

## Rules

| Check | Verifies |
| --- | --- |
| `sigma_rules_dir`, `yara_rules_dir` | The rule folders exist |
| `sigma_rules_parse`, `yara_rules_parse` | Every rule compiles. Lists the files that do not |
| `sigma_rules_unsupported` | Correlation or filter documents dropped because a rule they reference does not apply here |
| `sigma_rules_inert` | Rules that loaded but have no collector on this platform, grouped by logsource. They never fire |
| `ioc_files`, `ioc_parse`, `ioc_hashes`, `ioc_ips`, `ioc_domains`, `ioc_paths_regex` | Indicator files exist and parse |
| `field_availability` | The field availability contract loaded. Names fields this platform never fills |
| `rules_pack_state`, `rules_pack_manifest`, `rules_pack_schema`, `rules_pack_checksum`, `rules_pack_compatibility` | The installed pack is intact and fits this Rustinel version |

## Service and response

| Check | Verifies |
| --- | --- |
| `native_service` | Service status. Passes in portable mode, where no service is needed |
| `linux_systemd` | systemd is available (Linux) |
| `active_response_mode` | Whether response is off, dry run, or killing |
| `active_response_safety` | `response.min_severity` is a valid severity |
| `active_response_allowlist` | Prevention has a trusted path allowlist |

## Platform prerequisites

| Check | Verifies |
| --- | --- |
| `telemetry_prerequisites` | Summary of the checks below |
| `windows_etw` | ETW is usable (Windows) |
| `linux_kernel`, `linux_btf`, `linux_tracefs`, `linux_dns_hooks` | Kernel 5.8+, BTF, tracefs, and DNS hooks (Linux) |
| `macos_endpoint_security`, `macos_full_disk_access`, `macos_app_location` | Endpoint Security can start, see [macOS permissions](macos-permissions.md) |

## Telemetry health

These read `telemetry.json` from a running or stopped agent.
See [Telemetry loss](telemetry-loss.md).

| Check | Warns when |
| --- | --- |
| `pipeline_telemetry` | Any queue dropped events. Also warns when `telemetry.enabled = false` |
| `linux_ebpf` | A kernel ring or map filled, records were short or unusable, file paths could not be rebuilt, or counters do not add up |
| `linux_ebpf_<feature>_capability` | A kernel hook is missing, so that feature is degraded. The rest keeps working |
| `linux_task_<field>` | A process identity field is unavailable on this kernel |
| `macos_esf_kernel_loss`, `macos_bpf_kernel_loss` | Endpoint Security or packet capture dropped events |
| `macos_bpf_interface_<name>` | Capture on that interface failed or dropped packets |
| `registry_path_resolution` | Fewer than 99.9% of registry writes had a key path (Windows) |
| `file_path_attribution` | Fewer than 99% of file events had a path, or the startup file snapshot was rejected (Windows) |
| `etw_decode` | ETW records failed to decode. Names the provider, event ID, and version (Windows) |
| `etw_decode_reconciliation` | Records reached no outcome. A growing gap is a bug worth reporting (Windows) |
| `windows_process_correlation` | Two sources disagreed about a process command line (Windows) |
| `windows_event_log_<channel>` | The System or Security subscription failed or went stale (Windows) |
| `windows_event_log_<channel>_retention` | Records were overwritten before Rustinel read them, for example while it was stopped (Windows) |
