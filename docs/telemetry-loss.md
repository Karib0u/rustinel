# Telemetry loss

Rustinel prefers losing events to slowing down the host.
When events arrive faster than they can be processed, some are dropped and no rule sees them.
Every drop is counted, so you can tell whether a quiet endpoint is quiet or blind.

## Where events can be lost

| Stage | Example | Reported by `doctor` as |
| --- | --- | --- |
| Before Rustinel | An eBPF ring is full, Endpoint Security or `/dev/bpf` drops, ETW buffers overflow | `linux_ebpf`, `macos_esf_kernel_loss`, `macos_bpf_kernel_loss`. ETW loss is a warning in the operational log |
| Inside the sensor | A Windows registry or file event whose path cannot be recovered, an ETW record that fails to decode | `registry_path_resolution`, `file_path_attribution`, `etw_decode` |
| Between stages | A full queue between the sensor and the detectors, or in front of YARA, hashing, or response | `pipeline_telemetry` |

A rule can also miss events that were never produced, because the platform or host policy does not provide them.
That is a coverage question, see [Platform coverage](coverage.md).

## Check an endpoint

```bash
rustinel doctor
```

A passing `pipeline_telemetry` check means nothing was dropped since the agent started.
When something was, the check names the queue:

```text
[WARN] pipeline_telemetry: 12600 events were dropped under load
    detail: sensor_events: 12500 dropped of 412500 offered (3.03%), peak depth 8192/8192
```

`doctor` reads `telemetry.json`, which the running agent rewrites every 30 seconds in its log directory.
For scripts:

```bash
rustinel doctor --json | jq '.telemetry.channels[] | select(.dropped > 0)'
```

Counters reset when the agent restarts.
Every field is described in [telemetry.json](telemetry.md).

## Which drops matter most

| Queue | Lost when full |
| --- | --- |
| `sensor_events` | Events never reach any rule. The widest gap |
| `yara_file_scan` | Executables are not YARA scanned |
| `yara_memory_scan` | Processes are not memory scanned |
| `ioc_hash` | Executables are not hashed |
| `active_response` | Responses are not carried out |
| `capture_writer` | Events are missing from a recording, which is then marked incomplete |

A peak depth equal to the capacity means the queue was full.
Drops with a low peak depth mean a short burst.

## Reduce loss

- Narrow or remove very broad rules.
- Add trusted paths to `allowlist.paths` so YARA and hashing skip them.
- Avoid scanning large trusted software trees.
- On Windows, a small share of registry and file writes is expected to stay unnamed, mostly writes by protected system processes.
  A rate that keeps falling, or drops after a Windows update, is worth reporting.

Queue sizes are fixed, except `response.channel_capacity` and `scanner.yara_memory_queue_capacity`.
Rustinel does not sample or prioritize: reducing volume is the only lever.
