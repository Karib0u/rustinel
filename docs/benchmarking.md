# Benchmarking

Rustinel ships benchmark scripts that measure agent overhead, workload timing,
alert latency, and drop counters on Windows and Linux. They compare baseline
host behavior against Rustinel on the **same machine** with a fixed rule corpus.

Do not use a single run as a product claim. Run each mode at least three times,
report medians, and hold the rule corpus, allowlists, cargo profile, and machine
fixed across baseline and with-agent runs.

Script internals, isolated-workload forensics, and corpus-fetch options are
documented in [`scripts/bench/README.md`](https://github.com/Karib0u/rustinel/blob/main/scripts/bench/README.md).

## Running A Matrix

Build the release binary first:

```bash
cargo build --locked --release
```

Fetch a realistic rule corpus (the bundled demo rules are only a smoke test):

```bash
python scripts/rules/fetch_corpus.py --output rules-bench --force
```

That pulls SigmaHQ community rules, YARA Forge `core`, and the Feodo Tracker C2
blocklist, and writes provenance to `rules-bench/sources/metadata.json`.

Then run each mode three times:

=== "Linux"

    ```bash
    bash scripts/bench/linux.sh \
      --mode baseline \
      --sigma-rules-path ./rules-bench/sigma \
      --yara-rules-path ./rules-bench/yara \
      --ioc-rules-path ./rules-bench/ioc
    ```

    Swap `--mode with-agent` for the second set. Run as the normal user, since the
    script elevates only the agent through sudo, so cargo keeps using your
    toolchain.

=== "Windows"

    ```powershell
    powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
      -Mode baseline `
      -SigmaRulesPath .\rules-bench\sigma `
      -YaraRulesPath .\rules-bench\yara `
      -IocRulesPath .\rules-bench\ioc
    ```

    Swap `-Mode with-agent` for the second set. Run from an Administrator shell
    so ETW providers can be collected.

If Rustinel is already running, the script reuses it, so restart the agent with
the same corpus first, or your measurements describe a different configuration
than you think.

## Reading The Output

Each run writes a timestamped directory under `target/rustinel-bench/`:

| File | Contents |
| --- | --- |
| `summary.json` | Machine info, rule inventory, parameters, resource summaries, workload steps, alert latency, `valid`, `validation_errors` |
| `resource-samples.csv` | Per-second CPU, memory, process count, thread samples |
| `workload-steps.jsonl` | Raw workload timings and statuses |
| `agent.stdout.log` | Linux-only agent output, when the script started it |

Slowdown is:

```text
((rustinel_duration_ms - baseline_duration_ms) / baseline_duration_ms) * 100
```

### Run validity

With-agent runs record `valid` and `validation_errors`. A run is **invalid**
when the agent process is not observable after startup, idle samples never see
`pid_count > 0`, alert latency is null, any workload step fails, or (on Windows)
ETW drops are observed. Invalid runs are useful for investigation but must not
back slowdown or readiness claims.

### What to report

Report the git commit, the corpus metadata from
`rules-bench/sources/metadata.json`, platform and machine info, idle CPU average
and p95, idle memory average and max, workload durations and slowdown, detection
latency, drop counters, `valid` / `validation_errors`, and any warnings in the
operational logs.

Drop counters are the ones to watch closely. See
[Pipeline Telemetry](configuration.md#pipeline-telemetry). Windows summaries
additionally carry `etw_drops`, whose `final_counter` is the last observed
`dropped_events=N`; anything nonzero marks the run invalid.

## Acceptance Targets

=== "Linux"

    - Idle CPU median below 3%, p95 below 8%
    - Alert latency non-null across three consecutive with-agent runs
    - Median alert latency below 1,000 ms
    - Every workload status `ok`

=== "Windows"

    - Zero ETW drops in the default workload, or a documented bounded drop
      policy for low-value event classes only
    - Median alert latency below 500 ms
    - Process and file IO slowdown within 5% of the current with-agent baseline
    - Every workload status `ok`

## Published Results

The last full published matrix is from **2026-05-16**, and its Linux figures
still stand: median idle CPU average `0.847%`, p95 `0.875%`, median alert
latency `155 ms`, run valid.

**The Windows figures from that run are obsolete.** They were collected before
[#312](https://github.com/Karib0u/rustinel/pull/312) replaced the inherited ETW
buffer sizing, which was the source of the drops that invalidated those runs.
The shipped configuration has not yet been re-measured through this harness, so
there is currently no valid published Windows matrix. See
[Windows ETW session buffers](operations.md#windows-etw-session-buffers) for
what the fix was measured against directly.

## Sigma Engine Micro-Benchmark

The `sigma_engine` Criterion benchmark measures `Engine::evaluate_event` in
isolation, and is distinct from the agent-overhead scripts above.

```sh
cargo bench --bench sigma_engine
```

Each iteration runs one pass over five normalized events against two rulesets:
`mixed` (four matching rules, nothing to prune) and `large` (~2,000 rules, where
per-rule scanning cost dominates). Both use the synchronized RSigma engine.

Indicative figures from a single macOS development machine. Re-run locally
before quoting them:

| Scenario | Ruleset | Per iteration |
| --- | --- | --- |
| `mixed` | 4 rules | 11.6 µs |
| `large` | ~2,000 rules | 204 µs |

Cost grows far slower than rule count: the engine's inverted rule index skips
rules whose literals cannot be present in the event, rather than scanning each
candidate bucket linearly.

This isolates matching throughput only: it excludes normalization, alert
serialization, IOC and YARA, and the sensor pipeline. Source:
[benches/sigma_engine.rs](https://github.com/Karib0u/rustinel/blob/main/benches/sigma_engine.rs).

## Wildcard Domain IOC Micro-Benchmark

The `ioc_domains` Criterion benchmark measures `IocEngine::check_event` against
a wildcard domain feed (`*.example.com` indicators), which is the IOC path whose
cost used to scale with feed size.

```sh
cargo bench --bench ioc_domains
```

Each iteration matches one DNS event against a feed of 100 or 100,000 wildcard
indicators, once for a hostname no indicator covers (`miss`, the common case)
and once for a hostname one indicator covers (`hit`).

Indicative figures from a single macOS development machine. Re-run locally
before quoting them:

| Scenario | 100 indicators | 100,000 indicators |
| --- | --- | --- |
| `miss` | 112 ns | 102 ns |
| `hit` | 669 ns | 682 ns |

Cost tracks the hostname's DNS label count, not the size of the feed: wildcard
suffixes are indexed, so a hostname only looks up its own suffixes. Before that
index, the same two scenarios cost 6.3 µs and 8.1 ms respectively, because every
eligible event scanned the whole feed.

Source:
[benches/ioc_domains.rs](https://github.com/Karib0u/rustinel/blob/main/benches/ioc_domains.rs).
