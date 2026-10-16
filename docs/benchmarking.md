# Benchmarking

## Agent overhead

`scripts/bench` measures CPU, memory, workload slowdown, alert latency, and drops on Windows and Linux, comparing the same machine with and without Rustinel.
Details are in [`scripts/bench/README.md`](https://github.com/Karib0u/rustinel/blob/main/scripts/bench/README.md).

1. Build a release binary and fetch a realistic rule corpus (SigmaHQ, YARA Forge `core`, and the Feodo Tracker blocklist):

    ```bash
    cargo build --locked --release
    python scripts/rules/fetch_corpus.py --output rules-bench --force
    ```

2. Run each mode three times, `baseline` then `with-agent`:

    === "Linux"

        As your normal user; the script uses `sudo` for the agent only.

        ```bash
        bash scripts/bench/linux.sh --mode baseline \
          --sigma-rules-path ./rules-bench/sigma \
          --yara-rules-path ./rules-bench/yara \
          --ioc-rules-path ./rules-bench/ioc
        ```

    === "Windows"

        From an elevated PowerShell:

        ```powershell
        powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
          -Mode baseline `
          -SigmaRulesPath .\rules-bench\sigma `
          -YaraRulesPath .\rules-bench\yara `
          -IocRulesPath .\rules-bench\ioc
        ```

    If Rustinel is already running, the script reuses it.
    Restart it with the same corpus first.

3. Read `target/rustinel-bench/<timestamp>/summary.json`.
   A run with `valid: false` must not back any claim; `validation_errors` says why.
   A with-agent run is also invalid when `telemetry.json` reports dropped events or, on Windows, when ETW discarded events in the kernel buffer pool, so a run that shed telemetry can no longer pass as valid.
   The trigger rule is `level: critical`, so SigmaHQ's own `whoami` rules cannot outrank it, and the Linux script sets `LC_ALL=C` so `summary.json` stays valid JSON in any locale.
   Do not compare versions with the cargo step enabled, since each checkout rebuilds different code; pass `--skip-cargo` or `-SkipCargo`.

Report medians, and keep the corpus, allowlists, build profile, and machine fixed across modes.
Include the commit, `rules-bench/sources/metadata.json`, machine details, idle CPU and memory, workload slowdown, alert latency, and drop counters.

### Targets

| | Linux | Windows |
| --- | --- | --- |
| Idle CPU | median below 3%, p95 below 8% | |
| Median alert latency | below 1,000 ms | below 500 ms |
| Drops | | zero ETW drops in the default workload |
| Slowdown | | process and file I/O within 5% of the previous with-agent run |
| Workload | every step `ok` | every step `ok` |

## Realistic and stress benchmark

The runs above measure the cost of the agent at rest, with a short synthetic workload.
`scripts/bench/realistic.py` measures a working machine instead, with the full rule corpus loaded, and finds where events start to be lost.
It uses only the Python standard library and runs the same way on Windows, Linux, and macOS.

1. Fetch a corpus that includes public IOC feeds and a realistic IOC volume:

    ```bash
    python scripts/rules/fetch_corpus.py --output rules-bench --force \
      --public-iocs --synthetic-ioc 100000
    ```

    `--public-iocs` adds feeds that need no key: ET compromised IPs, ipsum (three or more lists), Spamhaus DROP, URLhaus online hosts, Phishing Army domains, and recent MalwareBazaar SHA-256.
    `--synthetic-ioc N` pads IPs, domains, and hashes up to `N` each with values that cannot match real traffic (198.18.0.0/15, `.invalid`, hashes of a fixed label), to stress the lookup tables.
    Add `--yara-forge-set extended` for a heavier YARA set.

2. Run it elevated, once without the agent and once per version:

    === "Linux and macOS"

        ```bash
        sudo python3 scripts/bench/realistic.py --mode baseline --idle-secs 0
        sudo python3 scripts/bench/realistic.py --agent ./rustinel --corpus rules-bench
        ```

    === "Windows"

        ```powershell
        python scripts\bench\realistic.py --mode baseline --idle-secs 0
        python scripts\bench\realistic.py --agent .\rustinel.exe --corpus rules-bench
        ```

3. Compare runs:

    ```bash
    python3 scripts/bench/realistic.py compare run-a/summary.json run-b/summary.json
    ```

The run has these phases, each reported with the agent's CPU and memory, sensor event rate, and the latency of the workload itself:

| Phase | Default length | What happens |
| --- | --- | --- |
| `idle` | 60 s | The agent alone. |
| `warmup` | 30 s | The steady mix, not used for verdicts. |
| `steady` | 300 s | A desktop-like mix at 1x: short commands, editor-style saves, executable and archive drops, loopback and DNS traffic, a build burst every minute, and registry writes on Windows. |
| `ramp_x2` to `ramp_x16` | 45 s each | The same mix at 2x, 4x, 8x, and 16x, to find where the first events are lost. |

Each phase of `summary.json` also lists the accepted events per second for every sensor category, the whole-machine CPU percentage, and the six busiest agent threads with their average and peak percent of one core (Windows and Linux).
A peak near 100% on one thread means that thread is the ceiling.
A busy machine with no hot thread means the workload is competing with the agent for cores, so a loss at that step says little about the agent itself.

During every phase except `idle` the harness injects one canary per detection engine every 10 seconds (Sigma process, Sigma file, YARA, IOC IP, IOC domain) and records whether each one raised its alert and how late.
It reads `telemetry.json` for dropped events per channel and per sensor category, and the kernel-side loss counters (eBPF rings, Endpoint Security) and the ETW buffer loss logged by the agent.

A run is invalid if the agent exits, if any event is lost during `idle`, `warmup`, or `steady`, or if a steady-state canary is missed.
Loss during the ramp is a result, not an error: `headroom.first_phase_with_loss` names the first step that lost events.
Report the corpus metadata (`sources/metadata.json`), the machine, and the summary of each run.
The workload is deterministic for a given `--seed`, but wall-clock rates on a busy host vary, so compare runs on the same machine and read the achieved `ops_per_s` in `summary.json` before trusting a ramp step.

## Micro-benchmarks

Criterion benchmarks for hot paths, run on one machine:

| Benchmark | Measures |
| --- | --- |
| `cargo bench --bench sigma_engine` | Sigma evaluation of five events against 4 and about 2,000 rules, and of one recorded event per Windows event shape against 20 and 2,000 rules |
| `cargo bench --bench field_lookup` | One default-view field lookup, for a field availability contract found early, found deep, and missing |
| `cargo bench --bench ioc_domains` | Wildcard domain matching against 100 and 100,000 indicators |
| `cargo bench --bench ioc_ips` | CIDR indicator matching |
| `cargo bench --bench ioc_observables` | Observable extraction and IOC matching per event, on a miss and a hit, and file hash matching |
| `cargo bench --bench cache_eviction` | Inserts into a full bounded cache |

Compare results against the base branch on the same machine, not against numbers from elsewhere.
