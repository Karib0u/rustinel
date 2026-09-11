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

## Micro-benchmarks

Criterion benchmarks for hot paths, run on one machine:

| Benchmark | Measures |
| --- | --- |
| `cargo bench --bench sigma_engine` | Sigma evaluation of five events against 4 and about 2,000 rules |
| `cargo bench --bench ioc_domains` | Wildcard domain matching against 100 and 100,000 indicators |
| `cargo bench --bench cache_eviction` | Inserts into a full bounded cache |

Compare results against the base branch on the same machine, not against numbers from elsewhere.
