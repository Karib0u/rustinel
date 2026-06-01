# Benchmarking Rustinel

Rustinel includes lightweight benchmark scripts for collecting agent overhead,
workload timing, alert latency, and drop-counter evidence on Windows and Linux.
The benchmark is intended to compare baseline host behavior against Rustinel on
the same machine with a fixed rule corpus.

Do not use a single run as a product claim. Run each mode at least three times,
report medians, and keep the rule corpus, allowlists, cargo profile, and machine
fixed across baseline and with-agent runs.

## What To Report

Report these fields for every benchmark set:

- Git commit or diff summary.
- Corpus metadata from `rules-bench/sources/metadata.json`.
- Platform and machine info from `summary.json`.
- Idle CPU average and p95.
- Idle memory average and max.
- Workload durations and slowdown percentages.
- Detection latency from trigger action to alert output.
- Queue or sensor drop counters.
- `valid` and `validation_errors` from with-agent summaries.
- Any warnings or errors in Rustinel operational logs.

Calculate slowdown as:

```text
((rustinel_duration_ms - baseline_duration_ms) / baseline_duration_ms) * 100
```

## Run Validity

With-agent runs write `valid` and `validation_errors` in `summary.json`.

A with-agent run is invalid when:

- the agent process is not observable after startup;
- idle samples never observe `pid_count > 0`;
- alert latency is null;
- one or more workload steps fail;
- on Windows, ETW drops are observed.

Invalid runs are still useful for investigation, but they should not be used for
slowdown or production-readiness claims.

## Queue And Drop Signals

Search operational logs for these messages:

```text
Sensor event channel full; dropping ETW event
YARA queue full; dropping scan job
IOC hash queue full; dropping job
Active response queue full, dropping task
```

Windows benchmark summaries also include:

```json
"etw_drops": {
  "warning_count": 0,
  "final_counter": 0
}
```

`warning_count` is the number of ETW drop warnings appended during that run.
`final_counter` is the last `dropped_events=N` value seen during that run. A
nonzero value marks the Windows with-agent run invalid.

## Build

Build the release binary before running benchmarks:

```powershell
cargo build --locked --release
```

On Linux or WSL:

```bash
cargo build --locked --release
```

## Rule Corpus

The bundled rules are enough for a quick smoke benchmark. For a realistic
benchmark, use a fixed `rules-bench` directory:

```text
rules-bench/
├── sigma/
├── yara/
├── ioc/
└── sources/
```

Fetch a corpus:

```bash
python scripts/rules/fetch_corpus.py --output rules-bench --force
```

The default fetch includes:

- SigmaHQ community rules from the current `master` branch, excluding
  deprecated, unsupported, test, and documentation directories.
- YARA Forge `core`.
- Feodo Tracker recommended C2 IP blocklist.

Optional authenticated feeds:

```bash
THREATFOX_AUTH_KEY=... python scripts/rules/fetch_corpus.py \
  --output rules-bench \
  --force \
  --threatfox-days 7 \
  --threatfox-min-confidence 70
```

```bash
URLHAUS_AUTH_KEY=... python scripts/rules/fetch_corpus.py \
  --output rules-bench \
  --force \
  --include-urlhaus
```

For a heavier YARA profile:

```bash
python scripts/rules/fetch_corpus.py \
  --output rules-bench \
  --force \
  --yara-forge-set extended
```

The fetcher writes source metadata to
`rules-bench/sources/metadata.json`. Include that metadata when reporting
benchmark results. YARA files are flattened into `rules-bench/yara/` because
Rustinel loads YARA rules from the top-level configured directory.

## Windows Full Matrix

Run from an Administrator shell so Windows ETW providers can be collected.

Run baseline three times:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
  -Mode baseline `
  -SigmaRulesPath .\rules-bench\sigma `
  -YaraRulesPath .\rules-bench\yara `
  -IocRulesPath .\rules-bench\ioc
```

Run with-agent three times:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
  -Mode with-agent `
  -SigmaRulesPath .\rules-bench\sigma `
  -YaraRulesPath .\rules-bench\yara `
  -IocRulesPath .\rules-bench\ioc
```

If Rustinel is not already running, the script starts
`.\target\release\rustinel.exe run` and stops that process when the
benchmark ends. When the script starts the agent, it creates a benchmark Sigma
trigger rule and passes matching `EDR__` environment overrides so the agent uses
the requested corpus.

If Rustinel is already running, the script reuses it. In that case, restart the
agent with the same corpus before benchmarking, or pass `-NoBenchmarkTriggerRule`
only when the existing configuration already contains the alert trigger rule you
want to measure.

## Windows Isolated Workloads

Use isolated workloads when ETW drops or workload regressions need root-cause
work. Each selector runs only one workload:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
  -Mode with-agent `
  -ProcessOnly `
  -SigmaRulesPath .\rules-bench\sigma `
  -YaraRulesPath .\rules-bench\yara `
  -IocRulesPath .\rules-bench\ioc `
  -AlertRuleName "Local Accounts Discovery" `
  -NoBenchmarkTriggerRule
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
  -Mode with-agent `
  -FileOnly `
  -SigmaRulesPath .\rules-bench\sigma `
  -YaraRulesPath .\rules-bench\yara `
  -IocRulesPath .\rules-bench\ioc `
  -AlertRuleName "Local Accounts Discovery" `
  -NoBenchmarkTriggerRule
```

For cargo-only isolation, avoid launching the agent from
`target\release\rustinel.exe`, because Windows can lock the executable while the
benchmark's cargo workload tries to rebuild it. Copy the agent first:

```powershell
New-Item -ItemType Directory -Force .\target\rustinel-bench-agent | Out-Null
Copy-Item .\target\release\rustinel.exe .\target\rustinel-bench-agent\rustinel.exe -Force

powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
  -Mode with-agent `
  -CargoOnly `
  -AgentPath .\target\rustinel-bench-agent\rustinel.exe `
  -SigmaRulesPath .\rules-bench\sigma `
  -YaraRulesPath .\rules-bench\yara `
  -IocRulesPath .\rules-bench\ioc `
  -AlertRuleName "Local Accounts Discovery" `
  -NoBenchmarkTriggerRule
```

Interpretation:

- Process-only drops point at process ETW callback, queueing, normalization, or
  rule-evaluation pressure.
- File-only drops point at file ETW callback, queueing, normalization, or
  rule-evaluation pressure.
- Cargo-only drops usually indicate common ingestion or build-time host noise,
  not cargo itself.

## Linux Full Matrix

Run Linux benchmarks as the normal user. The script elevates only Rustinel agent
startup through sudo so cargo still uses the user's Rust toolchain.

Run baseline three times:

```bash
bash scripts/bench/linux.sh \
  --mode baseline \
  --sigma-rules-path ./rules-bench/sigma \
  --yara-rules-path ./rules-bench/yara \
  --ioc-rules-path ./rules-bench/ioc
```

Run with-agent three times:

```bash
bash scripts/bench/linux.sh \
  --mode with-agent \
  --sigma-rules-path ./rules-bench/sigma \
  --yara-rules-path ./rules-bench/yara \
  --ioc-rules-path ./rules-bench/ioc
```

When prompted, enter sudo credentials so the agent can attach eBPF programs.
The script calls `sudo -v` before starting the background agent, then starts the
agent through sudo while keeping the benchmark workloads under the normal user.

For noninteractive lab runs, set `SUDO_ASKPASS` to an executable askpass helper
and run the same command. Do not commit askpass helpers or passwords.

If Rustinel is already running, the script reuses it. Restart Rustinel with the
same corpus before benchmarking, or pass `--no-benchmark-trigger-rule` only when
the existing configuration already contains the alert trigger rule you want to
measure.

## Linux Isolated Workloads

Linux supports the same workload selectors:

```bash
bash scripts/bench/linux.sh \
  --mode with-agent \
  --process-only \
  --sigma-rules-path ./rules-bench/sigma \
  --yara-rules-path ./rules-bench/yara \
  --ioc-rules-path ./rules-bench/ioc
```

```bash
bash scripts/bench/linux.sh \
  --mode with-agent \
  --file-only \
  --sigma-rules-path ./rules-bench/sigma \
  --yara-rules-path ./rules-bench/yara \
  --ioc-rules-path ./rules-bench/ioc
```

```bash
bash scripts/bench/linux.sh \
  --mode with-agent \
  --cargo-only \
  --sigma-rules-path ./rules-bench/sigma \
  --yara-rules-path ./rules-bench/yara \
  --ioc-rules-path ./rules-bench/ioc
```

Use isolated Linux workloads when investigating idle CPU, alert latency, or a
specific workload regression. For the current 2026-05-16 investigation, the
clean Linux full matrix was valid and below the idle CPU acceptance threshold.

## Output Files

Each run writes a timestamped directory under `target/rustinel-bench/`:

- `summary.json`: machine info, rule inventory, parameters, resource summaries,
  workload steps, alert latency, `valid`, and `validation_errors`.
- `resource-samples.csv`: per-second CPU, memory, process count, and thread
  samples.
- `workload-steps.jsonl`: raw workload timings and statuses.
- `agent.stdout.log`: Linux-only stdout and stderr for an agent started by the
  benchmark script.
- `sigma-benchmark/`: generated benchmark trigger rule corpus when the script
  starts the agent and trigger-rule injection is enabled.

Do not commit generated benchmark output directories, logs, copied binaries, or
temporary scripts.

## Current Acceptance Targets

Linux:

- Idle CPU median below `3%`.
- Idle CPU p95 below `8%`.
- Alert latency non-null in three consecutive with-agent runs.
- Median alert latency below `1,000 ms`.
- Every workload status is `ok`.

Windows:

- Zero ETW drops in the default workload, or a documented bounded drop policy
  for low-value event classes only.
- Alert latency below `500 ms` median.
- Process and file IO slowdown should not regress by more than `5%` relative to
  the current with-agent baseline.
- Every workload status is `ok`.

## Reading The Current Results

As of the 2026-05-16 investigation:

- Linux full with-agent matrix is valid: median idle CPU avg `0.847%`, median
  idle CPU p95 `0.875%`, and median alert latency `155 ms`.
- Windows isolated process-only and file-only runs are invalid because ETW drops
  were observed.
- Windows cargo-only with the copied agent executable had zero ETW drops.

The benchmark harness is suitable for tracking progress, but Rustinel should not
be presented as production-ready EDR telemetry under Windows stress until the
process/file ETW drop source is instrumented and mitigated.
