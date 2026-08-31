# Benchmark harness internals

Maintainer notes for `linux.sh` and `windows.ps1`. The user-facing guide (how to
run a matrix, what to report, and the acceptance targets) is
[docs/benchmarking.md](../../docs/benchmarking.md).

## Corpus fetching

`scripts/rules/fetch_corpus.py` builds a fixed corpus under `rules-bench/`:

```text
rules-bench/
├── sigma/
├── yara/
├── ioc/
└── sources/metadata.json
```

The default fetch includes SigmaHQ community rules from `master` (excluding
deprecated, unsupported, test, and documentation directories), YARA Forge
`core`, and the Feodo Tracker recommended C2 IP blocklist.

Optional authenticated feeds and heavier profiles:

```bash
THREATFOX_AUTH_KEY=... python scripts/rules/fetch_corpus.py \
  --output rules-bench --force \
  --threatfox-days 7 --threatfox-min-confidence 70

URLHAUS_AUTH_KEY=... python scripts/rules/fetch_corpus.py \
  --output rules-bench --force --include-urlhaus

python scripts/rules/fetch_corpus.py \
  --output rules-bench --force --yara-forge-set extended
```

Always report `rules-bench/sources/metadata.json` alongside results: the corpus
is the largest single variable in any comparison.

## Trigger rules

When the script starts the agent itself, it generates a benchmark Sigma trigger
rule under `sigma-benchmark/` and passes matching `EDR__` overrides so the agent
uses the requested corpus. Pass `-NoBenchmarkTriggerRule` /
`--no-benchmark-trigger-rule` only when the existing configuration already
contains the alert trigger rule you intend to measure, and pair it with
`-AlertRuleName` / `--alert-rule-name`.

## Isolated workloads

Use these when a drop or regression needs root-cause work. Each selector runs
exactly one workload.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
  -Mode with-agent -ProcessOnly `
  -SigmaRulesPath .\rules-bench\sigma `
  -YaraRulesPath .\rules-bench\yara `
  -IocRulesPath .\rules-bench\ioc `
  -AlertRuleName "Local Accounts Discovery" `
  -NoBenchmarkTriggerRule
```

`-FileOnly` and `-CargoOnly` take the same shape; Linux uses `--process-only`,
`--file-only`, and `--cargo-only`.

Interpretation:

- **Process-only drops** point at the process ETW callback, queueing,
  normalization, or rule-evaluation pressure.
- **File-only drops** point at the same path for file events.
- **Cargo-only drops** usually indicate common ingestion or build-time host
  noise rather than cargo itself.

### Cargo-only on Windows

Do not launch the agent from `target\release\rustinel.exe` for cargo workloads,
Windows can lock the executable while the benchmark's cargo step tries to
rebuild it. Copy it first:

```powershell
New-Item -ItemType Directory -Force .\target\rustinel-bench-agent | Out-Null
Copy-Item .\target\release\rustinel.exe .\target\rustinel-bench-agent\rustinel.exe -Force

powershell -ExecutionPolicy Bypass -File .\scripts\bench\windows.ps1 `
  -Mode with-agent -CargoOnly `
  -AgentPath .\target\rustinel-bench-agent\rustinel.exe `
  -SigmaRulesPath .\rules-bench\sigma `
  -YaraRulesPath .\rules-bench\yara `
  -IocRulesPath .\rules-bench\ioc `
  -AlertRuleName "Local Accounts Discovery" `
  -NoBenchmarkTriggerRule
```

## Linux sudo handling

The script calls `sudo -v` before starting the background agent, then starts the
agent through sudo while keeping workloads under the normal user. For
non-interactive lab runs, set `SUDO_ASKPASS` to an askpass helper. Never commit
askpass helpers or passwords.

## Drop signals in logs

```text
Pipeline channel full; shedding telemetry channel="sensor_events" ...
YARA queue full; dropping scan job
IOC hash queue full; dropping job
Active response queue full, dropping task
```

`dropped_total` in the pipeline line is cumulative per agent run, so the last
line for a channel is its running total. Prefer `rustinel doctor --json` over
log scraping.

## Hygiene

Do not commit generated benchmark output directories, logs, copied binaries, or
temporary scripts.
