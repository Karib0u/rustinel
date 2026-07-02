# Sigma Engine Benchmark

This documents the Criterion micro-benchmark that compares Rustinel's two Sigma detection backends: the built-in matcher (default) and the RSigma library engine (the `rsigma-engine` feature). It measures `Engine::check_event` in isolation.

This is not a whole-agent overhead benchmark. For idle CPU, alert latency, and sensor drop measurements of the running agent, see [docs/benchmarking.md](docs/benchmarking.md).

## Running

The Sigma backend is selected at compile time, so the benchmark is run once per backend and the results are labelled accordingly:

```sh
cargo bench --bench sigma_backend                          # built-in matcher
cargo bench --bench sigma_backend --features rsigma-engine # RSigma engine
```

Both runs share the same inputs, so the two Criterion baselines (`check_event/builtin/*` and `check_event/rsigma/*`) can be compared directly. The benchmark source is [benches/sigma_backend.rs](benches/sigma_backend.rs).

## What it measures

Each iteration runs `check_event` once over a fixed batch of five normalized events (process, network, file, DNS, and one non-matching process) against two rulesets:

- `mixed`: four matching rules, one per logsource family. A trivial ruleset where there is nothing to prune.
- `large`: the same four rules plus 500 synthetic, non-matching rules per family (about 2,000 rules total, a few hundred per candidate bucket). A realistic corpus where per-rule scanning cost dominates.

The synthetic rules are mostly literal matchers (`endswith`, `contains`) with a `cidr` family that neither engine indexes, so the large case is a conservative mix rather than a best case for indexing.

## Results

Indicative figures from a single macOS development machine (Criterion, 1s warm-up, 3s measurement, 50 samples, release profile). Absolute numbers are machine-dependent, so re-run locally before quoting them. Lower is better; the time is for one pass over all five events.

| Scenario | Ruleset | Built-in | RSigma | Delta |
|----------|---------|----------|--------|-------|
| `mixed`  | 4 rules | 10.9 µs | 11.6 µs | RSigma about 6% slower |
| `large`  | ~2,000 rules | 284 µs | 204 µs | RSigma about 28% faster (1.39x) |

## Interpretation

- On trivial rulesets the built-in matcher is marginally faster. RSigma carries a small fixed per-event cost (the `Event` adapter indirection and result construction), and with roughly one rule per bucket there is nothing to prune, so that overhead is the whole story. The gap is well under a microsecond per event.
- On realistic rulesets RSigma is clearly faster. With hundreds of rules per bucket the built-in matcher scans every rule in the candidate bucket linearly, while RSigma's inverted rule index skips rules whose literals cannot be present. The advantage grows with the rule count and with the share of literal (non-`cidr`) rules, so a full SigmaHQ-scale corpus would widen it.

## Caveats

- Single machine, `EventFields::Generic` events (HashMap lookups rather than the typed field variants), and one run per scenario.
- Both backends still use Rustinel's per-bucket logsource routing. A single-engine variant using RSigma's own `evaluate_with_logsource` could sharpen the large-ruleset result further.
- This isolates matching throughput. It excludes normalization, alert serialization, IOC/YARA, and the sensor pipeline, which the agent-overhead harness in [docs/benchmarking.md](docs/benchmarking.md) covers.
