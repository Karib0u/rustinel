# IOC metadata sharing measurement

Local measurements for [issue #410](https://github.com/Karib0u/rustinel/issues/410),
comparing base `2cf83757751acfd09fe74c5c3c9ad2bdc01c6157` with the local
`Arc<str>` source and per-file comment interning change. Both builds use the
same `examples/ioc_load.rs` harness and lockfile.

## Method

Measured on 2026-09-10, Apple M1 Max, 64 GiB RAM, macOS 26.6.2 arm64,
Rust 1.96.0, with `cargo build --locked --release --example ioc_load`.
The harness times `IocEngine::load`, prints counts and elapsed milliseconds,
then keeps the engine alive until stdin receives a newline. RSS is read with
`ps -o rss= -p PID` after the ready line. This is resident process memory after
loading, including allocator-retained pages, not peak RSS or live heap size.

The synthetic feed contains 2,121,596 distinct wildcard domains and four
repeated comments, totaling 65,769,476 bytes. It is not the Radegast corpus
from the issue. Generate it outside the measurement process:

```python
from pathlib import Path
path = Path('/tmp/rustinel-ioc-410-benchmark-feeds-malware/domains.txt')
path.parent.mkdir(parents=True, exist_ok=True)
with path.open('w') as feed:
    for i in range(2_121_596):
        feed.write(f'*.feed{i:07d}.invalid; threat{i % 4}\n')
```

Save the baseline and updated example executables as `/tmp/rustinel-410-before`
and `/tmp/rustinel-410-after`. After builds finish, run five fresh processes
per version, alternating order each round, against the same cached feed:

```python
import subprocess
for run in range(5):
    order = ['before', 'after'] if run % 2 == 0 else ['after', 'before']
    for version in order:
        process = subprocess.Popen(
            ['/tmp/rustinel-410-' + version,
             '/tmp/rustinel-ioc-410-benchmark-feeds-malware/domains.txt'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        ready = process.stdout.readline().strip()
        rss = subprocess.check_output(
            ['ps', '-o', 'rss=', '-p', str(process.pid)], text=True).strip()
        process.communicate('\n')
        assert process.returncode == 0
        print(run + 1, version, ready, 'rss_kib=' + rss)
```

The public engine reports exactly 2,121,596 suffix entries and zero exact
entries for every measured process. Feed generation, compilation, and engine
destruction are excluded from load time. This is a shared development machine;
load times remain sensitive to unrelated host activity.

## Results

| Run | Before load (ms) | After load (ms) | Before RSS (MiB) | After RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 1386.131 | 1231.219 | 585.05 | 406.33 |
| 2 | 1367.485 | 1206.723 | 630.98 | 406.36 |
| 3 | 1363.969 | 1221.076 | 585.88 | 406.78 |
| 4 | 1353.136 | 1229.880 | 633.00 | 406.80 |
| 5 | 1350.276 | 1217.531 | 630.50 | 406.91 |
| Median | 1363.969 | 1221.076 | 630.50 | 406.78 |

Median RSS decreased by 223.72 MiB (35.5%). Median load
time decreased by 142.893 ms (10.5%). The baseline RSS
varied more across runs, so the individual samples are retained above.

Validation: `cargo test --locked --release` passed 514 tests with 8 ignored;
`cargo clippy --locked --all-targets -- -D clippy::all` and
`cargo fmt --all -- --check` passed. Allocation identity tests cover all four
loaders; integration tests verify public match metadata, including duplicate
wildcards, absent comments, and comments containing semicolons.
