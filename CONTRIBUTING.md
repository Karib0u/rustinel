# Contributing to Rustinel

## Getting started

See [docs/development.md](docs/development.md) for the full build matrix, toolchain requirements, and fastest local build paths.

Quick start:
```sh
cargo check          # fast syntax + type check
cargo test           # run the test suite
cargo clippy --all-targets -- -D clippy::all
cargo fmt --all
```

For Linux eBPF development you need nightly Rust, `rust-src`, and `bpf-linker`. See `docs/development.md` for details.

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes and ensure `cargo test`, `cargo clippy`, and `cargo fmt` all pass
3. Add or update tests if behaviour changed
4. **Add a label** to your PR before requesting review. This drives release notes:
   - `enhancement`: new feature
   - `bug`: bug fix
   - `refactor`: refactoring
   - `documentation`: docs only
   - `ci`: CI/CD changes
5. Open a PR against `main`

## Writing documentation

The docs in `docs/` are organized so that every topic has exactly one home.
Keeping that property is what keeps them short and trustworthy.

- **One canonical home per topic.** If a topic already has a section elsewhere,
  reference it with a link instead of restating it. Two copies of a fact become
  two different facts within a release or two.
- **Reference pages state behavior; rationale goes elsewhere.** Design
  arguments, benchmark methodology, and "why we chose this" belong in
  `limitations.md`, the issue, or the PR, not in an option table.
- **No dated results in prose.** Link to the source of truth rather than
  embedding measurements that will rot. If a number must appear, say what it was
  measured against and cite the issue or PR.
- **Every page opens with one or two lines** saying who it is for and what
  question it answers.
- **Mark silent risks.** In `limitations.md`, anything that makes a rule fail to
  fire with no error is tagged **silent risk**. That tag is the most useful
  thing on the page, so keep applying it.
- Rough budget: no page over ~300 lines. `troubleshooting.md` is the exception
  and may grow as symptoms accumulate.

When a change alters observable behavior, grep the docs for the old behavior
before opening the PR. Stale claims in a second page are the most common docs
bug in this repo.

## Reporting security vulnerabilities

See [SECURITY.md](SECURITY.md). Do not open a public issue for security reports.
