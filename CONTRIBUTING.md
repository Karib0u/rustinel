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

For Linux eBPF development you need nightly Rust, `rust-src`, and `bpf-linker`.
See `docs/development.md` for details.

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes and ensure `cargo test`, `cargo clippy`, and `cargo fmt` all pass
3. Add or update tests if behaviour changed
4. **Add a label** to your PR before requesting review.
   This drives release notes:
   - `enhancement`: new feature
   - `performance`: performance improvement
   - `bug`: bug fix
   - `refactor`: refactoring
   - `documentation`: docs only
   - `ci`: CI/CD changes
   - `dependencies`: dependency update
   - `chore`: other maintenance
   - `breaking-change`: breaking change (takes priority over other categories)
   - `skip-changelog`: release preparation or changes with no release-note value
5. Open a PR against `main`

## Preparing a release

In the `chore(release)` preparation PR, add `.github/release-notes/<version>.md` using the exact tag version without the leading `v` (for example, `1.6.0.md` or `1.7.0-rc.1.md`).
Start with `## Highlights` and write 3 to 5 bullets explaining user-visible improvements.
Add `## Upgrade notes` when users need to change configuration, integrations, or deployment steps.
Review these notes with the PR.
See [the 1.6.0 notes](.github/release-notes/1.6.0.md) for an example.

Label the preparation PR `skip-changelog` so the version bump does not appear in the generated list.
Before tagging, check that the release's PRs have appropriate labels, especially `breaking-change` and `performance`.
Categories use PR labels, not conventional title prefixes.
Breaking changes take priority, followed by Performance, so a performance PR can also carry a feature or bug label.

The release workflow requires a nonempty notes file matching the tag.
It places those reviewed notes before downloads and installation instructions, then appends GitHub's generated PR list and full comparison link.
Refactoring, CI, and chores are grouped under Maintenance.
Keep notes for previous versions in place.

## Writing documentation

The docs are for people running and writing rules for Rustinel.
Keep them short: a reader should find the command or the answer in seconds.

**Every page has one job.**
Put new content on the page of the right kind:

| Kind | Answers | Examples |
| --- | --- | --- |
| Get started | How do I install and see it work? | `installation.md`, `getting-started.md` |
| Guide | How do I do this task? | `rule-packs.md`, `upgrade.md` |
| Concept | How does this work? | `how-it-works.md`, `telemetry-loss.md` |
| Reference | What exactly does this option, field, or check do? | `cli.md`, `configuration.md`, `doctor.md` |
| Contributing | How is the code built and tested? | `development.md`, `architecture.md` |

**Rules:**

1. **Describe current behavior.**
   No issue or PR numbers, dates, versions, or words like "now", "since", "previously", or "no longer".
   History goes in the release notes.
2. **No lab results in the docs.**
   Measurements, validation runs, and test counts go in the PR description.
   A number belongs in the docs only when it changes what the reader does, such as a limit or a default.
3. **Say it once.**
   Each fact has one home.
   Link to it from everywhere else.
4. **Command first.**
   Show what to run, then explain only what the reader needs.
5. **Short.**
   Paragraphs of three sentences or fewer.
   Tables for options and fields.
   No page over about 300 lines, except generated reference.
6. **No source paths or type names** outside the Contributing pages.
7. **Mark silent failures.**
   In `limitations.md`, start an item with **Silent:** when it makes a rule stop firing with no error.
8. **Plain punctuation.**
   No em dashes: use commas, colons, or a new sentence.
9. **One sentence per line.**
   Start a new line only after a sentence ends, never in the middle of a sentence or inside a code span.
   Do not hard-wrap at a column width.
   `python3 scripts/docs/reflow.py <files>` fixes a file, and CI runs it with `--check`.

**Generated sections.**
The CLI reference, the configuration options, and the field availability tables are generated from code.
Edit the source (`src/cli/mod.rs`, `src/config/reference.rs`, `src/field_availability.rs`) and run `cargo run --bin generate-docs`.
Tests fail when a generated section is stale, and when a config option has no description.

**Before opening a PR** that changes behavior, search the docs for the old behavior and update every page that mentions it.
Preview with `zensical serve`; CI builds the site in strict mode.

## Reporting security vulnerabilities

See [SECURITY.md](SECURITY.md).
Do not open a public issue for security reports.
