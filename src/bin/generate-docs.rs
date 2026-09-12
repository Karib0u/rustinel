//! Regenerates every generated region in `docs/` plus the field availability
//! baseline. Run with `cargo run --bin generate-docs`; tests fail when a
//! checked-in region no longer matches its source.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

const FIELD_BEGIN: &str = "<!-- BEGIN GENERATED FIELD AVAILABILITY -->";
const FIELD_END: &str = "<!-- END GENERATED FIELD AVAILABILITY -->";

fn replace_region(path: &Path, begin: &str, end: &str, generated: &str) -> Result<()> {
    let current = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let start = current
        .find(begin)
        .with_context(|| format!("{} has no {begin} marker", path.display()))?;
    let stop = current[start..]
        .find(end)
        .map(|offset| start + offset + end.len())
        .with_context(|| format!("{} has no {end} marker", path.display()))?;
    let mut updated = String::with_capacity(current.len() + generated.len());
    updated.push_str(&current[..start]);
    updated.push_str(generated.trim_end());
    updated.push_str(&current[stop..]);
    fs::write(path, updated).with_context(|| format!("write {}", path.display()))
}

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = root.join("docs");

    fs::write(
        root.join("compatibility/field-availability.json"),
        rustinel::field_availability::compatibility_json(),
    )
    .context("write field availability compatibility baseline")?;
    replace_region(
        &docs.join("field-availability.md"),
        FIELD_BEGIN,
        FIELD_END,
        &rustinel::field_availability::unavailable_fields_markdown(),
    )?;
    replace_region(
        &docs.join("coverage.md"),
        FIELD_BEGIN,
        FIELD_END,
        &rustinel::field_availability::coverage_markdown(),
    )?;
    replace_region(
        &docs.join("cli.md"),
        rustinel::cli::reference::BEGIN,
        rustinel::cli::reference::END,
        &rustinel::cli::reference::cli_markdown(),
    )?;
    replace_region(
        &docs.join("configuration.md"),
        rustinel::config::reference::BEGIN,
        rustinel::config::reference::END,
        &rustinel::config::reference::configuration_markdown(),
    )?;
    Ok(())
}
