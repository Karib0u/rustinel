use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

const BEGIN: &str = "<!-- BEGIN GENERATED FIELD AVAILABILITY -->";
const END: &str = "<!-- END GENERATED FIELD AVAILABILITY -->";

fn replace_region(path: &Path, generated: &str) -> Result<()> {
    let current = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let start = current
        .find(BEGIN)
        .with_context(|| format!("{} has no generated-section start marker", path.display()))?;
    let end = current[start..]
        .find(END)
        .map(|offset| start + offset + END.len())
        .with_context(|| format!("{} has no generated-section end marker", path.display()))?;
    let mut updated = String::with_capacity(current.len() + generated.len());
    updated.push_str(&current[..start]);
    updated.push_str(generated.trim_end());
    updated.push_str(&current[end..]);
    fs::write(path, updated).with_context(|| format!("write {}", path.display()))
}

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::write(
        root.join("compatibility/field-availability.json"),
        rustinel::field_availability::compatibility_json(),
    )
    .context("write field availability compatibility baseline")?;
    replace_region(
        &root.join("docs/limitations.md"),
        &rustinel::field_availability::limitations_markdown(),
    )?;
    replace_region(
        &root.join("docs/coverage.md"),
        &rustinel::field_availability::coverage_markdown(),
    )?;
    Ok(())
}
