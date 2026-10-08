//! Enforces the one-way module dependency direction described in `docs/architecture.md`.
//!
//! A top-level module may import `crate::<other>` only when `<other>` sits in the same layer or a lower one.
//! `ALLOWED_UPWARD` lists the upward edges that still exist.
//! The list may only shrink: a new upward edge fails this test, and so does a stale entry for an edge that is gone.
//! Test-only code (`#[cfg(test)] mod ... { }` bodies and `tests.rs` files) is not part of the production graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Layers from the leaf up.
/// A module may depend on its own layer and on every layer before it.
const LAYERS: &[&[&str]] = &[
    // Shared vocabulary. Imports nothing.
    &["vocab", "signature"],
    // Foundation: data models, configuration, and helpers.
    &[
        "field_availability",
        "observable",
        "models",
        "utils",
        "config",
    ],
    &["telemetry"],
    &["state"],
    // Platform sensors and the shared raw-event boundary.
    &["sensor"],
    &["normalizer"],
    // Detectors, sinks, and workers.
    &["memory", "alerts", "response", "ioc", "scanner", "capture"],
    &["engine"],
    // Pipeline stages between the engine and artifact resolution.
    &["stages"],
    &["artifact"],
    // Features built on the pipeline.
    &[
        "reload", "replay", "platform", "service", "rules", "cli", "update",
    ],
    &["doctor", "setup"],
    // Wiring. Nothing below may import it.
    &["runtime"],
];

/// Upward edges that still exist, as `(from, to)`.
/// Remove an entry when its edge is cut. Never add one.
const ALLOWED_UPWARD: &[(&str, &str)] = &[
    // `HostState` builds a `Normalizer` over itself, and the normalizer needs a `HostState`.
    ("state", "normalizer"),
    // `HostState` converts `RawEvent`, which is declared in `sensor`.
    ("state", "sensor"),
    // Snapshot sources for telemetry.json.
    ("telemetry", "alerts"),
    ("telemetry", "artifact"),
    ("telemetry", "sensor"),
    ("telemetry", "state"),
    // Replay initialises runtime logging.
    ("replay", "runtime"),
    // The ETW session reads the process list through `platform::windows`.
    ("sensor", "platform"),
];

fn layer_of(module: &str) -> Option<usize> {
    LAYERS.iter().position(|layer| layer.contains(&module))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Drop comments and everything from the first `#[cfg(...test...)] mod name {` on.
fn production_text(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut kept = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.starts_with("#[cfg(") && line.contains("test") {
            let mut next = index + 1;
            while next < lines.len() && lines[next].trim_start().starts_with("#[") {
                next += 1;
            }
            let item = lines.get(next).map_or("", |l| l.trim_start());
            let item = item
                .strip_prefix("pub(crate) ")
                .or_else(|| item.strip_prefix("pub "))
                .unwrap_or(item);
            if item.starts_with("mod ") && item.trim_end().ends_with('{') {
                break;
            }
        }
        if !line.trim_start().starts_with("//") {
            kept.push(line);
        }
        index += 1;
    }
    kept.join("\n")
}

/// Every `crate::<module>` target named in `text`, including `crate::{a, b::c}` groups.
fn crate_targets(text: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    let mut rest = text;
    while let Some(at) = rest.find("crate::") {
        let before = rest[..at].chars().next_back();
        let after = &rest[at + "crate::".len()..];
        rest = after;
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':') {
            continue;
        }
        if let Some(group) = after.strip_prefix('{') {
            let end = group.find('}').unwrap_or(group.len());
            let mut word = String::new();
            let mut depth = 0;
            let mut at_start = true;
            for ch in group[..end].chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    ',' if depth == 0 => {
                        if !word.is_empty() {
                            targets.insert(std::mem::take(&mut word));
                        }
                        at_start = true;
                    }
                    c if depth == 0 && at_start && (c.is_alphanumeric() || c == '_') => {
                        word.push(c)
                    }
                    ':' if depth == 0 => at_start = false,
                    c if depth == 0 && at_start && c.is_whitespace() => {}
                    _ => at_start = false,
                }
            }
            if !word.is_empty() {
                targets.insert(word);
            }
        } else {
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                targets.insert(name);
            }
        }
    }
    targets
}

/// Production `crate::` edges between top-level modules, as `(from, to)`.
fn production_edges() -> BTreeMap<(String, String), Vec<String>> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut edges: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for file in files {
        let relative = file.strip_prefix(&src).unwrap();
        let mut parts = relative.components();
        let first = parts
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        if first == "bin" || first == "main.rs" || first == "lib.rs" {
            continue;
        }
        if file.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        let from = first.trim_end_matches(".rs").to_string();
        let text = production_text(&fs::read_to_string(&file).unwrap());
        for target in crate_targets(&text) {
            if target != from && layer_of(&target).is_some() {
                edges
                    .entry((from.clone(), target))
                    .or_default()
                    .push(relative.display().to_string());
            }
        }
    }
    edges
}

#[test]
fn every_top_level_module_has_a_layer() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        if matches!(name.as_str(), "lib" | "main" | "bin") {
            continue;
        }
        assert!(
            layer_of(&name).is_some(),
            "src/{name} has no layer in tests/module_dependencies.rs"
        );
    }
}

#[test]
fn no_new_upward_module_dependency() {
    let mut violations = Vec::new();
    for ((from, to), files) in production_edges() {
        let upward = layer_of(&to).unwrap() > layer_of(&from).unwrap();
        if upward && !ALLOWED_UPWARD.contains(&(from.as_str(), to.as_str())) {
            violations.push(format!("{from} -> {to} (in {})", files.join(", ")));
        }
    }
    assert!(
        violations.is_empty(),
        "upward module dependencies, see the direction in docs/architecture.md:\n{}",
        violations.join("\n")
    );
}

#[test]
fn allowlist_lists_only_existing_upward_edges() {
    let edges = production_edges();
    for (from, to) in ALLOWED_UPWARD {
        assert!(
            layer_of(to).unwrap() > layer_of(from).unwrap(),
            "{from} -> {to} is not an upward edge; remove it from ALLOWED_UPWARD"
        );
        assert!(
            edges.contains_key(&(from.to_string(), to.to_string())),
            "{from} -> {to} no longer exists; remove it from ALLOWED_UPWARD"
        );
    }
}
