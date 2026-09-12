//! The generated regions of `docs/cli.md` and `docs/configuration.md` must match
//! their sources. Regenerate with `cargo run --bin generate-docs`.

use rustinel::cli::reference::{self as cli_reference, cli_markdown};
use rustinel::config::reference::{
    self as config_reference, configuration_markdown, default_keys, CONFIG_OPTIONS, CONFIG_SECTIONS,
};

fn region<'a>(document: &'a str, begin: &str, end: &str) -> &'a str {
    let start = document.find(begin).expect("generated section starts");
    let stop = document[start..]
        .find(end)
        .map(|offset| start + offset + end.len())
        .expect("generated section ends");
    &document[start..stop]
}

#[test]
fn cli_reference_is_current() {
    let page = include_str!("../docs/cli.md");
    assert_eq!(
        region(page, cli_reference::BEGIN, cli_reference::END),
        cli_markdown().trim_end(),
        "docs/cli.md is stale: run `cargo run --bin generate-docs`"
    );
}

#[test]
fn configuration_reference_is_current() {
    let page = include_str!("../docs/configuration.md");
    assert_eq!(
        region(page, config_reference::BEGIN, config_reference::END),
        configuration_markdown().trim_end(),
        "docs/configuration.md is stale: run `cargo run --bin generate-docs`"
    );
}

#[test]
fn every_configuration_option_is_documented_once() {
    let mut documented: Vec<String> = CONFIG_OPTIONS
        .iter()
        .map(|option| option.key.to_string())
        .collect();
    documented.sort();
    let before = documented.len();
    documented.dedup();
    assert_eq!(before, documented.len(), "an option is documented twice");
    assert_eq!(
        documented,
        default_keys(),
        "CONFIG_OPTIONS in src/config/reference.rs must list exactly the AppConfig options"
    );
}

#[test]
fn every_documented_option_belongs_to_a_section() {
    for option in CONFIG_OPTIONS {
        let section = option.key.split('.').next().unwrap_or_default();
        assert!(
            CONFIG_SECTIONS.iter().any(|known| known.name == section),
            "{} has no entry in CONFIG_SECTIONS",
            option.key
        );
    }
}
