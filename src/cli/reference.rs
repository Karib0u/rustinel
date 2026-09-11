//! Markdown CLI reference generated from the clap definitions.
//!
//! `docs/cli.md` embeds [`cli_markdown`] between generated-section markers, so
//! the published reference cannot drift from `rustinel --help`. Regenerate it
//! with `cargo run --bin generate-docs`.

use clap::{Arg, ArgAction, Command, CommandFactory};

use super::Cli;

pub const BEGIN: &str = "<!-- BEGIN GENERATED CLI REFERENCE -->";
pub const END: &str = "<!-- END GENERATED CLI REFERENCE -->";

/// The generated region of `docs/cli.md`, markers included.
pub fn cli_markdown() -> String {
    let mut root = Cli::command();
    root.build();

    let mut out = String::new();
    out.push_str(BEGIN);
    out.push_str(
        "\nThis section is generated from the clap definitions in `src/cli/mod.rs`. \
Edit those and run `cargo run --bin generate-docs`.\n\n",
    );

    out.push_str("## Global options\n\nAccepted by every command.\n\n");
    let mut rows: Vec<&Arg> = root
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .collect();
    rows.sort_by_key(|arg| arg.get_long().unwrap_or_default().to_string());
    push_table(&mut out, rows.into_iter());
    out.push_str("| `--help` | Print help. |\n| `--version` | Print the version. |\n\n");

    for command in root.get_subcommands() {
        push_command(&mut out, command, 2);
    }

    out.push_str(END);
    out.push('\n');
    out
}

fn push_command(out: &mut String, command: &Command, depth: usize) {
    if command.is_hide_set() || command.get_name() == "help" {
        return;
    }
    let path = command
        .get_bin_name()
        .map(str::to_string)
        .unwrap_or_else(|| format!("rustinel {}", command.get_name()));
    out.push_str(&format!("{} `{}`\n\n", "#".repeat(depth), path));

    if let Some(about) = command.get_long_about().or_else(|| command.get_about()) {
        let paragraphs: Vec<String> = about
            .to_string()
            .trim()
            .split("\n\n")
            .map(|paragraph| {
                let mut text = paragraph.split_whitespace().collect::<Vec<_>>().join(" ");
                if !text.ends_with('.') {
                    text.push('.');
                }
                escape_markdown(&text)
            })
            .collect();
        out.push_str(&paragraphs.join("\n\n"));
        out.push_str("\n\n");
    }

    let subcommands: Vec<&Command> = command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
        .collect();
    if !subcommands.is_empty() {
        for sub in subcommands {
            push_command(out, sub, depth + 1);
        }
        return;
    }

    out.push_str(&format!("```text\n{}\n```\n\n", usage(command, &path)));

    let args: Vec<&Arg> = command
        .get_arguments()
        .filter(|arg| documented(arg))
        .collect();
    if !args.is_empty() {
        push_table(out, args.into_iter());
        out.push('\n');
    }
}

fn usage(command: &Command, path: &str) -> String {
    let mut parts = vec![path.to_string()];
    for arg in command.get_arguments().filter(|arg| documented(arg)) {
        let rendered = arg_label(arg);
        if arg.is_positional() && arg.is_required_set() {
            parts.push(rendered);
        } else {
            parts.push(format!("[{rendered}]"));
        }
    }
    parts.join(" ")
}

/// Arguments listed per command: global options are listed once, and clap's
/// generated `--help` and `--version` are listed with them.
fn documented(arg: &Arg) -> bool {
    let id = arg.get_id().as_str();
    !arg.is_hide_set() && !arg.is_global_set() && id != "help" && id != "version"
}

fn push_table<'a>(out: &mut String, args: impl Iterator<Item = &'a Arg>) {
    out.push_str("| Option | Description |\n| --- | --- |\n");
    for arg in args {
        let mut description = arg
            .get_long_help()
            .or_else(|| arg.get_help())
            .map(|help| help.to_string())
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !description.is_empty() && !description.ends_with('.') {
            description.push('.');
        }
        let mut description = escape_markdown(&description);

        let is_flag = matches!(arg.get_action(), ArgAction::SetTrue | ArgAction::SetFalse);
        let possible: Vec<String> = arg
            .get_possible_values()
            .iter()
            .filter(|value| !value.is_hide_set())
            .map(|value| format!("`{}`", value.get_name()))
            .collect();
        if !possible.is_empty() && !is_flag {
            description.push_str(&format!(" One of {}.", possible.join(", ")));
        }
        let defaults: Vec<String> = arg
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        if !defaults.is_empty() && !is_flag {
            description.push_str(&format!(" Default: `{}`.", defaults.join(", ")));
        }
        out.push_str(&format!(
            "| `{}` | {} |\n",
            arg_label(arg),
            description.trim()
        ));
    }
}

fn arg_label(arg: &Arg) -> String {
    let value = arg
        .get_value_names()
        .and_then(|names| names.first())
        .map(|name| name.to_string())
        .unwrap_or_else(|| arg.get_id().as_str().to_ascii_uppercase());
    if arg.is_positional() {
        return format!("<{value}>");
    }
    let flag = arg
        .get_long()
        .map(|long| format!("--{long}"))
        .or_else(|| arg.get_short().map(|short| format!("-{short}")))
        .unwrap_or_else(|| arg.get_id().to_string());
    if matches!(arg.get_action(), ArgAction::SetTrue | ArgAction::SetFalse) {
        flag
    } else {
        format!("{flag} <{value}>")
    }
}

/// Escape text that Markdown or the table syntax would otherwise swallow,
/// leaving inline code spans untouched.
fn escape_markdown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (index, segment) in text.split('`').enumerate() {
        if index > 0 {
            out.push('`');
        }
        if index % 2 == 1 {
            out.push_str(segment);
            continue;
        }
        for ch in segment.chars() {
            match ch {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '|' => out.push_str("\\|"),
                _ => out.push(ch),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_leaves_code_spans_alone() {
        assert_eq!(
            escape_markdown("<dir>/x `a<b>` | y"),
            "&lt;dir&gt;/x `a<b>` \\| y"
        );
    }

    #[test]
    fn every_subcommand_is_documented() {
        let markdown = cli_markdown();
        for command in Cli::command().get_subcommands() {
            assert!(
                markdown.contains(&format!("`rustinel {}", command.get_name())),
                "{} is missing from the CLI reference",
                command.get_name()
            );
        }
    }
}
