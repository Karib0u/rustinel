//! Markdown configuration reference.
//!
//! Every option is listed in [`CONFIG_OPTIONS`] with a one-line description.
//! Defaults are read from [`AppConfig::default`], so `docs/configuration.md`
//! cannot show a stale default. Tests fail when an option is added to
//! `AppConfig` without an entry here. Regenerate the page region with
//! `cargo run --bin generate-docs`.

use super::AppConfig;

pub const BEGIN: &str = "<!-- BEGIN GENERATED CONFIG REFERENCE -->";
pub const END: &str = "<!-- END GENERATED CONFIG REFERENCE -->";

/// One configuration section and its summary line.
pub struct ConfigSection {
    pub name: &'static str,
    pub summary: &'static str,
}

/// One configuration option.
pub struct ConfigOption {
    /// Dotted key, such as `scanner.sigma_enabled`.
    pub key: &'static str,
    /// Replaces the computed default when it depends on the platform or on
    /// another option.
    pub default_note: Option<&'static str>,
    pub description: &'static str,
}

const INHERITS: Option<&str> = Some("inherits `allowlist.paths`");

pub const CONFIG_SECTIONS: &[ConfigSection] = &[
    ConfigSection {
        name: "scanner",
        summary: "Sigma and YARA rules, YARA scan limits, and optional memory scanning.",
    },
    ConfigSection {
        name: "allowlist",
        summary: "Trusted path prefixes shared by YARA, IOC hashing, and active response.",
    },
    ConfigSection {
        name: "reload",
        summary: "Hot reload of rules, indicators, and the `[response]` section.",
    },
    ConfigSection {
        name: "logging",
        summary: "The operational log.",
    },
    ConfigSection {
        name: "alerts",
        summary: "The ECS NDJSON alert file.",
    },
    ConfigSection {
        name: "dedup",
        summary: "Collapsing of repeated identical alerts.",
    },
    ConfigSection {
        name: "response",
        summary: "Optional process termination. Off by default.",
    },
    ConfigSection {
        name: "ioc",
        summary: "Indicator files for hashes, IPs, domains, and path patterns.",
    },
    ConfigSection {
        name: "process",
        summary: "The process cache used for parent and context enrichment.",
    },
    ConfigSection {
        name: "capture",
        summary: "Recordings written by `rustinel capture`.",
    },
    ConfigSection {
        name: "telemetry",
        summary: "The `telemetry.json` loss counters that `rustinel doctor` reads.",
    },
    ConfigSection {
        name: "windows",
        summary: "ETW delivery. Read on every platform so one file can serve a mixed fleet, used only on Windows.",
    },
];

pub const CONFIG_OPTIONS: &[ConfigOption] = &[
    // scanner
    ConfigOption {
        key: "scanner.sigma_enabled",
        default_note: None,
        description: "Evaluate Sigma rules.",
    },
    ConfigOption {
        key: "scanner.sigma_rules_path",
        default_note: None,
        description: "Sigma rules directory, loaded recursively.",
    },
    ConfigOption {
        key: "scanner.yara_enabled",
        default_note: None,
        description: "Scan executables with YARA when they start.",
    },
    ConfigOption {
        key: "scanner.yara_rules_path",
        default_note: None,
        description: "Directory of `.yar` and `.yara` files, loaded recursively.",
    },
    ConfigOption {
        key: "scanner.yara_allowlist_paths",
        default_note: INHERITS,
        description: "Path prefixes YARA never scans. Replaces `allowlist.paths` for YARA once set.",
    },
    ConfigOption {
        key: "scanner.yara_scan_timeout_ms",
        default_note: None,
        description: "Time limit for one file scan, or for all memory reads of one process. `0` disables it.",
    },
    ConfigOption {
        key: "scanner.yara_max_file_mb",
        default_note: None,
        description: "Larger files are reported as oversized instead of scanned. `0` disables the limit.",
    },
    ConfigOption {
        key: "scanner.yara_memory_enabled",
        default_note: None,
        description: "Also scan the memory of new processes. Needs `yara_enabled`.",
    },
    ConfigOption {
        key: "scanner.yara_memory_queue_capacity",
        default_note: None,
        description: "Pending memory scans. New scans are dropped when it is full.",
    },
    ConfigOption {
        key: "scanner.yara_memory_delay_ms",
        default_note: None,
        description: "Wait after process start before reading memory, so packed code can unpack.",
    },
    ConfigOption {
        key: "scanner.yara_memory_max_process_mb",
        default_note: None,
        description: "Stop reading a process after this many MB.",
    },
    ConfigOption {
        key: "scanner.yara_memory_max_region_mb",
        default_note: None,
        description: "Most memory read from one region at a time, in MB.",
    },
    ConfigOption {
        key: "scanner.yara_memory_include_private",
        default_note: None,
        description: "Scan private (anonymous) memory.",
    },
    ConfigOption {
        key: "scanner.yara_memory_include_image",
        default_note: None,
        description: "Scan memory backed by executables and libraries.",
    },
    ConfigOption {
        key: "scanner.yara_memory_include_mapped",
        default_note: None,
        description: "Scan memory-mapped files.",
    },
    // allowlist
    ConfigOption {
        key: "allowlist.paths",
        default_note: Some("OS directories, see below"),
        description: "Trusted path prefixes. Each module uses this list until its own allowlist is set.",
    },
    // reload
    ConfigOption {
        key: "reload.enabled",
        default_note: None,
        description: "Reload rules, indicators, and the `[response]` section when their files change.",
    },
    ConfigOption {
        key: "reload.debounce_ms",
        default_note: None,
        description: "Wait this long after the last change before reloading.",
    },
    ConfigOption {
        key: "reload.fallback_poll_interval_ms",
        default_note: None,
        description: "Poll interval, used only when the file watcher cannot start.",
    },
    // logging
    ConfigOption {
        key: "logging.level",
        default_note: None,
        description: "`trace`, `debug`, `info`, `warn`, or `error`.",
    },
    ConfigOption {
        key: "logging.filter",
        default_note: Some("unset"),
        description: "A `tracing` filter expression. Overrides `level` when valid.",
    },
    ConfigOption {
        key: "logging.directory",
        default_note: None,
        description: "Operational log directory.",
    },
    ConfigOption {
        key: "logging.filename",
        default_note: None,
        description: "Operational log file name. Rotated daily with a date suffix.",
    },
    ConfigOption {
        key: "logging.console_output",
        default_note: None,
        description: "Mirror the log to the console. `rustinel run` enables the console anyway; pass `--no-console` to turn it off.",
    },
    // alerts
    ConfigOption {
        key: "alerts.directory",
        default_note: None,
        description: "Alert directory.",
    },
    ConfigOption {
        key: "alerts.filename",
        default_note: None,
        description: "Alert file name. Rotated daily with a date suffix.",
    },
    ConfigOption {
        key: "alerts.match_debug",
        default_note: None,
        description: "Match detail added to alerts: `off`, `summary` (what matched), or `full` (also the matched values).",
    },
    // dedup
    ConfigOption {
        key: "dedup.enabled",
        default_note: None,
        description: "Collapse identical alerts within a window.",
    },
    ConfigOption {
        key: "dedup.window_secs",
        default_note: None,
        description: "Window length, counted from the first alert. Repeats do not extend it.",
    },
    ConfigOption {
        key: "dedup.max_entries",
        default_note: None,
        description: "Distinct alerts tracked at once.",
    },
    // response
    ConfigOption {
        key: "response.enabled",
        default_note: None,
        description: "Turn on the response engine.",
    },
    ConfigOption {
        key: "response.prevention_enabled",
        default_note: None,
        description: "Kill processes. When `false`, actions are only logged.",
    },
    ConfigOption {
        key: "response.min_severity",
        default_note: None,
        description: "Lowest alert severity that triggers a response: `low`, `medium`, `high`, or `critical`.",
    },
    ConfigOption {
        key: "response.channel_capacity",
        default_note: None,
        description: "Pending response actions. New ones are dropped when it is full. Read at startup only.",
    },
    ConfigOption {
        key: "response.allowlist_images",
        default_note: None,
        description: "Executable names or full paths that are never killed.",
    },
    ConfigOption {
        key: "response.allowlist_paths",
        default_note: INHERITS,
        description: "Path prefixes that are never killed. Replaces `allowlist.paths` for response once set.",
    },
    // ioc
    ConfigOption {
        key: "ioc.enabled",
        default_note: None,
        description: "Match indicator files.",
    },
    ConfigOption {
        key: "ioc.hashes_path",
        default_note: None,
        description: "MD5, SHA1, or SHA256 hashes, one per line.",
    },
    ConfigOption {
        key: "ioc.ips_path",
        default_note: None,
        description: "IP addresses and CIDR ranges.",
    },
    ConfigOption {
        key: "ioc.domains_path",
        default_note: None,
        description: "Domains. A leading `.` or `*.` also matches subdomains.",
    },
    ConfigOption {
        key: "ioc.paths_regex_path",
        default_note: None,
        description: "Path regular expressions, matched case-insensitively.",
    },
    ConfigOption {
        key: "ioc.default_severity",
        default_note: None,
        description: "Severity of IOC alerts: `low`, `medium`, `high`, or `critical`.",
    },
    ConfigOption {
        key: "ioc.max_file_size_mb",
        default_note: None,
        description: "Larger executables are not hashed.",
    },
    ConfigOption {
        key: "ioc.hash_allowlist_paths",
        default_note: INHERITS,
        description: "Path prefixes that are never hashed. Replaces `allowlist.paths` for hashing once set.",
    },
    // process
    ConfigOption {
        key: "process.max_entries",
        default_note: None,
        description: "Process records kept. The oldest are evicted first.",
    },
    // capture
    ConfigOption {
        key: "capture.directory",
        default_note: None,
        description: "Where `rustinel capture` writes recordings when `--output` is not given.",
    },
    // telemetry
    ConfigOption {
        key: "telemetry.enabled",
        default_note: None,
        description: "Write `telemetry.json` to the log directory.",
    },
    ConfigOption {
        key: "telemetry.snapshot_interval_secs",
        default_note: None,
        description: "How often `telemetry.json` is rewritten. It is also written at shutdown.",
    },
    // windows
    ConfigOption {
        key: "windows.etw_flush_interval_ms",
        default_note: None,
        description: "How often the main ETW session hands over partly filled buffers. Lower is faster alerting. `0` falls back to the 1 second ETW timer. Values below 20 are raised to 20.",
    },
    ConfigOption {
        key: "windows.etw_process_flush_interval_ms",
        default_note: None,
        description: "The same for the process session. Keep it at 10 or below: the command line is read from the live process, so slower values lose it for short-lived processes, and `0` loses most of them.",
    },
];

/// The generated region of `docs/configuration.md`, markers included.
pub fn configuration_markdown() -> String {
    let defaults =
        serde_json::to_value(AppConfig::default()).expect("default configuration serializes");

    let mut out = String::new();
    out.push_str(BEGIN);
    out.push_str(
        "\nThis section is generated from `src/config/reference.rs`. Edit that file \
and run `cargo run --bin generate-docs`.\n",
    );

    for section in CONFIG_SECTIONS {
        out.push_str(&format!(
            "\n### `[{}]`\n\n{}\n\n",
            section.name, section.summary
        ));
        out.push_str("| Option | Default | Description |\n| --- | --- | --- |\n");
        let prefix = format!("{}.", section.name);
        for option in CONFIG_OPTIONS
            .iter()
            .filter(|option| option.key.starts_with(&prefix))
        {
            let name = &option.key[prefix.len()..];
            let default = match option.default_note {
                Some(note) => note.to_string(),
                None => format!("`{}`", toml_literal(&defaults[section.name][name])),
            };
            out.push_str(&format!(
                "| `{name}` | {default} | {} |\n",
                option.description
            ));
        }
    }

    out.push_str(END);
    out.push('\n');
    out
}

/// Every leaf key of the default configuration, dotted.
pub fn default_keys() -> Vec<String> {
    let defaults =
        serde_json::to_value(AppConfig::default()).expect("default configuration serializes");
    let mut keys = Vec::new();
    if let serde_json::Value::Object(sections) = defaults {
        for (section, value) in sections {
            if let serde_json::Value::Object(options) = value {
                keys.extend(options.keys().map(|key| format!("{section}.{key}")));
            }
        }
    }
    keys.sort();
    keys
}

fn toml_literal(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => format!("\"{text}\""),
        serde_json::Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(toml_literal)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        serde_json::Value::Null => "unset".to_string(),
        other => other.to_string(),
    }
}
