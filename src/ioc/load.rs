use super::types::{DomainIocs, HashIocs, IocMeta, IpIocs, PathIocs};
use crate::models::AlertSeverity;
use ipnetwork::IpNetwork;
use regex::{Regex, RegexSetBuilder};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::{info, warn};

pub(crate) fn parse_severity(value: &str) -> AlertSeverity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => AlertSeverity::Critical,
        "high" => AlertSeverity::High,
        "medium" => AlertSeverity::Medium,
        "low" => AlertSeverity::Low,
        other => {
            warn!(
                target: "ioc",
                severity = %other,
                "Unknown ioc.default_severity; defaulting to high"
            );
            AlertSeverity::High
        }
    }
}

fn split_value_and_comment(line: &str) -> (String, Option<String>) {
    let mut parts = line.splitn(2, ';');
    let value = parts.next().unwrap_or("").trim().to_string();
    let comment = parts
        .next()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    (value, comment)
}

fn should_skip_line(line: &str) -> bool {
    line.is_empty() || line.starts_with('#') || line.starts_with("//")
}

fn read_lines(path: &Path) -> Vec<(usize, String)> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            warn!(
                target: "ioc",
                path = ?path,
                error = %err,
                "IOC file missing or unreadable"
            );
            return Vec::new();
        }
    };

    content
        .lines()
        .enumerate()
        .map(|(idx, line)| (idx + 1, line.to_string()))
        .collect()
}

pub(crate) fn load_hashes(path: &Path) -> HashIocs {
    let mut iocs = HashIocs::default();
    let source = path.display().to_string();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        let normalized = value.to_ascii_lowercase();
        let meta = IocMeta {
            comment,
            source: source.clone(),
            line: line_no,
        };

        if !is_hex(&normalized) {
            warn!(
                target: "ioc",
                path = %source,
                line = line_no,
                value = %value,
                "Invalid hash (non-hex), skipping"
            );
            continue;
        }

        match normalized.len() {
            32 => {
                iocs.md5.insert(normalized, meta);
            }
            40 => {
                iocs.sha1.insert(normalized, meta);
            }
            64 => {
                iocs.sha256.insert(normalized, meta);
            }
            _ => {
                warn!(
                    target: "ioc",
                    path = %source,
                    line = line_no,
                    value = %value,
                    "Invalid hash length, skipping"
                );
            }
        }
    }

    info!(
        target: "ioc",
        md5 = iocs.md5.len(),
        sha1 = iocs.sha1.len(),
        sha256 = iocs.sha256.len(),
        "Loaded hash IOCs"
    );

    iocs
}

pub(crate) fn load_ips(path: &Path) -> IpIocs {
    let mut iocs = IpIocs::default();
    let source = path.display().to_string();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        let meta = IocMeta {
            comment,
            source: source.clone(),
            line: line_no,
        };

        if value.contains('/') {
            match value.parse::<IpNetwork>() {
                Ok(network) => iocs.cidr.push((network, meta)),
                Err(err) => warn!(
                    target: "ioc",
                    path = %source,
                    line = line_no,
                    value = %value,
                    error = %err,
                    "Invalid CIDR, skipping"
                ),
            }
        } else {
            match value.parse::<IpAddr>() {
                Ok(ip) => {
                    iocs.exact.insert(ip, meta);
                }
                Err(err) => warn!(
                    target: "ioc",
                    path = %source,
                    line = line_no,
                    value = %value,
                    error = %err,
                    "Invalid IP, skipping"
                ),
            }
        }
    }

    info!(
        target: "ioc",
        ip = iocs.exact.len(),
        cidr = iocs.cidr.len(),
        "Loaded IP IOCs"
    );

    iocs
}

fn is_hex(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn load_domains(path: &Path) -> DomainIocs {
    let mut iocs = DomainIocs::default();
    let source = path.display().to_string();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        let meta = IocMeta {
            comment,
            source: source.clone(),
            line: line_no,
        };

        let mut normalized = value.to_ascii_lowercase();
        normalized = normalized.trim_end_matches('.').to_string();

        if normalized.starts_with("*.") {
            normalized = format!(".{}", normalized.trim_start_matches("*."));
        }

        if normalized.starts_with('.') {
            let suffix = normalized.trim_start_matches('.').to_string();
            if !suffix.is_empty() {
                iocs.suffix.push((suffix, meta));
            }
        } else {
            iocs.exact.insert(normalized, meta);
        }
    }

    info!(
        target: "ioc",
        exact = iocs.exact.len(),
        suffix = iocs.suffix.len(),
        "Loaded domain IOCs"
    );

    iocs
}

pub(crate) fn load_path_regexes(path: &Path) -> PathIocs {
    let mut iocs = PathIocs::default();
    let source = path.display().to_string();
    let mut patterns = Vec::new();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        if let Err(err) = Regex::new(value) {
            warn!(
                target: "ioc",
                path = %source,
                line = line_no,
                pattern = %value,
                error = %err,
                "Invalid path regex, skipping"
            );
            continue;
        }

        iocs.patterns.push((
            value.to_string(),
            IocMeta {
                comment,
                source: source.clone(),
                line: line_no,
            },
        ));
        patterns.push(value.to_string());
    }

    if !patterns.is_empty() {
        let regex_set = RegexSetBuilder::new(patterns)
            .case_insensitive(true)
            .build();
        match regex_set {
            Ok(set) => iocs.regex_set = Some(set),
            Err(err) => warn!(
                target: "ioc",
                path = %source,
                error = %err,
                "Failed to build path regex set"
            ),
        }
    }

    info!(
        target: "ioc",
        count = iocs.patterns.len(),
        "Loaded path regex IOCs"
    );

    iocs
}
