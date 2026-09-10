use super::types::{DomainIocs, HashIocs, IocMeta, IpIocs, PathIocs};
use crate::models::AlertSeverity;
use ipnetwork::IpNetwork;
use regex::{Regex, RegexSetBuilder};
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
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

fn split_value_and_comment(line: &str) -> (&str, Option<&str>) {
    let mut parts = line.splitn(2, ';');
    let value = parts.next().unwrap_or("").trim();
    let comment = parts.next().map(str::trim).filter(|v| !v.is_empty());
    (value, comment)
}

// Scoped to one file load: the temporary index is dropped after loading, while
// metadata retains the shared strings. Reloads do not retain obsolete comments.
fn intern_comment(comment: Option<&str>, comments: &mut HashSet<Arc<str>>) -> Option<Arc<str>> {
    comment.map(|text| {
        if let Some(shared) = comments.get(text) {
            return Arc::clone(shared);
        }
        let shared: Arc<str> = Arc::from(text);
        comments.insert(Arc::clone(&shared));
        shared
    })
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
    let source: Arc<str> = Arc::from(path.display().to_string());
    let mut comments = HashSet::new();

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
            comment: intern_comment(comment, &mut comments),
            source: Arc::clone(&source),
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
    let source: Arc<str> = Arc::from(path.display().to_string());
    let mut comments = HashSet::new();

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
            comment: intern_comment(comment, &mut comments),
            source: Arc::clone(&source),
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
    let source: Arc<str> = Arc::from(path.display().to_string());
    let mut comments = HashSet::new();

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
            comment: intern_comment(comment, &mut comments),
            source: Arc::clone(&source),
            line: line_no,
        };

        let mut normalized = value.to_ascii_lowercase();
        normalized = normalized.trim_end_matches('.').to_string();

        if normalized.starts_with("*.") {
            normalized = format!(".{}", normalized.trim_start_matches("*."));
        }

        if normalized.starts_with('.') {
            let suffix = normalized.trim_start_matches('.');
            if !suffix.is_empty() && !iocs.suffix.insert(suffix, meta) {
                warn!(
                    target: "ioc",
                    path = %source,
                    line = line_no,
                    value = %value,
                    "Too many wildcard domain indicators, skipping"
                );
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
    let source: Arc<str> = Arc::from(path.display().to_string());
    let mut comments = HashSet::new();
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
                comment: intern_comment(comment, &mut comments),
                source: Arc::clone(&source),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_shared(first: &IocMeta, second: &IocMeta) {
        assert!(Arc::ptr_eq(&first.source, &second.source));
        assert!(Arc::ptr_eq(
            first.comment.as_ref().expect("first comment"),
            second.comment.as_ref().expect("second comment"),
        ));
        assert_eq!(first.comment.as_deref(), Some("repeated; detail"));
        assert_ne!(first.line, second.line);
    }

    #[test]
    fn loaders_share_source_and_repeated_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.txt");
        fs::write(&path, "# header\nexact.test; repeated; detail\n*.wild.test; repeated; detail\n.wild.test; other\nempty.test; \nnone.test\n").unwrap();
        let domains = load_domains(&path);
        let exact = &domains.exact["exact.test"];
        let suffixes: Vec<_> = domains.suffix.lookup("wild.test").collect();
        assert_shared(exact, suffixes[0].1);
        assert_eq!(exact.source.as_ref(), path.display().to_string());
        assert_eq!(exact.line, 2);
        assert_eq!(suffixes[0].1.line, 3);
        assert_eq!(suffixes[1].1.line, 4);
        assert_eq!(suffixes[1].1.comment.as_deref(), Some("other"));
        assert!(Arc::ptr_eq(&exact.source, &suffixes[1].1.source));
        for name in ["empty.test", "none.test"] {
            assert!(domains.exact[name].comment.is_none());
            assert!(Arc::ptr_eq(&exact.source, &domains.exact[name].source));
        }

        fs::write(
            &path,
            "192.0.2.1; repeated; detail\n192.0.2.0/24; repeated; detail\n",
        )
        .unwrap();
        let ips = load_ips(&path);
        assert_shared(&ips.exact[&"192.0.2.1".parse().unwrap()], &ips.cidr[0].1);

        fs::write(&path, "a{2}; repeated; detail\nb{2}; repeated; detail\n").unwrap();
        let paths = load_path_regexes(&path);
        assert_shared(&paths.patterns[0].1, &paths.patterns[1].1);

        let md5 = "a".repeat(32);
        let sha1 = "b".repeat(40);
        let sha256 = "c".repeat(64);
        fs::write(
            &path,
            format!(
                "{md5}; repeated; detail\n{sha1}; repeated; detail\n{sha256}; repeated; detail\n"
            ),
        )
        .unwrap();
        let hashes = load_hashes(&path);
        assert_shared(&hashes.md5[&md5], &hashes.sha1[&sha1]);
        assert_shared(&hashes.md5[&md5], &hashes.sha256[&sha256]);
    }
}
