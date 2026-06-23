//! Yara scanner module
//!
//! Handles compiling rules, listening for process events, and scanning files.

use anyhow::{Context, Result};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};
use yara_x::{Compiler, Rules, Scanner as XScanner};

use crate::models::{MatchDebugLevel, YaraRuleMatch, YaraStringMatch};
use crate::sensor::{SensorAction, SensorEvent, SensorEventHandler, SensorPayload};

/// Strip NT namespace prefix and convert to a path the YARA scanner can open.
/// On Windows raw ETW paths may arrive as `\??\C:\Windows\...`.
/// On Linux eBPF paths are already native (`/usr/bin/bash`) — return as-is.
#[cfg(windows)]
fn normalize_yara_path(nt_path: &str) -> String {
    let cleaned = nt_path.strip_prefix("\\??\\").unwrap_or(nt_path);
    crate::utils::convert_nt_to_dos(cleaned)
}

#[cfg(not(windows))]
fn normalize_yara_path(path: &str) -> String {
    path.to_string()
}

/// Normalize a path for allowlist prefix matching.
/// Windows: backslash separator, lowercase (case-insensitive FS).
/// Linux:   forward slash separator, case preserved (case-sensitive FS).
fn normalize_path_for_allowlist(path: &str) -> String {
    #[cfg(windows)]
    {
        path.trim().replace('/', "\\").to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        path.trim().to_string()
    }
}

const PATH_SEPARATOR: char = if cfg!(windows) { '\\' } else { '/' };

pub fn normalize_allowlist_paths(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|value| {
            let mut normalized = normalize_path_for_allowlist(value);
            if !normalized.ends_with(PATH_SEPARATOR) {
                normalized.push(PATH_SEPARATOR);
            }
            normalized
        })
        .collect()
}

pub fn is_path_allowlisted(path: &str, allowlist_paths: &[String]) -> bool {
    if allowlist_paths.is_empty() {
        return false;
    }

    let normalized = normalize_path_for_allowlist(path);
    allowlist_paths
        .iter()
        .any(|prefix| normalized.starts_with(prefix.as_str()))
}

const MAX_YARA_STRINGS_PER_RULE: usize = 8;
const MAX_YARA_SNIPPET_LEN: usize = 80;
const YARA_CACHE_MAX_ENTRIES: usize = 10_000;
const YARA_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct YaraFileIdentity {
    path: String,
    size: u64,
    mtime_nanos: u128,
    match_debug: MatchDebugLevel,
}

#[derive(Debug, Clone)]
struct YaraCacheEntry {
    matches: Vec<YaraRuleMatch>,
    timestamp: u64,
}

#[derive(Debug)]
struct YaraScanCache {
    entries: HashMap<YaraFileIdentity, YaraCacheEntry>,
    max_entries: usize,
    ttl_secs: u64,
}

impl YaraScanCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: YARA_CACHE_MAX_ENTRIES,
            ttl_secs: YARA_CACHE_TTL_SECS,
        }
    }

    fn get(&mut self, identity: &YaraFileIdentity) -> Option<Vec<YaraRuleMatch>> {
        let entry = self.entries.get(identity)?;
        if self.is_expired(entry) {
            self.entries.remove(identity);
            return None;
        }

        Some(entry.matches.clone())
    }

    fn insert(&mut self, identity: YaraFileIdentity, matches: Vec<YaraRuleMatch>) {
        let now = now_secs();
        self.entries.insert(
            identity,
            YaraCacheEntry {
                matches,
                timestamp: now,
            },
        );

        if self.entries.len() > self.max_entries {
            self.trim();
        }
    }

    fn is_expired(&self, entry: &YaraCacheEntry) -> bool {
        now_secs().saturating_sub(entry.timestamp) > self.ttl_secs
    }

    fn trim(&mut self) {
        if self.entries.len() <= self.max_entries {
            return;
        }

        let mut timestamps: Vec<u64> = self.entries.values().map(|entry| entry.timestamp).collect();
        timestamps.sort_unstable();
        let cutoff = timestamps[self.entries.len() / 2];
        self.entries.retain(|_, entry| entry.timestamp >= cutoff);

        if self.entries.len() > self.max_entries {
            let extra = self.entries.len() - self.max_entries;
            let keys: Vec<YaraFileIdentity> = self.entries.keys().take(extra).cloned().collect();
            for key in keys {
                self.entries.remove(&key);
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn yara_file_identity(path: &str, match_debug: MatchDebugLevel) -> Option<YaraFileIdentity> {
    let metadata = fs::metadata(path).ok()?;
    let size = metadata.len();
    let mtime_nanos = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    Some(YaraFileIdentity {
        path: normalize_path_for_allowlist(path),
        size,
        mtime_nanos,
        match_debug,
    })
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    if max_len <= 3 {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        return s[..end].to_string();
    }

    let limit = max_len - 3;
    let mut end = limit;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push_str("...");
    out
}

/// Job queued from a process-start event for background memory scanning.
#[derive(Debug, Clone)]
pub struct YaraMemoryJob {
    pub pid: u32,
    pub image: String,
}

/// Main Scanner struct holding compiled rules
pub struct Scanner {
    rules: Rules,
    compiled_files: usize,
    files_found: usize,
    failed_files: usize,
    cache: Mutex<YaraScanCache>,
}

impl Scanner {
    /// Compile all .yar files in a directory
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Result<Self> {
        let rules_dir = rules_dir.as_ref();
        let mut compiler = Compiler::new();
        let mut files_found = 0;
        let mut files_compiled = 0;
        let mut files_failed = 0;

        info!("Loading YARA rules from: {:?} (recursive)", rules_dir);

        if rules_dir.exists() && rules_dir.is_dir() {
            let mut queue = VecDeque::from([rules_dir.to_path_buf()]);
            while let Some(dir) = queue.pop_front() {
                for entry in fs::read_dir(&dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        queue.push_back(path);
                        continue;
                    }
                    if let Some(ext) = path.extension() {
                        if ext == "yar" || ext == "yara" {
                            files_found += 1;
                            debug!("Found YARA rule file: {:?}", path);
                            let src = fs::read_to_string(&path)
                                .with_context(|| format!("Failed to read {:?}", path))?;

                            match compiler.add_source(src.as_str()) {
                                Ok(_) => {
                                    files_compiled += 1;
                                    debug!("✓ Compiled YARA rule: {:?}", path);
                                }
                                Err(e) => {
                                    files_failed += 1;
                                    warn!("✗ Failed to compile {:?}: {}", path, e);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            warn!(
                "YARA rules directory does not exist or is not a directory: {:?}",
                rules_dir
            );
        }

        if files_found > 0 && files_compiled == 0 {
            warn!("YARA rules found but none compiled successfully");
        }

        let rules = compiler.build();
        info!(
            "YARA Scanner: Found {} rule files, compiled {} successfully",
            files_found, files_compiled
        );
        Ok(Self {
            rules,
            compiled_files: files_compiled,
            files_found,
            failed_files: files_failed,
            cache: Mutex::new(YaraScanCache::new()),
        })
    }

    pub fn compiled_files(&self) -> usize {
        self.compiled_files
    }

    pub fn files_found(&self) -> usize {
        self.files_found
    }

    pub fn failed_files(&self) -> usize {
        self.failed_files
    }

    /// Scan a file path and return matching rule details
    pub fn scan_file(
        &self,
        path: &str,
        match_debug: MatchDebugLevel,
    ) -> Result<Vec<YaraRuleMatch>> {
        if self.compiled_files == 0 {
            return Ok(Vec::new());
        }

        let path = normalize_yara_path(path);
        let path = path.as_str();
        let identity = yara_file_identity(path, match_debug);
        if let Some(identity) = identity.as_ref() {
            if let Ok(mut cache) = self.cache.lock() {
                if let Some(cached_matches) = cache.get(identity) {
                    tracing::trace!(
                        target: "scanner",
                        file = %path,
                        matches = cached_matches.len(),
                        "YARA cache hit"
                    );
                    return Ok(cached_matches);
                }
            }
        }

        let mut matches = Vec::new();
        let mut scan_ok = false;
        let mut scanner = XScanner::new(&self.rules);

        match scanner.scan_file(path) {
            Ok(scan_results) => {
                scan_ok = true;
                matches = collect_yara_matches(scan_results, match_debug);
            }
            Err(e) => {
                // File locking issues are common in EDR; keep these at trace to avoid debug spam.
                tracing::trace!(
                    target: "scanner",
                    file = %path,
                    error = %e,
                    "Skipping YARA scan"
                );
            }
        }

        if scan_ok {
            if let Some(identity) = identity {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.insert(identity, matches.clone());
                }
            }
        }

        Ok(matches)
    }

    /// Scan a byte slice and return matching rule details.
    pub fn scan_bytes(
        &self,
        data: &[u8],
        match_debug: MatchDebugLevel,
    ) -> Result<Vec<YaraRuleMatch>> {
        if self.compiled_files == 0 {
            return Ok(Vec::new());
        }

        let mut scanner = XScanner::new(&self.rules);
        match scanner.scan(data) {
            Ok(scan_results) => Ok(collect_yara_matches(scan_results, match_debug)),
            Err(err) => {
                tracing::trace!(
                    target: "scanner",
                    error = %err,
                    "Skipping YARA memory chunk"
                );
                Ok(Vec::new())
            }
        }
    }
}

fn collect_yara_matches(
    scan_results: yara_x::ScanResults,
    match_debug: MatchDebugLevel,
) -> Vec<YaraRuleMatch> {
    let mut matches = Vec::new();

    for rule in scan_results.matching_rules() {
        let rule_name = rule.identifier().to_string();
        let include_meta = !matches!(match_debug, MatchDebugLevel::Off);
        let include_strings = matches!(match_debug, MatchDebugLevel::Full);

        let tags = if include_meta {
            rule.tags()
                .map(|tag| tag.identifier().to_string())
                .collect()
        } else {
            Vec::new()
        };

        let namespace = if include_meta {
            Some(rule.namespace().to_string())
        } else {
            None
        };

        let mut strings = Vec::new();
        if include_strings {
            let mut count = 0usize;
            for pattern in rule.patterns() {
                let pattern_id = pattern.identifier().to_string();
                for m in pattern.matches() {
                    if count >= MAX_YARA_STRINGS_PER_RULE {
                        break;
                    }
                    let offset = m.range().start as u64;
                    let snippet_raw = String::from_utf8_lossy(m.data()).to_string();
                    let snippet = truncate_str(&snippet_raw, MAX_YARA_SNIPPET_LEN);
                    strings.push(YaraStringMatch {
                        id: pattern_id.clone(),
                        offset: Some(offset),
                        snippet: Some(snippet),
                    });
                    count += 1;
                }
                if count >= MAX_YARA_STRINGS_PER_RULE {
                    break;
                }
            }
        }

        let mut metadata_id = None;
        for (identifier, value) in rule.metadata() {
            if identifier == "id" {
                if let yara_x::MetaValue::String(s) = value {
                    metadata_id = Some(s.to_string());
                }
            }
        }

        matches.push(YaraRuleMatch {
            rule: rule_name,
            metadata_id,
            tags,
            namespace,
            strings,
        });
    }

    matches
}

/// Sensor-event handler that sends file paths to the background worker.
pub struct YaraEventHandler {
    pub tx: Sender<(String, u32)>,
    pub memory_tx: Option<Sender<YaraMemoryJob>>,
    pub allowlist_paths: Vec<String>,
}

impl SensorEventHandler for YaraEventHandler {
    fn handle_event(&self, event: &SensorEvent) {
        if event.action != SensorAction::Start {
            return;
        }

        let SensorPayload::Process(fields) = &event.payload else {
            return;
        };

        let Some(path) = fields.image.as_deref() else {
            tracing::trace!(
                target: "scanner",
                pid = event.pid,
                "YARA process-start event missing executable path"
            );
            return;
        };

        let pid = fields
            .process_id
            .as_deref()
            .and_then(|value| value.parse::<u32>().ok())
            .or(event.pid)
            .unwrap_or(0);

        if is_path_allowlisted(path, &self.allowlist_paths) {
            tracing::trace!(
                target: "scanner",
                pid = pid,
                file = path,
                "YARA skipping allowlisted path"
            );
            return;
        }

        match self.tx.try_send((path.to_string(), pid)) {
            Ok(_) => tracing::trace!(
                target: "scanner",
                pid = pid,
                file = path,
                "YARA queued file for scan"
            ),
            Err(err) => warn!(
                target: "scanner",
                pid = pid,
                file = path,
                error = %err,
                "YARA queue full; dropping scan job"
            ),
        }

        if let Some(memory_tx) = &self.memory_tx {
            match memory_tx.try_send(YaraMemoryJob {
                pid,
                image: path.to_string(),
            }) {
                Ok(_) => tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    file = path,
                    "YARA queued process for memory scan"
                ),
                Err(err) => warn!(
                    target: "scanner",
                    pid = pid,
                    file = path,
                    error = %err,
                    "YARA memory queue full; dropping scan job"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        // Test that we can create a scanner even with an empty/missing directory
        let result = Scanner::new("nonexistent_dir");
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_normalize_yara_path_strips_win32_prefix() {
        let input = r"\??\C:\Windows\System32\cmd.exe";
        let normalized = normalize_yara_path(input);
        assert_eq!(normalized, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn test_normalize_yara_path_passthrough() {
        // On Windows: a plain DOS path passes through unchanged.
        // On Linux: all paths pass through unchanged (no NT prefix exists).
        #[cfg(windows)]
        let input = r"C:\Temp\edrust.exe";
        #[cfg(not(windows))]
        let input = "/tmp/edrust";
        let normalized = normalize_yara_path(input);
        assert_eq!(normalized, input);
    }

    #[test]
    fn test_normalize_allowlist_paths_adds_trailing_separator() {
        #[cfg(windows)]
        {
            let paths = vec![r"C:\Windows".to_string()];
            let normalized = normalize_allowlist_paths(&paths);
            assert_eq!(normalized, vec![r"c:\windows\".to_string()]);
        }
        #[cfg(not(windows))]
        {
            let paths = vec!["/usr/bin".to_string()];
            let normalized = normalize_allowlist_paths(&paths);
            assert_eq!(normalized, vec!["/usr/bin/".to_string()]);
        }
    }

    #[test]
    fn test_is_path_allowlisted_matches_prefix() {
        #[cfg(windows)]
        {
            let allowlist = normalize_allowlist_paths(&[r"C:\Windows".to_string()]);
            assert!(is_path_allowlisted(
                r"C:\Windows\System32\cmd.exe",
                &allowlist
            ));
            assert!(!is_path_allowlisted(r"C:\Temp\evil.exe", &allowlist));
        }
        #[cfg(not(windows))]
        {
            let allowlist = normalize_allowlist_paths(&["/usr/bin".to_string()]);
            assert!(is_path_allowlisted("/usr/bin/curl", &allowlist));
            assert!(!is_path_allowlisted("/tmp/evil", &allowlist));
        }
    }

    #[test]
    fn test_yara_scan_cache_returns_cached_matches() {
        let mut cache = YaraScanCache {
            entries: HashMap::new(),
            max_entries: 10,
            ttl_secs: 60,
        };
        let identity = YaraFileIdentity {
            path: r"c:\temp\sample.exe".to_string(),
            size: 1337,
            mtime_nanos: 42,
            match_debug: MatchDebugLevel::Off,
        };
        let expected = vec![YaraRuleMatch {
            rule: "TestRule".to_string(),
            metadata_id: None,
            tags: Vec::new(),
            namespace: None,
            strings: Vec::new(),
        }];

        cache.insert(identity.clone(), expected.clone());
        let from_cache = cache.get(&identity);

        let cached = from_cache.expect("expected cache hit");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].rule, expected[0].rule);
    }

    #[test]
    fn test_yara_scan_cache_miss_on_identity_change() {
        let mut cache = YaraScanCache {
            entries: HashMap::new(),
            max_entries: 10,
            ttl_secs: 60,
        };
        let identity = YaraFileIdentity {
            path: r"c:\temp\sample.exe".to_string(),
            size: 1337,
            mtime_nanos: 42,
            match_debug: MatchDebugLevel::Off,
        };
        let updated = YaraFileIdentity {
            path: r"c:\temp\sample.exe".to_string(),
            size: 2048,
            mtime_nanos: 43,
            match_debug: MatchDebugLevel::Off,
        };

        cache.insert(identity, Vec::new());
        assert!(cache.get(&updated).is_none());
    }
}
