//! Yara scanner module
//!
//! Handles compiling rules, listening for process events, and scanning files.

use anyhow::{Context, Result};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};
use yara_x::{Compiler, Rules, Scanner as XScanner};

use crate::models::{MatchDebugLevel, ProcessCreationFields, YaraRuleMatch, YaraStringMatch};
use crate::sensor::{SensorAction, SensorEvent, SensorEventHandler, SensorPayload};
use crate::utils::file_identity::{self, FileIdentity};
use crate::utils::{hash_command_line, query_process_identity, ProcessIdentity};

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

/// Default per-scan timeout applied to file and memory scans.
pub const DEFAULT_SCAN_TIMEOUT_MS: u64 = 10_000;
/// Default maximum size of a file accepted by [`Scanner::scan_file`].
pub const DEFAULT_MAX_FILE_MB: u64 = 64;

/// Resource guards applied to every scan.
///
/// A zero value disables the corresponding guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    /// Per-scan timeout handed to `yara_x::Scanner::set_timeout`.
    pub timeout: Duration,
    /// Maximum size of a file accepted by [`Scanner::scan_file`].
    pub max_file_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(DEFAULT_SCAN_TIMEOUT_MS),
            max_file_bytes: DEFAULT_MAX_FILE_MB * 1024 * 1024,
        }
    }
}

/// Why a scan did not produce a match verdict.
///
/// Timed-out and oversized targets stay distinct from engine failures so
/// operators never see them collapse into clean results.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The scan hit the configured per-scan timeout.
    #[error("YARA scan timed out after {} ms", timeout.as_millis())]
    TimedOut { timeout: Duration },
    /// The target was larger than the configured maximum and was not scanned.
    #[error("target of {size} bytes exceeds the maximum scan size of {limit} bytes")]
    TooLarge { size: u64, limit: u64 },
    /// The scan engine or the underlying I/O failed.
    #[error("{0:#}")]
    Failed(anyhow::Error),
}

impl ScanError {
    /// Short, stable label for logs and counters.
    pub fn kind(&self) -> &'static str {
        match self {
            ScanError::TimedOut { .. } => "timeout",
            ScanError::TooLarge { .. } => "oversized",
            ScanError::Failed(_) => "failed",
        }
    }
}

/// Outcome of a single scan: matches (possibly empty) or a typed failure.
pub type ScanResult = std::result::Result<Vec<YaraRuleMatch>, ScanError>;

const MAX_YARA_STRINGS_PER_RULE: usize = 8;
const MAX_YARA_SNIPPET_LEN: usize = 80;
const YARA_CACHE_MAX_ENTRIES: usize = 10_000;
const YARA_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct YaraFileIdentity {
    file: FileIdentity,
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
    pub expected_identity: ProcessIdentity,
}

/// Main Scanner struct holding compiled rules
pub struct Scanner {
    rules: Rules,
    compiled_files: usize,
    files_found: usize,
    failed_files: usize,
    limits: ScanLimits,
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
            limits: ScanLimits::default(),
            cache: Mutex::new(YaraScanCache::new()),
        })
    }

    /// Build a scanner with zero rules without touching the filesystem.
    ///
    /// Used when YARA scanning is disabled or rule loading fails, so the
    /// fallback never walks a directory tree.
    pub fn empty() -> Self {
        Self {
            rules: Compiler::new().build(),
            compiled_files: 0,
            files_found: 0,
            failed_files: 0,
            limits: ScanLimits::default(),
            cache: Mutex::new(YaraScanCache::new()),
        }
    }

    /// Override the default scan guards.
    pub fn with_limits(mut self, limits: ScanLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> ScanLimits {
        self.limits
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

    /// Scan a file path and return matching rule details.
    ///
    /// Files above the configured maximum size are rejected before the scan
    /// starts, and the scan itself is bounded by the configured timeout.
    pub fn scan_file(&self, path: &str, match_debug: MatchDebugLevel) -> ScanResult {
        if self.compiled_files == 0 {
            return Ok(Vec::new());
        }

        let path = normalize_yara_path(path);
        self.check_file_size(&path)?;
        self.scan_file_cached(&path, match_debug, |path| {
            let mut scanner = XScanner::new(&self.rules);
            self.apply_timeout(&mut scanner);
            let scan_results = scanner.scan_file(path).map_err(|err| {
                self.map_scan_error(err, || format!("YARA scan failed for {path}"))
            })?;
            Ok(collect_yara_matches(scan_results, match_debug))
        })
    }

    /// Reject targets above the configured maximum file size.
    fn check_file_size(&self, path: &str) -> std::result::Result<(), ScanError> {
        let limit = self.limits.max_file_bytes;
        if limit == 0 {
            return Ok(());
        }

        let size = fs::metadata(path)
            .map(|metadata| metadata.len())
            .map_err(|err| {
                ScanError::Failed(
                    anyhow::Error::new(err)
                        .context(format!("YARA scan failed for {path}: cannot read metadata")),
                )
            })?;
        if size > limit {
            return Err(ScanError::TooLarge { size, limit });
        }

        Ok(())
    }

    fn apply_timeout(&self, scanner: &mut XScanner<'_>) {
        if !self.limits.timeout.is_zero() {
            scanner.set_timeout(self.limits.timeout);
        }
    }

    fn map_scan_error<F: FnOnce() -> String>(
        &self,
        err: yara_x::ScanError,
        context: F,
    ) -> ScanError {
        if matches!(err, yara_x::ScanError::Timeout) {
            return ScanError::TimedOut {
                timeout: self.limits.timeout,
            };
        }
        ScanError::Failed(anyhow::Error::new(err).context(context()))
    }

    fn scan_file_cached<F>(&self, path: &str, match_debug: MatchDebugLevel, scan: F) -> ScanResult
    where
        F: FnOnce(&str) -> ScanResult,
    {
        let identity_guard = fs::File::open(path).ok();
        let identity = identity_guard
            .as_ref()
            .and_then(file_identity::from_file)
            .map(|file| YaraFileIdentity { file, match_debug });
        if let Some(identity) = identity.as_ref() {
            if let Ok(mut cache) = self.cache.lock() {
                if let Some(cached_matches) = cache.get(identity) {
                    if let Some(identity_guard) = identity_guard.as_ref() {
                        if file_identity::unchanged(identity_guard, Path::new(path), &identity.file)
                        {
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
            }
        }

        let matches = scan(path)?;

        if let (Some(identity), Some(identity_guard)) = (identity, identity_guard) {
            if file_identity::unchanged(&identity_guard, Path::new(path), &identity.file) {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.insert(identity, matches.clone());
                }
            }
        }

        Ok(matches)
    }

    /// Scan a byte slice and return matching rule details.
    ///
    /// The scan is bounded by the configured timeout. Size limiting is the
    /// caller's job here: memory scans are already bounded by
    /// `MemoryScanConfig::max_region_bytes`.
    pub fn scan_bytes(&self, data: &[u8], match_debug: MatchDebugLevel) -> ScanResult {
        if self.compiled_files == 0 {
            return Ok(Vec::new());
        }

        let mut scanner = XScanner::new(&self.rules);
        self.apply_timeout(&mut scanner);
        let scan_results = scanner
            .scan(data)
            .map_err(|err| self.map_scan_error(err, || "YARA memory scan failed".to_string()))?;
        Ok(collect_yara_matches(scan_results, match_debug))
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

        match crate::telemetry::try_send(
            crate::telemetry::ChannelId::YaraFileScan,
            &self.tx,
            (path.to_string(), pid),
        ) {
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
            let expected_identity = capture_process_identity(event, fields, pid, path);
            match crate::telemetry::try_send(
                crate::telemetry::ChannelId::YaraMemoryScan,
                memory_tx,
                YaraMemoryJob { expected_identity },
            ) {
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

fn capture_process_identity(
    event: &SensorEvent,
    fields: &ProcessCreationFields,
    pid: u32,
    image: &str,
) -> ProcessIdentity {
    let queried = query_process_identity(pid);
    let event_start_time = event
        .process_start_key
        .filter(|key| key.pid == pid)
        .map(|key| key.start_time);
    let start_time = event_start_time
        .or_else(|| queried.as_ref().and_then(|identity| identity.start_time))
        .or(fields.process_start_time);
    let command_line_hash = fields
        .command_line
        .as_deref()
        .map(hash_command_line)
        .or_else(|| {
            queried
                .as_ref()
                .and_then(|identity| identity.command_line_hash.clone())
        });

    ProcessIdentity {
        pid,
        image: image.to_string(),
        start_time,
        command_line_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_file_identity() -> FileIdentity {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        file_identity::from_file(file.as_file()).expect("stable file identity")
    }

    fn scanner_with_marker_rule(dir: &Path) -> Scanner {
        let rules_dir = dir.join("rules");
        fs::create_dir_all(&rules_dir).expect("create rules directory");
        fs::write(
            rules_dir.join("malicious.yar"),
            r#"rule Malicious { strings: $marker = "evil!!" condition: $marker }"#,
        )
        .expect("write rule");
        Scanner::new(&rules_dir).expect("compile scanner")
    }

    #[test]
    fn test_default_scan_limits_are_active() {
        let limits = Scanner::empty().limits();
        assert_eq!(
            limits.timeout,
            Duration::from_millis(DEFAULT_SCAN_TIMEOUT_MS)
        );
        assert_eq!(limits.max_file_bytes, DEFAULT_MAX_FILE_MB * 1024 * 1024);
    }

    #[test]
    fn test_scan_file_rejects_oversized_target_before_scanning() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let scanner = scanner_with_marker_rule(tempdir.path()).with_limits(ScanLimits {
            timeout: Duration::from_secs(1),
            max_file_bytes: 4,
        });
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"evil!!").expect("write sample");

        let error = scanner
            .scan_file(path.to_str().unwrap(), MatchDebugLevel::Off)
            .expect_err("oversized file must not be reported as a clean scan");

        match error {
            ScanError::TooLarge { size, limit } => {
                assert_eq!(size, 6);
                assert_eq!(limit, 4);
            }
            other => panic!("expected an oversized outcome, got {other:?}"),
        }
        assert_eq!(error.kind(), "oversized");
    }

    #[test]
    fn test_scan_file_accepts_target_at_the_size_limit() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let scanner = scanner_with_marker_rule(tempdir.path()).with_limits(ScanLimits {
            timeout: Duration::from_secs(1),
            max_file_bytes: 6,
        });
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"evil!!").expect("write sample");

        let matches = scanner
            .scan_file(path.to_str().unwrap(), MatchDebugLevel::Off)
            .expect("scan at the limit");
        assert_eq!(matches[0].rule, "Malicious");
    }

    #[test]
    fn test_zero_max_file_bytes_disables_the_size_guard() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let scanner = scanner_with_marker_rule(tempdir.path()).with_limits(ScanLimits {
            timeout: Duration::from_secs(1),
            max_file_bytes: 0,
        });
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"evil!!").expect("write sample");

        let matches = scanner
            .scan_file(path.to_str().unwrap(), MatchDebugLevel::Off)
            .expect("scan with the size guard disabled");
        assert_eq!(matches[0].rule, "Malicious");
    }

    #[test]
    fn test_scan_file_reports_unstattable_target_as_failure() {
        let scanner = scanner_with_marker_rule(tempfile::tempdir().expect("tempdir").path());
        let error = scanner
            .scan_file("definitely/missing/sample.bin", MatchDebugLevel::Off)
            .expect_err("missing file must not be reported as a clean scan");
        assert_eq!(error.kind(), "failed");
        assert!(
            error.to_string().contains("YARA scan failed"),
            "failure should retain scan context: {error}"
        );
    }

    #[test]
    fn test_engine_timeout_maps_to_timed_out_outcome() {
        let timeout = Duration::from_millis(25);
        let scanner = Scanner::empty().with_limits(ScanLimits {
            timeout,
            max_file_bytes: 1,
        });

        let mapped = scanner.map_scan_error(yara_x::ScanError::Timeout, || "unused".to_string());

        match mapped {
            ScanError::TimedOut { timeout: reported } => assert_eq!(reported, timeout),
            other => panic!("expected a timeout outcome, got {other:?}"),
        }
        assert_eq!(mapped.kind(), "timeout");
    }

    #[test]
    fn test_scanner_creation() {
        // Test that we can create a scanner even with an empty/missing directory
        let result = Scanner::new("nonexistent_dir");
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_scanner_has_no_rules() {
        let scanner = Scanner::empty();
        assert_eq!(scanner.compiled_files(), 0);
        assert_eq!(scanner.files_found(), 0);
        assert_eq!(scanner.failed_files(), 0);
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
            file: test_file_identity(),
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
            file: test_file_identity(),
            match_debug: MatchDebugLevel::Off,
        };
        let updated = YaraFileIdentity {
            file: test_file_identity(),
            match_debug: MatchDebugLevel::Off,
        };

        cache.insert(identity, Vec::new());
        assert!(cache.get(&updated).is_none());
    }

    #[test]
    fn test_yara_scan_cache_hits_for_unchanged_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write sample");
        let scanner = Scanner::empty();

        scanner
            .scan_file_cached(path.to_str().unwrap(), MatchDebugLevel::Off, |_| {
                Ok(Vec::new())
            })
            .expect("initial scan");
        scanner
            .scan_file_cached(path.to_str().unwrap(), MatchDebugLevel::Off, |_| {
                panic!("unchanged file should use cached result")
            })
            .expect("cached scan");
    }

    #[cfg(unix)]
    #[test]
    fn test_yara_scan_cache_misses_after_same_metadata_replacement() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write sample");
        let original_mtime = fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let scanner = Scanner::empty();

        scanner
            .scan_file_cached(path.to_str().unwrap(), MatchDebugLevel::Off, |_| {
                Ok(Vec::new())
            })
            .expect("initial scan");

        let replacement = tempdir.path().join("replacement.bin");
        fs::write(&replacement, b"evil!!").expect("write replacement");
        fs::File::options()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .set_times(fs::FileTimes::new().set_modified(original_mtime))
            .expect("preserve mtime");
        fs::rename(&replacement, &path).expect("replace sample");

        let matches = scanner
            .scan_file_cached(path.to_str().unwrap(), MatchDebugLevel::Off, |_| {
                Ok(vec![YaraRuleMatch {
                    rule: "Malicious".to_string(),
                    metadata_id: None,
                    tags: Vec::new(),
                    namespace: None,
                    strings: Vec::new(),
                }])
            })
            .expect("replacement scan");
        assert_eq!(matches[0].rule, "Malicious");
    }

    #[cfg(unix)]
    #[test]
    fn test_yara_scan_detects_same_metadata_replacement() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let rules_dir = tempdir.path().join("rules");
        fs::create_dir(&rules_dir).expect("create rules directory");
        fs::write(
            rules_dir.join("malicious.yar"),
            r#"rule Malicious { strings: $marker = "evil!!" condition: $marker }"#,
        )
        .expect("write rule");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write clean sample");
        let original_mtime = fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let scanner = Scanner::new(&rules_dir).expect("compile scanner");

        assert!(scanner
            .scan_file(path.to_str().unwrap(), MatchDebugLevel::Off)
            .expect("scan clean sample")
            .is_empty());

        let replacement = tempdir.path().join("replacement.bin");
        fs::write(&replacement, b"evil!!").expect("write malicious replacement");
        fs::File::options()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .set_times(fs::FileTimes::new().set_modified(original_mtime))
            .expect("preserve mtime");
        fs::rename(&replacement, &path).expect("replace sample");

        let matches = scanner
            .scan_file(path.to_str().unwrap(), MatchDebugLevel::Off)
            .expect("scan malicious replacement");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "Malicious");
    }

    #[cfg(unix)]
    #[test]
    fn test_yara_scan_does_not_cache_file_changed_during_scan() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write sample");
        let scanner = Scanner::empty();

        scanner
            .scan_file_cached(
                path.to_str().unwrap(),
                MatchDebugLevel::Off,
                |scanned_path| {
                    fs::write(scanned_path, b"evil!!").expect("mutate during scan");
                    Ok(Vec::new())
                },
            )
            .expect("scan mutated file");

        assert!(scanner.cache.lock().unwrap().entries.is_empty());
    }
}
