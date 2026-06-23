//! Hot-reload support for Sigma, YARA, and IOC engines.
//!
//! This module keeps detector instances behind atomic pointers and provides:
//! - A debounced reload worker.
//! - A lightweight polling task that detects local rule/IOC file changes.

use std::collections::{hash_map::DefaultHasher, HashSet, VecDeque};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::{IocConfig, ReloadConfig, ScannerConfig};
use crate::engine::Engine;
use crate::ioc::IocEngine;
use crate::models::MatchDebugLevel;
use crate::scanner;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReloadTarget {
    Sigma,
    Yara,
    Ioc,
}

/// Shared detector store with atomic swaps.
pub struct DetectorStore {
    sigma: ArcSwap<Engine>,
    yara: ArcSwap<scanner::Scanner>,
    ioc: ArcSwap<IocEngine>,
}

impl DetectorStore {
    pub fn new(sigma: Arc<Engine>, yara: Arc<scanner::Scanner>, ioc: Arc<IocEngine>) -> Arc<Self> {
        Arc::new(Self {
            sigma: ArcSwap::from(sigma),
            yara: ArcSwap::from(yara),
            ioc: ArcSwap::from(ioc),
        })
    }

    pub fn sigma(&self) -> arc_swap::Guard<Arc<Engine>> {
        self.sigma.load()
    }

    pub fn yara(&self) -> arc_swap::Guard<Arc<scanner::Scanner>> {
        self.yara.load()
    }

    pub fn ioc(&self) -> arc_swap::Guard<Arc<IocEngine>> {
        self.ioc.load()
    }

    fn swap_sigma(&self, engine: Arc<Engine>) {
        self.sigma.store(engine);
    }

    fn swap_yara(&self, scanner: Arc<scanner::Scanner>) {
        self.yara.store(scanner);
    }

    fn swap_ioc(&self, ioc: Arc<IocEngine>) {
        self.ioc.store(ioc);
    }
}

pub fn spawn_reload_worker(
    store: Arc<DetectorStore>,
    scanner_cfg: ScannerConfig,
    ioc_cfg: IocConfig,
    reload_cfg: ReloadConfig,
    log_level: String,
    match_debug: MatchDebugLevel,
    mut reload_rx: mpsc::UnboundedReceiver<ReloadTarget>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !reload_cfg.enabled {
            return;
        }

        let debounce = Duration::from_millis(reload_cfg.debounce_ms.max(100));
        let mut pending: HashSet<ReloadTarget> = HashSet::new();
        let mut channel_closed = false;

        info!(
            target: "reload",
            debounce_ms = reload_cfg.debounce_ms,
            "Hot-reload worker started"
        );

        loop {
            let Some(first) = reload_rx.recv().await else {
                break;
            };
            pending.insert(first);

            let sleep = tokio::time::sleep(debounce);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => {
                        break;
                    }
                    msg = reload_rx.recv() => {
                        match msg {
                            Some(target) => {
                                pending.insert(target);
                            }
                            None => {
                                channel_closed = true;
                                break;
                            }
                        }
                    }
                }
            }

            let mut targets: Vec<ReloadTarget> = pending.drain().collect();
            targets.sort_by_key(|t| match t {
                ReloadTarget::Sigma => 0_u8,
                ReloadTarget::Yara => 1_u8,
                ReloadTarget::Ioc => 2_u8,
            });

            for target in targets {
                match target {
                    ReloadTarget::Sigma => {
                        if !scanner_cfg.sigma_enabled {
                            continue;
                        }

                        let started = Instant::now();
                        let mut engine =
                            Engine::new_with_logging_level_and_match_debug(&log_level, match_debug);

                        match engine.load_rules(&scanner_cfg.sigma_rules_path) {
                            Ok(()) => {
                                let stats = engine.stats();
                                if stats.rule_files_found > 0 && stats.total_rules == 0 {
                                    warn!(
                                        target: "reload",
                                        path = ?scanner_cfg.sigma_rules_path,
                                        errors = ?stats.failed_rules,
                                        "Rejected Sigma reload: all found rule files are broken"
                                    );
                                    continue;
                                }
                                if !stats.failed_rules.is_empty() {
                                    warn!(
                                        target: "reload",
                                        path = ?scanner_cfg.sigma_rules_path,
                                        errors = ?stats.failed_rules,
                                        "Some Sigma rules failed to compile, but loading the working rules"
                                    );
                                }
                                store.swap_sigma(Arc::new(engine));
                                info!(
                                    target: "reload",
                                    component = "sigma",
                                    total_rules = stats.total_rules,
                                    elapsed_ms = started.elapsed().as_millis() as u64,
                                    "Sigma rules hot-reloaded"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    target: "reload",
                                    component = "sigma",
                                    path = ?scanner_cfg.sigma_rules_path,
                                    error = %err,
                                    "Sigma reload failed; keeping previous engine"
                                );
                            }
                        }
                    }
                    ReloadTarget::Yara => {
                        if !scanner_cfg.yara_enabled {
                            continue;
                        }

                        let started = Instant::now();
                        match scanner::Scanner::new(&scanner_cfg.yara_rules_path) {
                            Ok(compiled) => {
                                let compiled_files = compiled.compiled_files();
                                if compiled.files_found() > 0 && compiled_files == 0 {
                                    warn!(
                                        target: "reload",
                                        path = ?scanner_cfg.yara_rules_path,
                                        "Rejected YARA reload: all found rule files are broken"
                                    );
                                    continue;
                                }
                                if compiled.failed_files() > 0 {
                                    warn!(
                                        target: "reload",
                                        path = ?scanner_cfg.yara_rules_path,
                                        failed = compiled.failed_files(),
                                        "Some YARA rules failed to compile, but loading the working rules"
                                    );
                                }
                                store.swap_yara(Arc::new(compiled));
                                info!(
                                    target: "reload",
                                    component = "yara",
                                    compiled_files = compiled_files,
                                    elapsed_ms = started.elapsed().as_millis() as u64,
                                    "YARA rules hot-reloaded"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    target: "reload",
                                    component = "yara",
                                    path = ?scanner_cfg.yara_rules_path,
                                    error = %err,
                                    "YARA reload failed; keeping previous scanner"
                                );
                            }
                        }
                    }
                    ReloadTarget::Ioc => {
                        if !ioc_cfg.enabled {
                            continue;
                        }

                        let started = Instant::now();
                        let ioc = IocEngine::load(&ioc_cfg);
                        let stats = ioc.stats();
                        let total = stats.md5
                            + stats.sha1
                            + stats.sha256
                            + stats.ip
                            + stats.cidr
                            + stats.domain_exact
                            + stats.domain_suffix
                            + stats.path_regex;
                        if total == 0 {
                            warn!(
                                target: "reload",
                                hashes = ?ioc_cfg.hashes_path,
                                ips = ?ioc_cfg.ips_path,
                                domains = ?ioc_cfg.domains_path,
                                paths_regex = ?ioc_cfg.paths_regex_path,
                                "Rejected IOC reload: indicator set is empty"
                            );
                            continue;
                        }

                        store.swap_ioc(Arc::new(ioc));
                        info!(
                            target: "reload",
                            component = "ioc",
                            total_indicators = total,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "IOC indicators hot-reloaded"
                        );
                    }
                }
            }

            if channel_closed {
                break;
            }
        }

        info!(target: "reload", "Hot-reload worker shutting down");
    })
}

pub fn spawn_reload_poller(
    scanner_cfg: ScannerConfig,
    ioc_cfg: IocConfig,
    reload_cfg: ReloadConfig,
    reload_tx: mpsc::UnboundedSender<ReloadTarget>,
) -> tokio::task::JoinHandle<()> {
    use notify::Watcher;

    tokio::spawn(async move {
        if !reload_cfg.enabled {
            return;
        }

        let mut watcher_setup_ok = true;
        let (tx, mut rx) = mpsc::channel::<()>(100);
        let mut watcher = None;

        let mut sigma_fp = scanner_cfg
            .sigma_enabled
            .then(|| fingerprint_dir(&scanner_cfg.sigma_rules_path, &["yml", "yaml"]));
        let mut yara_fp = scanner_cfg
            .yara_enabled
            .then(|| fingerprint_dir(&scanner_cfg.yara_rules_path, &["yar", "yara"]));
        let mut ioc_fp = ioc_cfg.enabled.then(|| fingerprint_ioc_files(&ioc_cfg));

        match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if res.is_ok() {
                let _ = tx.blocking_send(());
            }
        }) {
            Ok(mut w) => {
                let mut watch_targets = Vec::new();
                if scanner_cfg.sigma_enabled {
                    watch_targets.push((
                        scanner_cfg.sigma_rules_path.clone(),
                        notify::RecursiveMode::Recursive,
                    ));
                }
                if scanner_cfg.yara_enabled {
                    watch_targets.push((
                        scanner_cfg.yara_rules_path.clone(),
                        notify::RecursiveMode::Recursive,
                    ));
                }
                if ioc_cfg.enabled {
                    let mut parents = HashSet::new();
                    for path in [
                        &ioc_cfg.hashes_path,
                        &ioc_cfg.ips_path,
                        &ioc_cfg.domains_path,
                        &ioc_cfg.paths_regex_path,
                    ] {
                        let normalized = normalize_path(path);
                        if let Some(parent) = normalized.parent() {
                            parents.insert(parent.to_path_buf());
                        }
                    }
                    for parent in parents {
                        watch_targets.push((parent, notify::RecursiveMode::NonRecursive));
                    }
                }

                for (path, mode) in &watch_targets {
                    if let Err(e) = w.watch(path, *mode) {
                        warn!(
                            target: "reload",
                            path = ?path,
                            error = %e,
                            "Failed to watch path, inotify/watcher setup failed"
                        );
                        watcher_setup_ok = false;
                        break;
                    }
                }
                if watcher_setup_ok {
                    watcher = Some(w);
                }
            }
            Err(e) => {
                warn!(
                    target: "reload",
                    error = %e,
                    "Failed to initialize recommended watcher"
                );
                watcher_setup_ok = false;
            }
        }

        if !watcher_setup_ok {
            warn!(target: "reload", "inotify is not available for the rules directory");
        }

        let debounce_interval = Duration::from_millis(reload_cfg.debounce_ms);
        let poll_interval = Duration::from_millis(reload_cfg.fallback_poll_interval_ms);

        info!(
            target: "reload",
            watcher_active = watcher_setup_ok,
            "Hot-reload poller/watcher started"
        );

        loop {
            if watcher_setup_ok {
                // Wait for filesystem event
                if rx.recv().await.is_none() {
                    break; // channel closed
                }
                // Debounce: sleep to let multiple events coalesce
                tokio::time::sleep(debounce_interval).await;
                // Drain extra events
                while rx.try_recv().is_ok() {}
            } else {
                // Fallback: poll every 60 seconds
                tokio::time::sleep(poll_interval).await;
            }

            if scanner_cfg.sigma_enabled {
                let next = fingerprint_dir(&scanner_cfg.sigma_rules_path, &["yml", "yaml"]);
                if sigma_fp.as_ref() != Some(&next) {
                    sigma_fp = Some(next);
                    if reload_tx.send(ReloadTarget::Sigma).is_err() {
                        break;
                    }
                }
            }

            if scanner_cfg.yara_enabled {
                let next = fingerprint_dir(&scanner_cfg.yara_rules_path, &["yar", "yara"]);
                if yara_fp.as_ref() != Some(&next) {
                    yara_fp = Some(next);
                    if reload_tx.send(ReloadTarget::Yara).is_err() {
                        break;
                    }
                }
            }

            if ioc_cfg.enabled {
                let next = fingerprint_ioc_files(&ioc_cfg);
                if ioc_fp.as_ref() != Some(&next) {
                    ioc_fp = Some(next);
                    if reload_tx.send(ReloadTarget::Ioc).is_err() {
                        break;
                    }
                }
            }
        }

        drop(watcher);
        info!(target: "reload", "Hot-reload poller shutting down");
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    digest: u64,
    file_count: u64,
    exists: bool,
}

fn fingerprint_ioc_files(cfg: &IocConfig) -> Fingerprint {
    let mut hasher = DefaultHasher::new();
    let mut file_count = 0_u64;
    let mut exists = false;

    for path in [
        &cfg.hashes_path,
        &cfg.ips_path,
        &cfg.domains_path,
        &cfg.paths_regex_path,
    ] {
        path.hash(&mut hasher);
        let file_fp = fingerprint_file(path);
        file_fp.digest.hash(&mut hasher);
        file_fp.file_count.hash(&mut hasher);
        file_fp.exists.hash(&mut hasher);
        file_count += file_fp.file_count;
        exists = exists || file_fp.exists;
    }

    Fingerprint {
        digest: hasher.finish(),
        file_count,
        exists,
    }
}

fn fingerprint_file(path: &Path) -> Fingerprint {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);

    match fs::metadata(path) {
        Ok(meta) => {
            meta.len().hash(&mut hasher);
            modified_nanos(&meta).hash(&mut hasher);
            Fingerprint {
                digest: hasher.finish(),
                file_count: 1,
                exists: true,
            }
        }
        Err(_) => Fingerprint {
            digest: hasher.finish(),
            file_count: 0,
            exists: false,
        },
    }
}

fn fingerprint_dir(root: &Path, extensions: &[&str]) -> Fingerprint {
    let mut hasher = DefaultHasher::new();
    let mut file_count = 0_u64;

    let root = normalize_path(root);
    root.hash(&mut hasher);

    if !root.exists() || !root.is_dir() {
        return Fingerprint {
            digest: hasher.finish(),
            file_count: 0,
            exists: false,
        };
    }

    let mut queue = VecDeque::from([root.clone()]);
    while let Some(dir) = queue.pop_front() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                queue.push_back(path);
                continue;
            }

            if !matches_extension(&path, extensions) {
                continue;
            }

            if let Ok(meta) = entry.metadata() {
                let normalized = normalize_path(&path);
                normalized.hash(&mut hasher);
                meta.len().hash(&mut hasher);
                modified_nanos(&meta).hash(&mut hasher);
                file_count += 1;
            }
        }
    }

    Fingerprint {
        digest: hasher.finish(),
        file_count,
        exists: true,
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn matches_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let ext = ext.to_ascii_lowercase();
            extensions.iter().any(|candidate| ext == *candidate)
        })
        .unwrap_or(false)
}

fn modified_nanos(meta: &fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
