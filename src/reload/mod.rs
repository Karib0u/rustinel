//! Hot-reload support for Sigma, YARA, IOC engines, and configuration.
//!
//! This module keeps detector instances behind atomic pointers and provides:
//! - A debounced reload worker that swaps engines and active response config.
//! - A lightweight polling task that detects local rule/IOC/config file changes.

use std::collections::{hash_map::DefaultHasher, HashSet, VecDeque};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, watch};
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
    Config,
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

// The worker is wired from the platform runtime with the full detector,
// config, logging, backend, and channel context; grouping these into a struct
// would only obscure the call sites.
#[allow(clippy::too_many_arguments)]
pub fn spawn_reload_worker(
    store: Arc<DetectorStore>,
    scanner_cfg: ScannerConfig,
    ioc_cfg: IocConfig,
    reload_cfg: ReloadConfig,
    log_level: String,
    match_debug: MatchDebugLevel,
    engine_kind: crate::engine::SigmaEngineKind,
    config_path: Option<PathBuf>,
    response_config: Arc<ArcSwap<crate::config::ResponseConfig>>,
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
                ReloadTarget::Config => 3_u8,
            });

            for target in targets {
                match target {
                    ReloadTarget::Sigma => {
                        if !scanner_cfg.sigma_enabled {
                            continue;
                        }

                        let started = Instant::now();
                        let mut engine = Engine::new_with_logging_level_and_match_debug(
                            &log_level,
                            match_debug,
                            engine_kind,
                        );

                        match engine.load_rules(&scanner_cfg.sigma_rules_path) {
                            Ok(()) => {
                                let stats = engine.stats();
                                if stats.rule_files_found > 0
                                    && stats.total_rules == 0
                                    && stats.unsupported_rules.is_empty()
                                {
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
                                if !stats.unsupported_rules.is_empty() {
                                    warn!(
                                        target: "reload",
                                        path = ?scanner_cfg.sigma_rules_path,
                                        unsupported = ?stats.unsupported_rules,
                                        "Some Sigma documents are unsupported by the active runtime"
                                    );
                                }
                                store.swap_sigma(Arc::new(engine));
                                info!(
                                    target: "reload",
                                    component = "sigma",
                                    total_rules = stats.total_rules,
                                    unsupported_rules = stats.unsupported_rules.len(),
                                    unsupported_correlation_rules = stats.unsupported_correlation_rules,
                                    unsupported_filter_rules = stats.unsupported_filter_rules,
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
                        match scanner::Scanner::new(&scanner_cfg.yara_rules_path)
                            .map(|compiled| compiled.with_limits(scanner_cfg.yara_scan_limits()))
                        {
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
                    ReloadTarget::Config => {
                        let started = Instant::now();
                        match crate::config::AppConfig::from_config_path(config_path.clone()) {
                            Ok(new_cfg) => {
                                let resp = &new_cfg.response;
                                info!(
                                    target: "reload",
                                    component = "config",
                                    enabled = resp.enabled,
                                    prevention_enabled = resp.prevention_enabled,
                                    min_severity = %resp.min_severity,
                                    elapsed_ms = started.elapsed().as_millis() as u64,
                                    "Active response settings hot-reloaded"
                                );
                                response_config.store(Arc::new(new_cfg.response));
                            }
                            Err(err) => {
                                warn!(
                                    target: "reload",
                                    component = "config",
                                    error = %err,
                                    "Failed to reload config; keeping previous settings"
                                );
                            }
                        }
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

/// Maximum time [`ReloadPoller::shutdown`] waits for the task before aborting it.
const POLLER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Handle to a running hot-reload poller task.
///
/// Carries an explicit shutdown signal rather than relying on
/// [`tokio::task::JoinHandle::abort`], which cannot interrupt a task parked inside a
/// synchronous watcher call.
pub struct ReloadPoller {
    handle: tokio::task::JoinHandle<()>,
    shutdown: watch::Sender<bool>,
}

impl ReloadPoller {
    /// Signal the poller to stop and wait for it to finish.
    ///
    /// Aborts the task if it does not observe the signal within
    /// [`POLLER_SHUTDOWN_TIMEOUT`], so shutdown can never stall the process.
    pub async fn shutdown(self) {
        let ReloadPoller {
            mut handle,
            shutdown,
        } = self;
        let _ = shutdown.send(true);
        if tokio::time::timeout(POLLER_SHUTDOWN_TIMEOUT, &mut handle)
            .await
            .is_err()
        {
            warn!(target: "reload", "Hot-reload poller did not stop in time; aborting");
            handle.abort();
            let _ = handle.await;
        }
    }
}

/// Collect the paths to watch, and how deeply, for the enabled subsystems.
fn watch_targets(
    scanner_cfg: &ScannerConfig,
    ioc_cfg: &IocConfig,
    config_path: Option<&PathBuf>,
) -> Vec<(PathBuf, notify::RecursiveMode)> {
    let mut targets = Vec::new();

    if scanner_cfg.sigma_enabled {
        targets.push((
            scanner_cfg.sigma_rules_path.clone(),
            notify::RecursiveMode::Recursive,
        ));
    }
    if scanner_cfg.yara_enabled {
        targets.push((
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
            targets.push((parent, notify::RecursiveMode::NonRecursive));
        }
    }
    if let Some(cfg_path) = config_path {
        let normalized = normalize_path(cfg_path);
        if let Some(parent) = normalized.parent() {
            targets.push((parent.to_path_buf(), notify::RecursiveMode::NonRecursive));
        }
    }

    targets
}

/// Create the filesystem watcher and register every target.
///
/// Synchronous on purpose: `Watcher::watch()` blocks waiting on the watcher's own
/// event thread, so callers run this on a blocking thread.
fn build_watcher(
    targets: &[(PathBuf, notify::RecursiveMode)],
    tx: mpsc::Sender<()>,
) -> Option<notify::RecommendedWatcher> {
    use notify::Watcher;

    let mut watcher =
        match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if res.is_ok() {
                // Must not block: this runs on the watcher's event thread, the same
                // thread `watch()` waits on for its acknowledgement. A recursive
                // registration over a large tree emits an event per directory, which
                // would fill the channel before the receive loop starts and deadlock
                // setup. A full channel already means a wake-up is pending, and the
                // loop re-fingerprints everything after debouncing, so dropping the
                // signal costs nothing.
                let _ = tx.try_send(());
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(
                    target: "reload",
                    error = %e,
                    "Failed to initialize recommended watcher"
                );
                return None;
            }
        };

    for (path, mode) in targets {
        if let Err(e) = watcher.watch(path, *mode) {
            warn!(
                target: "reload",
                path = ?path,
                error = %e,
                "Failed to watch path, inotify/watcher setup failed"
            );
            return None;
        }
    }

    Some(watcher)
}

pub fn spawn_reload_poller(
    scanner_cfg: ScannerConfig,
    ioc_cfg: IocConfig,
    reload_cfg: ReloadConfig,
    config_path: Option<PathBuf>,
    reload_tx: mpsc::UnboundedSender<ReloadTarget>,
) -> ReloadPoller {
    let (shutdown, mut shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        if !reload_cfg.enabled {
            return;
        }

        let (tx, mut rx) = mpsc::channel::<()>(100);

        let mut sigma_fp = scanner_cfg
            .sigma_enabled
            .then(|| fingerprint_dir(&scanner_cfg.sigma_rules_path, &["yml", "yaml"]));
        let mut yara_fp = scanner_cfg
            .yara_enabled
            .then(|| fingerprint_dir(&scanner_cfg.yara_rules_path, &["yar", "yara"]));
        let mut ioc_fp = ioc_cfg.enabled.then(|| fingerprint_ioc_files(&ioc_cfg));
        let mut config_fp = config_path.as_ref().map(|path| fingerprint_file(path));

        let targets = watch_targets(&scanner_cfg, &ioc_cfg, config_path.as_ref());
        let setup = tokio::task::spawn_blocking(move || build_watcher(&targets, tx));
        let watcher = tokio::select! {
            res = setup => res.ok().flatten(),
            _ = shutdown_rx.changed() => {
                info!(target: "reload", "Hot-reload poller shutting down during watcher setup");
                return;
            }
        };

        let watcher_setup_ok = watcher.is_some();
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
                // Wait for a filesystem event, or for shutdown
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    event = rx.recv() => {
                        if event.is_none() {
                            break; // channel closed
                        }
                    }
                }
                // Debounce: sleep to let multiple events coalesce
                tokio::time::sleep(debounce_interval).await;
                // Drain extra events
                while rx.try_recv().is_ok() {}
            } else {
                // Fallback: poll on the configured interval
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(poll_interval) => {}
                }
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

            if let Some(cfg_path) = &config_path {
                let next = fingerprint_file(cfg_path);
                if config_fp.as_ref() != Some(&next) {
                    config_fp = Some(next);
                    if reload_tx.send(ReloadTarget::Config).is_err() {
                        break;
                    }
                }
            }
        }

        drop(watcher);
        info!(target: "reload", "Hot-reload poller shutting down");
    });

    ReloadPoller { handle, shutdown }
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
