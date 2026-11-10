//! Filesystem watching, fallback polling, and explicit poller shutdown.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use super::fingerprint::{
    fingerprint_dirs, fingerprint_file, fingerprint_ioc_files, normalize_path,
};
use super::ReloadTarget;
use crate::config::{IocConfig, ReloadConfig, ScannerConfig};

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
    ready: watch::Receiver<bool>,
}

impl ReloadPoller {
    /// Wait until registration and the initial fingerprint comparison finish.
    pub async fn ready(&mut self) -> bool {
        while !*self.ready.borrow_and_update() {
            if self.ready.changed().await.is_err() {
                return false;
            }
        }
        true
    }

    /// Signal the poller to stop and wait for it to finish.
    ///
    /// Aborts the task if it does not observe the signal within
    /// [`POLLER_SHUTDOWN_TIMEOUT`], so shutdown can never stall the process.
    pub async fn shutdown(self) {
        let ReloadPoller {
            mut handle,
            shutdown,
            ..
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

/// The Sigma pack directory followed by every local directory.
fn sigma_dirs(scanner_cfg: &ScannerConfig) -> impl Iterator<Item = &PathBuf> {
    std::iter::once(&scanner_cfg.sigma_rules_path).chain(&scanner_cfg.sigma_local_rules_paths)
}

/// The YARA pack directory followed by every local directory.
fn yara_dirs(scanner_cfg: &ScannerConfig) -> impl Iterator<Item = &PathBuf> {
    std::iter::once(&scanner_cfg.yara_rules_path).chain(&scanner_cfg.yara_local_rules_paths)
}

/// A watcher registration on a missing path fails the whole setup and drops
/// every target to polling, so a local directory that does not exist yet is
/// left to the polling fingerprint. The pack directory keeps its existing
/// behavior.
fn watchable<'a>(
    dirs: impl Iterator<Item = &'a PathBuf>,
    pack: &'a PathBuf,
) -> impl Iterator<Item = &'a PathBuf> {
    dirs.filter(move |dir| *dir == pack || dir.exists())
}

/// Collect the paths to watch, and how deeply, for the enabled subsystems.
fn watch_targets(
    scanner_cfg: &ScannerConfig,
    ioc_cfg: &IocConfig,
    config_path: Option<&PathBuf>,
) -> Vec<(PathBuf, notify::RecursiveMode)> {
    let mut targets = Vec::new();

    if scanner_cfg.sigma_enabled {
        for path in watchable(sigma_dirs(scanner_cfg), &scanner_cfg.sigma_rules_path) {
            targets.push((path.clone(), notify::RecursiveMode::Recursive));
        }
    }
    if scanner_cfg.yara_enabled {
        for path in watchable(yara_dirs(scanner_cfg), &scanner_cfg.yara_rules_path) {
            targets.push((path.clone(), notify::RecursiveMode::Recursive));
        }
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
fn should_wake_reload(kind: &notify::EventKind) -> bool {
    !kind.is_access()
}

/// Decides which filesystem events are worth a fingerprint pass.
///
/// Non-recursive targets (the config directory and the IOC parents) are shared
/// with unrelated files such as logs and state, so only events naming one of the
/// watched files wake the poller. Events under a recursive rule root always wake it.
#[derive(Debug, Default)]
struct EventFilter {
    rule_roots: Vec<PathBuf>,
    file_names: Vec<std::ffi::OsString>,
}

impl EventFilter {
    fn new(
        scanner_cfg: &ScannerConfig,
        ioc_cfg: &IocConfig,
        config_path: Option<&PathBuf>,
    ) -> Self {
        let mut filter = Self::default();
        let mut roots: Vec<&PathBuf> = Vec::new();
        if scanner_cfg.sigma_enabled {
            roots.extend(sigma_dirs(scanner_cfg));
        }
        if scanner_cfg.yara_enabled {
            roots.extend(yara_dirs(scanner_cfg));
        }
        for root in roots {
            // Backends disagree on whether they report the registered or the
            // canonical spelling, so match both.
            filter.rule_roots.push(root.clone());
            filter.rule_roots.push(normalize_path(root));
        }
        let mut files: Vec<&PathBuf> = Vec::new();
        if ioc_cfg.enabled {
            files.extend([
                &ioc_cfg.hashes_path,
                &ioc_cfg.ips_path,
                &ioc_cfg.domains_path,
                &ioc_cfg.paths_regex_path,
            ]);
        }
        files.extend(config_path);
        for file in files {
            if let Some(name) = file.file_name() {
                filter.file_names.push(name.to_os_string());
            }
        }
        filter
    }

    fn matches(&self, event: &notify::Event) -> bool {
        if event.paths.is_empty() {
            return true;
        }
        event.paths.iter().any(|path| {
            self.rule_roots.iter().any(|root| path.starts_with(root))
                || path.file_name().is_some_and(|name| {
                    self.file_names
                        .iter()
                        .any(|wanted| name.eq_ignore_ascii_case(wanted))
                })
        })
    }
}

fn wake_reload(
    result: Result<notify::Event, notify::Error>,
    filter: &EventFilter,
    tx: &mpsc::Sender<()>,
) {
    match result {
        Ok(event) if !should_wake_reload(&event.kind) || !filter.matches(&event) => return,
        Ok(_) => {}
        // An error can mean notifications were lost. Recheck fingerprints.
        Err(error) => warn!(target: "reload", %error, "Filesystem watcher error"),
    }
    // Never block the watcher's event thread: watch() waits on this thread
    // during recursive registration. A full channel already holds a wake-up.
    let _ = tx.try_send(());
}

fn build_watcher(
    targets: &[(PathBuf, notify::RecursiveMode)],
    filter: EventFilter,
    tx: mpsc::Sender<()>,
) -> Option<notify::RecommendedWatcher> {
    use notify::Watcher;

    let mut watcher = match notify::recommended_watcher(move |res| wake_reload(res, &filter, &tx)) {
        Ok(watcher) => watcher,
        Err(error) => {
            warn!(target: "reload", %error, "Failed to initialize recommended watcher");
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
    spawn_reload_poller_with_setup(
        scanner_cfg,
        ioc_cfg,
        reload_cfg,
        config_path,
        reload_tx,
        build_watcher,
    )
}

fn spawn_reload_poller_with_setup(
    scanner_cfg: ScannerConfig,
    ioc_cfg: IocConfig,
    reload_cfg: ReloadConfig,
    config_path: Option<PathBuf>,
    reload_tx: mpsc::UnboundedSender<ReloadTarget>,
    setup_watcher: impl FnOnce(
            &[(PathBuf, notify::RecursiveMode)],
            EventFilter,
            mpsc::Sender<()>,
        ) -> Option<notify::RecommendedWatcher>
        + Send
        + 'static,
) -> ReloadPoller {
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let (ready_tx, ready) = watch::channel(false);

    let handle = tokio::spawn(async move {
        if !reload_cfg.enabled {
            return;
        }

        let (tx, mut rx) = mpsc::channel::<()>(100);

        let mut sigma_fp = scanner_cfg
            .sigma_enabled
            .then(|| fingerprint_dirs(sigma_dirs(&scanner_cfg), &["yml", "yaml"]));
        let mut yara_fp = scanner_cfg
            .yara_enabled
            .then(|| fingerprint_dirs(yara_dirs(&scanner_cfg), &["yar", "yara"]));
        let mut ioc_fp = ioc_cfg.enabled.then(|| fingerprint_ioc_files(&ioc_cfg));
        let mut config_fp = config_path.as_ref().map(|path| fingerprint_file(path));

        let targets = watch_targets(&scanner_cfg, &ioc_cfg, config_path.as_ref());
        let filter = EventFilter::new(&scanner_cfg, &ioc_cfg, config_path.as_ref());
        let setup = tokio::task::spawn_blocking(move || setup_watcher(&targets, filter, tx));
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
        let poll_interval = Duration::from_millis(reload_cfg.fallback_poll_interval_ms.max(1));

        info!(
            target: "reload",
            watcher_active = watcher_setup_ok,
            "Hot-reload poller/watcher started"
        );

        // Registration can take seconds. Compare immediately after it, before
        // waiting, to catch changes made before watch() attached.
        let mut initial_check = true;
        loop {
            if !initial_check && watcher_setup_ok {
                // Wait for a filesystem event, or for shutdown
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(poll_interval) => {}
                    // A dead notification thread must not disable the safety poll.
                    _ = rx.recv(), if !rx.is_closed() => {}
                }
                // Debounce: sleep to let multiple events coalesce
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(debounce_interval) => {}
                }
                // Drain extra events
                while rx.try_recv().is_ok() {}
            } else if !initial_check {
                // Fallback: poll on the configured interval
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(poll_interval) => {}
                }
            }

            if scanner_cfg.sigma_enabled {
                let next = fingerprint_dirs(sigma_dirs(&scanner_cfg), &["yml", "yaml"]);
                if sigma_fp.as_ref() != Some(&next) {
                    sigma_fp = Some(next);
                    if reload_tx.send(ReloadTarget::Sigma).is_err() {
                        break;
                    }
                }
            }

            if scanner_cfg.yara_enabled {
                let next = fingerprint_dirs(yara_dirs(&scanner_cfg), &["yar", "yara"]);
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
            if initial_check {
                initial_check = false;
                let _ = ready_tx.send(true);
            }
        }

        drop(watcher);
        info!(target: "reload", "Hot-reload poller shutting down");
    });

    ReloadPoller {
        handle,
        shutdown,
        ready,
    }
}

#[cfg(test)]
mod watcher_tests {
    use notify::event::{AccessKind, AccessMode, CreateKind};

    use std::path::PathBuf;

    use super::{should_wake_reload, EventFilter};
    use crate::config::AppConfig;

    #[test]
    fn watcher_errors_wake_reload_even_without_a_matching_path() {
        let app = AppConfig::default();
        let filter = EventFilter::new(&app.scanner, &app.ioc, None);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        super::wake_reload(
            Err(notify::Error::generic("notifications lost")),
            &filter,
            &tx,
        );
        assert!(rx.try_recv().is_ok());
    }

    async fn assert_change_detected(change_during_setup: bool) {
        use std::time::Duration;

        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config.toml");
        std::fs::write(&config, "initial").unwrap();
        let mut cfg = AppConfig::default();
        cfg.scanner.sigma_enabled = false;
        cfg.scanner.yara_enabled = false;
        cfg.ioc.enabled = false;
        cfg.reload.enabled = true;
        cfg.reload.debounce_ms = 1;
        cfg.reload.fallback_poll_interval_ms = if change_during_setup { 3_600_000 } else { 20 };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let setup_path = config.clone();
        let mut poller = super::spawn_reload_poller_with_setup(
            cfg.scanner,
            cfg.ioc,
            cfg.reload,
            Some(config.clone()),
            tx,
            move |_, _, _| {
                if change_during_setup {
                    std::fs::write(setup_path, "changed while registering").unwrap();
                }
                // A live watcher with no paths deliberately delivers no events.
                // Neither test can pass by receiving a native notification.
                Some(notify::recommended_watcher(|_| {}).unwrap())
            },
        );
        assert!(tokio::time::timeout(Duration::from_secs(5), poller.ready())
            .await
            .unwrap());
        if !change_during_setup {
            std::fs::write(config, "changed without notification").unwrap();
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap(),
            Some(super::ReloadTarget::Config)
        );
        poller.shutdown().await;
    }

    #[tokio::test]
    async fn changes_during_watcher_setup_are_checked_before_waiting() {
        assert_change_detected(true).await;
    }

    #[tokio::test]
    async fn active_watcher_polls_to_recover_missed_notifications() {
        assert_change_detected(false).await;
    }

    fn event(path: &str) -> notify::Event {
        notify::Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Any))
            .add_path(PathBuf::from(path))
    }

    #[test]
    fn unrelated_sibling_writes_do_not_wake_reload() {
        let app = AppConfig::default();
        let mut scanner = app.scanner;
        scanner.sigma_enabled = true;
        scanner.yara_enabled = false;
        scanner.sigma_rules_path = PathBuf::from("/opt/rustinel/rules/sigma");
        scanner.sigma_local_rules_paths = Vec::new();
        let mut ioc = app.ioc;
        ioc.enabled = false;
        let config = PathBuf::from("/opt/rustinel/config.toml");
        let filter = EventFilter::new(&scanner, &ioc, Some(&config));

        assert!(!filter.matches(&event("/opt/rustinel/resource-samples.csv")));
        assert!(!filter.matches(&event("/opt/rustinel/agent.stdout.log")));
        assert!(filter.matches(&event("/opt/rustinel/config.toml")));
        assert!(filter.matches(&event("/opt/rustinel/rules/sigma/sub/new.yml")));
    }

    #[test]
    fn access_events_do_not_wake_reload_fingerprinting() {
        let access = notify::EventKind::Access(AccessKind::Open(AccessMode::Read));
        let create = notify::EventKind::Create(CreateKind::File);

        assert!(!should_wake_reload(&access));
        assert!(should_wake_reload(&create));
    }
}
