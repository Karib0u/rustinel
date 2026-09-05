//! Filesystem watching, fallback polling, and explicit poller shutdown.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use super::fingerprint::{
    fingerprint_dir, fingerprint_file, fingerprint_ioc_files, normalize_path,
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
fn should_wake_reload(kind: &notify::EventKind) -> bool {
    !kind.is_access()
}

fn build_watcher(
    targets: &[(PathBuf, notify::RecursiveMode)],
    tx: mpsc::Sender<()>,
) -> Option<notify::RecommendedWatcher> {
    use notify::Watcher;

    let mut watcher =
        match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            let Ok(event) = res else {
                return;
            };
            if !should_wake_reload(&event.kind) {
                return;
            }
            // Must not block: this runs on the watcher's event thread, the same
            // thread `watch()` waits on for its acknowledgement. A recursive
            // registration over a large tree emits an event per directory, which
            // would fill the channel before the receive loop starts and deadlock
            // setup. A full channel already means a wake-up is pending, and the
            // loop re-fingerprints everything after debouncing, so dropping the
            // signal costs nothing.
            let _ = tx.try_send(());
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

#[cfg(test)]
mod watcher_tests {
    use notify::event::{AccessKind, AccessMode, CreateKind};

    use super::should_wake_reload;

    #[test]
    fn access_events_do_not_wake_reload_fingerprinting() {
        let access = notify::EventKind::Access(AccessKind::Open(AccessMode::Read));
        let create = notify::EventKind::Create(CreateKind::File);

        assert!(!should_wake_reload(&access));
        assert!(should_wake_reload(&create));
    }
}
