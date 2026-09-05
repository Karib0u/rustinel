//! Debounced detector rebuilds and active response configuration reloads.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::ReloadTarget;
use crate::config::{IocConfig, ReloadConfig, ScannerConfig};
use crate::engine::{DetectorStore, Engine};
use crate::ioc::IocEngine;
use crate::models::MatchDebugLevel;
use crate::scanner;

// The worker is wired from the platform runtime with the full detector,
// config, and channel context; grouping these into a struct would only obscure
// the call sites.
#[allow(clippy::too_many_arguments)]
pub fn spawn_reload_worker(
    store: Arc<DetectorStore>,
    scanner_cfg: ScannerConfig,
    ioc_cfg: IocConfig,
    reload_cfg: ReloadConfig,
    match_debug: MatchDebugLevel,
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
                        let mut engine = Engine::new_with_match_debug(match_debug);

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
                                        "Some Sigma documents were dropped because their references are unavailable"
                                    );
                                }
                                store.swap_sigma(Arc::new(engine));
                                info!(
                                    target: "reload",
                                    component = "sigma",
                                    total_rules = stats.total_rules,
                                    unsupported_rules = stats.unsupported_rules.len(),
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
