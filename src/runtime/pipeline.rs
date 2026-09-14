//! Shared construction of live detection workers and event routing.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::alerts::AlertSink;
use crate::artifact::{spawn_artifact_resolver, ArtifactRuntime};
use crate::config::{AppConfig, ResponseConfig};
use crate::engine::{DetectionPipeline, DetectorStore, Engine, NormalizedEventHandler};
use crate::ioc::IocEngine;
use crate::memory::MemoryScanConfig;
use crate::response::ResponseEngine;
use crate::runtime::logging::TARGET_CONSOLE;
use crate::runtime::yara as runtime_yara;
use crate::scanner::{YaraMemoryEventHandler, YaraMemoryJob};
use crate::sensor::{Platform, SensorEventRouter};
use crate::state::HostState;
use crate::{reload, scanner};

pub(super) struct SharedState {
    pub host: Arc<HostState>,
}
impl SharedState {
    pub fn new(cfg: &AppConfig) -> Self {
        Self {
            host: HostState::for_runtime(cfg.process.max_entries),
        }
    }
}

pub(super) struct LivePipeline {
    pub router: Arc<SensorEventRouter>,
    pub host_state: Arc<HostState>,
    pub artifact_worker_handle: JoinHandle<()>,
    pub artifact_resolver_handle: crate::artifact::ArtifactResolverHandle,
    pub yara_memory_worker_handle: Option<JoinHandle<()>>,
    pub reload_poller: Option<reload::ReloadPoller>,
    pub reload_worker_handle: Option<JoinHandle<()>>,
    pub reload_tx: Option<mpsc::UnboundedSender<reload::ReloadTarget>>,
}

impl LivePipeline {
    pub fn new(
        cfg: &AppConfig,
        resolved_config_path: Option<PathBuf>,
        platform: Platform,
        state: SharedState,
        alert_sink: AlertSink,
        response_config: Arc<ArcSwap<ResponseConfig>>,
        response_engine: ResponseEngine,
    ) -> Self {
        // Sigma engine
        let mut sigma_engine =
            Engine::new_for_platform_with_match_debug(platform, cfg.alerts.match_debug);

        if cfg.scanner.sigma_enabled {
            info!(rules_path = ?cfg.scanner.sigma_rules_path, "Loading Sigma rules");
            if let Err(e) = sigma_engine.load_rules(&cfg.scanner.sigma_rules_path) {
                warn!(error = %e, "Failed to load Sigma rules");
            } else {
                let stats = sigma_engine.stats();
                info!(
                    target: TARGET_CONSOLE,
                    total_rules = stats.total_rules,
                    skipped_deferred_rules = stats.skipped_deferred_rules,
                    skipped_unknown_logsource_rules = stats.skipped_unknown_logsource_rules,
                    skipped_product_rules = stats.skipped_product_rules,
                    inactive_collector_rules = stats.inactive_collector_rules,
                    unsupported_rules = stats.unsupported_rules.len(),
                    "Sigma engine initialized"
                );
                if let Some(categories) = stats.inactive_collector_summary() {
                    warn!(
                        target: TARGET_CONSOLE,
                        inert_rules = stats.inactive_collector_rules,
                        categories = %categories,
                        "Sigma rules loaded without a backing collector and cannot fire"
                    );
                }
                for (logsource, count) in stats.rules_by_logsource {
                    info!(logsource = %logsource, count, "Sigma rules loaded");
                }
            }
        } else {
            info!(target: TARGET_CONSOLE, "Sigma detection disabled by configuration");
        }
        let sigma_engine = Arc::new(sigma_engine);

        // YARA scanner
        let yara_scanner = if cfg.scanner.yara_enabled {
            match scanner::Scanner::new(&cfg.scanner.yara_rules_path)
                .map(|s| s.with_limits(cfg.scanner.yara_scan_limits()))
            {
                Ok(s) => {
                    info!(target: TARGET_CONSOLE, "YARA scanner initialized");
                    Arc::new(s)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load YARA rules; YARA scanning disabled");
                    Arc::new(scanner::Scanner::empty())
                }
            }
        } else {
            info!(target: TARGET_CONSOLE, "YARA scanning disabled by configuration");
            Arc::new(scanner::Scanner::empty())
        };

        let yara_allowlist_paths =
            scanner::normalize_allowlist_paths(&cfg.scanner.yara_allowlist_paths);

        // IOC engine
        let ioc_engine = Arc::new(IocEngine::load(&cfg.ioc));
        if ioc_engine.is_enabled() {
            let stats = ioc_engine.stats();
            info!(
                target: TARGET_CONSOLE,
                md5 = stats.md5,
                sha1 = stats.sha1,
                sha256 = stats.sha256,
                ip = stats.ip,
                cidr = stats.cidr,
                domain_exact = stats.domain_exact,
                domain_suffix = stats.domain_suffix,
                path_regex = stats.path_regex,
                "IOC engine initialized"
            );
        } else {
            info!(target: TARGET_CONSOLE, "IOC detection disabled by configuration");
        }

        // Detector store + hot-reload
        let detectors = DetectorStore::new(
            Arc::clone(&sigma_engine),
            Arc::clone(&yara_scanner),
            Arc::clone(&ioc_engine),
        );

        let mut reload_poller = None;
        let mut reload_worker_handle = None;
        let mut reload_tx = None;
        if cfg.reload.enabled {
            let (tx, rx) = mpsc::unbounded_channel();
            reload_worker_handle = Some(reload::spawn_reload_worker(
                Arc::clone(&detectors),
                cfg.scanner.clone(),
                cfg.ioc.clone(),
                cfg.reload.clone(),
                cfg.alerts.match_debug,
                resolved_config_path.clone(),
                response_config.clone(),
                rx,
            ));
            reload_poller = Some(reload::spawn_reload_poller(
                cfg.scanner.clone(),
                cfg.ioc.clone(),
                cfg.reload.clone(),
                resolved_config_path.clone(),
                tx.clone(),
            ));
            reload_tx = Some(tx);
        }

        let (yara_memory_tx, yara_memory_rx) =
            if cfg.scanner.yara_enabled && cfg.scanner.yara_memory_enabled {
                let capacity = cfg.scanner.yara_memory_queue_capacity.max(1);
                let (tx, rx) = mpsc::channel::<YaraMemoryJob>(capacity);
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };

        // Spawn the optional YARA memory scanning worker.
        let yara_memory_worker_handle = if let Some(mem_rx) = yara_memory_rx {
            let mem_cfg = MemoryScanConfig {
                max_process_bytes: (cfg.scanner.yara_memory_max_process_mb * 1024 * 1024) as usize,
                max_region_bytes: (cfg.scanner.yara_memory_max_region_mb * 1024 * 1024) as usize,
                include_private: cfg.scanner.yara_memory_include_private,
                include_image: cfg.scanner.yara_memory_include_image,
                include_mapped: cfg.scanner.yara_memory_include_mapped,
                delay_ms: cfg.scanner.yara_memory_delay_ms,
            };
            Some(runtime_yara::spawn_yara_memory_worker(
                Arc::clone(&detectors),
                alert_sink.clone(),
                response_engine.clone(),
                mem_cfg,
                cfg.alerts.match_debug,
                mem_rx,
                platform,
                "yara-memory",
            ))
        } else {
            None
        };

        // Host-state enrichment and canonicalization boundary.
        let host_state = state.host;

        // Detection handlers + router
        let sigma_handler = NormalizedEventHandler::detecting(
            Arc::clone(&host_state),
            DetectionPipeline {
                detectors: Arc::clone(&detectors),
                alert_sink: alert_sink.clone(),
                response_engine: response_engine.clone(),
            },
        );

        let yara_memory_handler = yara_memory_tx.map(|tx| YaraMemoryEventHandler {
            tx,
            allowlist_paths: yara_allowlist_paths,
        });

        let mut downstream = SensorEventRouter::new();
        downstream.register_handler(Box::new(sigma_handler));
        if let Some(handler) = yara_memory_handler {
            downstream.register_handler(Box::new(handler));
        }
        let (router, artifact_worker_handle, artifact_resolver_handle) = spawn_artifact_resolver(
            Arc::new(downstream),
            Arc::clone(&host_state),
            ArtifactRuntime {
                detectors: Some(Arc::clone(&detectors)),
                alert_sink: Some(alert_sink),
                response_engine: Some(response_engine),
                match_debug: cfg.alerts.match_debug,
                yara_allowlist_paths: scanner::normalize_allowlist_paths(
                    &cfg.scanner.yara_allowlist_paths,
                ),
                pe_metadata: platform == Platform::Windows,
            },
        );

        Self {
            router,
            host_state,
            artifact_worker_handle,
            artifact_resolver_handle,
            yara_memory_worker_handle,
            reload_poller,
            reload_worker_handle,
            reload_tx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn optional_workers_follow_configuration_and_release_response_senders() {
        for enabled in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let mut cfg = AppConfig::default();
            cfg.scanner.sigma_enabled = false;
            cfg.scanner.yara_enabled = enabled;
            cfg.scanner.yara_memory_enabled = enabled;
            cfg.scanner.yara_rules_path = temp.path().to_path_buf();
            cfg.ioc.enabled = enabled;
            cfg.ioc.hashes_path = temp.path().join("hashes.txt");
            cfg.ioc.ips_path = temp.path().join("ips.txt");
            cfg.ioc.domains_path = temp.path().join("domains.txt");
            cfg.ioc.paths_regex_path = temp.path().join("paths.txt");
            std::fs::write(&cfg.ioc.domains_path, "example.test\n").unwrap();
            cfg.reload.enabled = enabled;
            cfg.response.enabled = false;
            cfg.response.prevention_enabled = false;
            let response_config = Arc::new(ArcSwap::from_pointee(cfg.response.clone()));
            let (response, response_worker) = ResponseEngine::new(response_config.clone());
            let (writer, _guard) = tracing_appender::non_blocking(std::io::sink());
            let pipeline = LivePipeline::new(
                &cfg,
                None,
                Platform::Linux,
                SharedState::new(&cfg),
                AlertSink::new(writer),
                response_config,
                response.clone(),
            );
            assert!(!pipeline.artifact_worker_handle.is_finished());
            assert_eq!(pipeline.yara_memory_worker_handle.is_some(), enabled);
            assert_eq!(pipeline.reload_poller.is_some(), enabled);
            assert_eq!(pipeline.reload_worker_handle.is_some(), enabled);
            assert_eq!(pipeline.reload_tx.is_some(), enabled);
            drop(response);
            let sensor_worker = tokio::spawn(async {});
            let (writer, _shutdown_guard) = tracing_appender::non_blocking(std::io::sink());
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                pipeline.shutdown(
                    sensor_worker,
                    response_worker,
                    None,
                    &AlertSink::new(writer),
                    None,
                ),
            )
            .await
            .expect("pipeline must release all worker senders");
        }
    }
}
