//! Shared construction of live detection workers and event routing.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::alerts::AlertSink;
use crate::config::{AppConfig, ResponseConfig};
use crate::engine::{DetectionPipeline, DetectorStore, Engine, NormalizedEventHandler};
use crate::ioc::IocEngine;
use crate::memory::MemoryScanConfig;
use crate::normalizer::Normalizer;
use crate::response::ResponseEngine;
use crate::runtime::logging::TARGET_CONSOLE;
use crate::runtime::{ioc as runtime_ioc, yara as runtime_yara};
use crate::scanner::{YaraEventHandler, YaraMemoryJob};
use crate::sensor::{Platform, SensorEventRouter};
use crate::state::{ConnectionAggregator, DnsCache, ProcessCache, SidCache};
use crate::{reload, scanner};

pub(super) struct SharedState {
    pub process_cache: Arc<ProcessCache>,
    sid_cache: Arc<SidCache>,
    dns_cache: Arc<DnsCache>,
    connection_aggregator: Arc<ConnectionAggregator>,
}

impl SharedState {
    pub fn new(cfg: &AppConfig) -> Self {
        Self {
            process_cache: Arc::new(ProcessCache::with_max_entries(cfg.process.max_entries)),
            sid_cache: Arc::new(SidCache::new()),
            dns_cache: Arc::new(DnsCache::new()),
            connection_aggregator: Arc::new(ConnectionAggregator::with_limits_and_window(
                cfg.network.aggregation_max_entries,
                cfg.network.aggregation_interval_buffer_size,
                cfg.network.aggregation_window_secs,
            )),
        }
    }
}

pub(super) struct LivePipeline {
    pub router: Arc<SensorEventRouter>,
    pub yara_worker_handle: Option<JoinHandle<()>>,
    pub yara_memory_worker_handle: Option<JoinHandle<()>>,
    pub ioc_hash_worker_handle: Option<JoinHandle<()>>,
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
        let provider = match platform {
            Platform::Linux => "ebpf",
            Platform::MacOS => "esf",
            Platform::Windows => "etw",
        };
        // 5. Sigma engine
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
                for (logsource, count) in stats.rules_by_logsource {
                    info!(logsource = %logsource, count, "Sigma rules loaded");
                }
            }
        } else {
            info!(target: TARGET_CONSOLE, "Sigma detection disabled by configuration");
        }
        let sigma_engine = Arc::new(sigma_engine);

        // 6. YARA scanner
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

        // 7. IOC engine
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

        // 8. Detector store + hot-reload
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

        // 9. YARA background worker
        let (yara_tx, yara_worker_handle) = if cfg.scanner.yara_enabled {
            let (tx, rx) = mpsc::channel::<(String, u32)>(1000);
            let handle = runtime_yara::spawn_yara_file_worker(
                Arc::clone(&detectors),
                alert_sink.clone(),
                response_engine.clone(),
                cfg.alerts.match_debug,
                rx,
                yara_allowlist_paths.clone(),
                platform,
                provider,
            );
            (Some(tx), Some(handle))
        } else {
            (None, None)
        };

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

        // 10. IOC hash background worker
        let (ioc_hash_tx, ioc_hash_worker_handle) = if ioc_engine.is_enabled() {
            let (hash_tx, hash_rx) = mpsc::channel::<(String, u32)>(1000);
            let handle = runtime_ioc::spawn_ioc_hash_worker(
                Arc::clone(&detectors),
                alert_sink.clone(),
                response_engine.clone(),
                hash_rx,
                platform,
                provider,
            );
            (Some(hash_tx), Some(handle))
        } else {
            (None, None)
        };

        // 11. Normalizer
        let normalizer = Arc::new(Normalizer::new(
            Arc::clone(&state.process_cache),
            Arc::clone(&state.sid_cache),
            Arc::clone(&state.dns_cache),
            Arc::clone(&state.connection_aggregator),
            cfg.network.aggregation_enabled,
        ));

        // 12. Detection handlers + router
        let sigma_handler = NormalizedEventHandler::detecting(
            Arc::clone(&normalizer),
            DetectionPipeline {
                detectors: Arc::clone(&detectors),
                ioc_hash_tx,
                alert_sink: alert_sink.clone(),
                response_engine: response_engine.clone(),
            },
        );

        let yara_handler = if cfg.scanner.yara_enabled {
            let yara_handler = YaraEventHandler {
                tx: yara_tx.expect("yara_tx exists when enabled"),
                memory_tx: yara_memory_tx,
                allowlist_paths: yara_allowlist_paths,
            };
            Some(yara_handler)
        } else {
            None
        };

        let mut router_inner = SensorEventRouter::new();
        router_inner.register_handler(Box::new(sigma_handler));
        if let Some(yh) = yara_handler {
            router_inner.register_handler(Box::new(yh));
        }
        let router = Arc::new(router_inner);

        Self {
            router,
            yara_worker_handle,
            yara_memory_worker_handle,
            ioc_hash_worker_handle,
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
            assert_eq!(pipeline.yara_worker_handle.is_some(), enabled);
            assert_eq!(pipeline.yara_memory_worker_handle.is_some(), enabled);
            assert_eq!(pipeline.ioc_hash_worker_handle.is_some(), enabled);
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
