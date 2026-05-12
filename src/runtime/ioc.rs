use crate::alerts::AlertSink;
use crate::ioc::{HashCache, HashRequirements};
use crate::reload::DetectorStore;
use crate::response::ResponseEngine;
use crate::sensor::Platform;
use crate::utils::LogRateLimiter;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info};

const WORKER_DEBUG_LOG_WINDOW_SECS: u64 = 30;

pub fn spawn_ioc_hash_worker(
    detectors: Arc<DetectorStore>,
    alert_sink: AlertSink,
    response_engine: ResponseEngine,
    mut rx: mpsc::Receiver<(String, u32)>,
    platform: Platform,
    provider: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        info!(
            target: "ioc",
            "IOC hash worker thread started and waiting for files to hash"
        );
        let mut cache = HashCache::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut last_requirements = HashRequirements {
            md5: false,
            sha1: false,
            sha256: false,
        };
        let mut hash_error_limiter =
            LogRateLimiter::new(Duration::from_secs(WORKER_DEBUG_LOG_WINDOW_SECS));

        while let Some((path, pid)) = rx.blocking_recv() {
            if path.is_empty() {
                continue;
            }

            let ioc_engine = detectors.ioc();
            if !ioc_engine.is_enabled() || !ioc_engine.wants_hashing() {
                continue;
            }

            let requirements = ioc_engine.hash_requirements();
            if requirements != last_requirements {
                cache = HashCache::new();
                last_requirements = requirements;
                info!(
                    target: "ioc",
                    md5 = requirements.md5,
                    sha1 = requirements.sha1,
                    sha256 = requirements.sha256,
                    "IOC hash requirements changed; cache reset"
                );
            }

            let max_file_size = ioc_engine.max_file_size_bytes();
            if ioc_engine.is_hash_allowlisted(&path) {
                tracing::trace!(
                    target: "ioc",
                    pid = pid,
                    file = %path,
                    "IOC hash worker skipping allowlisted path"
                );
                continue;
            }

            if max_file_size > 0 {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if metadata.len() > max_file_size {
                        tracing::trace!(
                            target: "ioc",
                            pid = pid,
                            file = %path,
                            file_mb = metadata.len() / (1024 * 1024),
                            max_mb = max_file_size / (1024 * 1024),
                            "IOC hash worker skipping oversized file"
                        );
                        continue;
                    }
                }
            }

            let hashes = match cache.get_or_compute(Path::new(&path), requirements, &mut buf) {
                Ok(hashes) => hashes,
                Err(err) => {
                    let decision = hash_error_limiter.should_emit("hash_error");
                    if decision.should_emit {
                        debug!(
                            target: "ioc",
                            pid = pid,
                            file = %path,
                            error = %err,
                            suppressed = decision.suppressed_since_last_emit,
                            "IOC hash worker failed to hash file"
                        );
                    }
                    continue;
                }
            };

            let matches = ioc_engine.match_hashes(&hashes);
            if !matches.is_empty() {
                info!(
                    pid = pid,
                    file = %path,
                    matches = matches.len(),
                    "IOC hash match detected"
                );
                for ioc_match in matches {
                    let alert = ioc_engine
                        .build_alert_for_hash_match(&ioc_match, &path, pid, platform, provider);
                    alert_sink.write_alert(&alert);
                    response_engine.handle_alert(&alert);
                }
            } else {
                tracing::trace!(
                    target: "ioc",
                    pid = pid,
                    file = %path,
                    "IOC hash worker no matches"
                );
            }
        }

        info!(target: "ioc", "IOC hash worker thread shutting down");
    })
}
