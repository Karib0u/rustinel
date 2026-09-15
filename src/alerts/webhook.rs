//! HTTP webhook delivery of ECS alerts.
//!
//! Every alert the sink writes to the NDJSON file is also offered to each
//! configured destination as one `POST` whose body is the same ECS JSON
//! object. The file stays the source of truth: offering never blocks and never
//! fails the file write.
//!
//! Each destination has its own bounded queue and one delivery task on the
//! agent's Tokio runtime, so a slow or failing endpoint only fills its own
//! queue. A full queue drops the new alert and counts it. Failed attempts are
//! retried with capped exponential backoff and jitter, up to `max_attempts`.
//!
//! Delivery uses reqwest's async client rather than the blocking one: the
//! blocking client runs its own runtime thread per client and must not be used
//! from async context, while the agent already runs a multi-threaded runtime
//! whose workers are idle while a request waits on the network.
//!
//! Nothing configured as a credential is logged. Diagnostics name a
//! destination by its label and `scheme://host[:port]` only, request errors are
//! stripped of their URL, and header values are marked sensitive.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, RETRY_AFTER};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::WebhookConfig;
use crate::telemetry::{WebhookCounters, WebhookSnapshot};
use crate::utils::LogRateLimiter;

/// Tracing target for webhook delivery.
pub const TARGET_WEBHOOK: &str = "alert_webhook";

/// Header carrying an identifier that stays the same across retries of one
/// alert, and across destinations, so receivers can discard duplicates.
pub const DELIVERY_HEADER: &str = "x-rustinel-delivery";
/// Unix time in seconds at which the signature was computed.
pub const TIMESTAMP_HEADER: &str = "x-rustinel-timestamp";
/// `sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`.
pub const SIGNATURE_HEADER: &str = "x-rustinel-signature";

/// How long shutdown waits for queued alerts to be delivered.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Spacing between repeated warnings of one kind for one destination.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

struct Delivery {
    id: Arc<str>,
    body: Arc<[u8]>,
}

struct Destination {
    counters: Arc<WebhookCounters>,
    tx: mpsc::Sender<Delivery>,
    max_payload_bytes: usize,
}

struct Worker {
    client: reqwest::Client,
    url: reqwest::Url,
    headers: HeaderMap,
    secret: Option<Vec<u8>>,
    max_attempts: u32,
    retry_initial: Duration,
    retry_max: Duration,
    counters: Arc<WebhookCounters>,
    warnings: Arc<Mutex<LogRateLimiter>>,
}

/// Fans alerts out to every configured webhook destination.
pub struct WebhookDispatcher {
    destinations: Vec<Destination>,
    workers: Mutex<Vec<(Arc<WebhookCounters>, JoinHandle<()>)>>,
    stop: watch::Sender<bool>,
    warnings: Arc<Mutex<LogRateLimiter>>,
    delivery_prefix: u64,
    next_delivery: AtomicU64,
}

impl WebhookDispatcher {
    /// Build a client and spawn a delivery task for each destination.
    ///
    /// Must be called from within a Tokio runtime. The configuration is
    /// expected to have passed [`crate::config::AppConfig::validate`]; an error
    /// here means the TLS backend could not be initialized.
    pub fn start(configs: &[WebhookConfig]) -> anyhow::Result<Self> {
        let (stop, _) = watch::channel(false);
        let warnings = Arc::new(Mutex::new(LogRateLimiter::new(WARN_INTERVAL)));
        let mut destinations = Vec::with_capacity(configs.len());
        let mut workers = Vec::with_capacity(configs.len());

        for (index, config) in configs.iter().enumerate() {
            config
                .validate(index)
                .map_err(|err| anyhow::anyhow!("invalid webhook configuration: {err}"))?;
            let label = config.label();
            let target = config.target();
            let worker = Worker::new(config, &label, &target, Arc::clone(&warnings))?;
            let counters = Arc::clone(&worker.counters);
            let (tx, rx) = mpsc::channel(config.queue_capacity);
            let handle = tokio::spawn(worker.run(rx, stop.subscribe()));

            if url_is_cleartext(config) && config.carries_credentials() {
                warn!(
                    target: TARGET_WEBHOOK,
                    webhook = %label,
                    target_url = %target,
                    "Webhook sends credentials over plain HTTP; use https"
                );
            }
            info!(
                target: TARGET_WEBHOOK,
                webhook = %label,
                target_url = %target,
                queue_capacity = config.queue_capacity,
                max_attempts = config.max_attempts,
                signed = config.secret.is_some(),
                "Alert webhook enabled"
            );

            destinations.push(Destination {
                counters: Arc::clone(&counters),
                tx,
                max_payload_bytes: config.max_payload_bytes,
            });
            workers.push((counters, handle));
        }

        Ok(Self {
            destinations,
            workers: Mutex::new(workers),
            stop,
            warnings,
            delivery_prefix: RandomState::new().hash_one(std::process::id()),
            next_delivery: AtomicU64::new(0),
        })
    }

    /// Number of configured destinations.
    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Current counters of every destination, in configuration order.
    pub fn snapshots(&self) -> Vec<WebhookSnapshot> {
        self.destinations
            .iter()
            .map(|destination| destination.counters.snapshot())
            .collect()
    }

    /// Queue one serialized ECS alert for every destination. Never blocks.
    pub fn dispatch(&self, body: &[u8]) {
        if self.destinations.is_empty() {
            return;
        }
        let sequence = self.next_delivery.fetch_add(1, Ordering::Relaxed);
        let id: Arc<str> = Arc::from(format!("{:016x}-{sequence}", self.delivery_prefix));
        let body: Arc<[u8]> = Arc::from(body);

        for destination in &self.destinations {
            let counters = &destination.counters;
            if body.len() > destination.max_payload_bytes {
                let total = counters.record_dropped_oversized();
                self.warn_limited(counters, "oversized", |suppressed| {
                    warn!(
                        target: TARGET_WEBHOOK,
                        webhook = counters.name(),
                        bytes = body.len(),
                        max_payload_bytes = destination.max_payload_bytes,
                        dropped_total = total,
                        suppressed_warnings = suppressed,
                        "Alert exceeds the webhook payload limit; not sent to this destination"
                    );
                });
                continue;
            }

            let delivery = Delivery {
                id: Arc::clone(&id),
                body: Arc::clone(&body),
            };
            match destination.tx.try_send(delivery) {
                Ok(()) => {
                    let depth = destination
                        .tx
                        .max_capacity()
                        .saturating_sub(destination.tx.capacity());
                    counters.record_queued(depth);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let total = counters.record_dropped_queue_full();
                    self.warn_limited(counters, "queue_full", |suppressed| {
                        warn!(
                            target: TARGET_WEBHOOK,
                            webhook = counters.name(),
                            capacity = destination.tx.max_capacity(),
                            dropped_total = total,
                            suppressed_warnings = suppressed,
                            "Webhook queue full; dropping alert for this destination"
                        );
                    });
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Offered after shutdown stopped the worker. Counted as
                    // queued too, so queued always equals the outcomes plus
                    // what is still pending.
                    counters.record_queued(0);
                    counters.record_abandoned(1);
                }
            }
        }
    }

    /// Stop accepting work once queues are empty, waiting at most `grace`.
    ///
    /// Alerts still queued or in flight when the grace period ends are counted
    /// as abandoned. Call after the final dedup flush so rollups are included.
    pub async fn shutdown(&self, grace: Duration) {
        let _ = self.stop.send(true);
        let workers = std::mem::take(&mut *self.workers.lock().unwrap_or_else(|e| e.into_inner()));
        let deadline = tokio::time::Instant::now() + grace;

        for (counters, mut handle) in workers {
            if tokio::time::timeout_at(deadline, &mut handle)
                .await
                .is_err()
            {
                handle.abort();
                let _ = handle.await;
            }
            let pending = counters.pending();
            if pending > 0 {
                counters.record_abandoned(pending);
                warn!(
                    target: TARGET_WEBHOOK,
                    webhook = counters.name(),
                    abandoned = pending,
                    grace_secs = grace.as_secs(),
                    "Webhook alerts undelivered at shutdown"
                );
            }
            let snapshot = counters.snapshot();
            info!(
                target: TARGET_WEBHOOK,
                webhook = counters.name(),
                delivered = snapshot.delivered,
                failed = snapshot.failed,
                dropped = snapshot.dropped_queue_full,
                oversized = snapshot.dropped_oversized,
                abandoned = snapshot.abandoned_at_shutdown,
                retries = snapshot.retries,
                "Webhook delivery summary"
            );
        }
    }

    fn warn_limited(&self, counters: &WebhookCounters, kind: &str, emit: impl FnOnce(u64)) {
        warn_limited(&self.warnings, counters, kind, emit);
    }
}

fn warn_limited(
    warnings: &Mutex<LogRateLimiter>,
    counters: &WebhookCounters,
    kind: &str,
    emit: impl FnOnce(u64),
) {
    let key = format!("{}:{kind}", counters.name());
    let decision = warnings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .should_emit(&key);
    if decision.should_emit {
        emit(decision.suppressed_since_last_emit);
    }
}

fn url_is_cleartext(config: &WebhookConfig) -> bool {
    config
        .url
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("http:")
}

enum Attempt {
    Delivered,
    Retry {
        reason: String,
        retry_after: Option<Duration>,
    },
    GiveUp {
        reason: String,
    },
}

impl Worker {
    fn new(
        config: &WebhookConfig,
        label: &str,
        target: &str,
        warnings: Arc<Mutex<LogRateLimiter>>,
    ) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(&config.url)
            .map_err(|_| anyhow::anyhow!("webhook {label}: url is not valid"))?;
        let mut headers = HeaderMap::new();
        for (name, value) in &config.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                anyhow::anyhow!("webhook {label}: header name {name:?} is not valid")
            })?;
            let mut value = HeaderValue::from_str(value).map_err(|_| {
                anyhow::anyhow!("webhook {label}: value of header {name:?} is not valid")
            })?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }

        let timeout = Duration::from_millis(config.timeout_ms);
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // A redirected POST is not a delivery, and following one could
            // hand the configured headers to another host.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("rustinel/", env!("CARGO_PKG_VERSION")));
        if !config.tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        for certificate in config
            .load_ca_bundle()
            .map_err(|err| anyhow::anyhow!("webhook {label}: ca_file: {err}"))?
        {
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build().map_err(|err| {
            anyhow::anyhow!("webhook {label}: HTTP client: {}", describe_error(err))
        })?;

        Ok(Self {
            client,
            url,
            headers,
            secret: config
                .secret
                .as_ref()
                .map(|secret| secret.as_bytes().to_vec()),
            max_attempts: config.max_attempts,
            retry_initial: Duration::from_millis(config.retry_initial_ms),
            retry_max: Duration::from_millis(config.retry_max_ms),
            counters: WebhookCounters::register(
                label.to_string(),
                target.to_string(),
                config.queue_capacity,
            ),
            warnings,
        })
    }

    async fn run(self, mut rx: mpsc::Receiver<Delivery>, mut stop: watch::Receiver<bool>) {
        loop {
            // Biased toward the queue, so shutdown drains what is already
            // queued before the stop signal is observed.
            tokio::select! {
                biased;
                delivery = rx.recv() => match delivery {
                    Some(delivery) => self.deliver(delivery).await,
                    None => return,
                },
                _ = stop.changed() => return,
            }
        }
    }

    async fn deliver(&self, delivery: Delivery) {
        let started = Instant::now();
        let mut attempt = 1;
        loop {
            let outcome = self.attempt(&delivery).await;
            let reason = match outcome {
                Attempt::Delivered => {
                    self.counters.record_delivered();
                    debug!(
                        target: TARGET_WEBHOOK,
                        webhook = self.counters.name(),
                        delivery = &*delivery.id,
                        attempts = attempt,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "Alert delivered to webhook"
                    );
                    return;
                }
                Attempt::GiveUp { reason } => reason,
                Attempt::Retry {
                    reason,
                    retry_after,
                } => {
                    if attempt < self.max_attempts {
                        let delay = backoff_delay(
                            attempt,
                            self.retry_initial,
                            self.retry_max,
                            retry_after,
                            RandomState::new().hash_one(attempt),
                        );
                        debug!(
                            target: TARGET_WEBHOOK,
                            webhook = self.counters.name(),
                            delivery = &*delivery.id,
                            attempt,
                            reason = %reason,
                            delay_ms = delay.as_millis() as u64,
                            "Webhook attempt failed; retrying"
                        );
                        self.counters.record_retry();
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    reason
                }
            };

            let total = self.counters.record_failed();
            warn_limited(&self.warnings, &self.counters, "failed", |suppressed| {
                warn!(
                    target: TARGET_WEBHOOK,
                    webhook = self.counters.name(),
                    target_url = self.counters.target(),
                    attempts = attempt,
                    reason = %reason,
                    failed_total = total,
                    suppressed_warnings = suppressed,
                    "Webhook delivery failed; alert not delivered to this destination"
                );
            });
            return;
        }
    }

    async fn attempt(&self, delivery: &Delivery) -> Attempt {
        let mut request = self
            .client
            .post(self.url.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(DELIVERY_HEADER, &*delivery.id)
            .headers(self.headers.clone());
        if let Some(secret) = &self.secret {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string();
            request = request.header(TIMESTAMP_HEADER, &timestamp).header(
                SIGNATURE_HEADER,
                signature(secret, &timestamp, &delivery.body),
            );
        }

        match request.body(delivery.body.to_vec()).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return Attempt::Delivered;
                }
                let reason = format!("HTTP {}", status.as_u16());
                if is_retryable_status(status.as_u16()) {
                    Attempt::Retry {
                        reason,
                        retry_after: retry_after(response.headers()),
                    }
                } else {
                    Attempt::GiveUp { reason }
                }
            }
            Err(err) => Attempt::Retry {
                reason: describe_error(err),
                retry_after: None,
            },
        }
    }
}

/// The `X-Rustinel-Signature` value for `body` sent at `timestamp`.
pub fn signature(secret: &[u8], timestamp: &str, body: &[u8]) -> String {
    let mac = hmac_sha256(secret, &[timestamp.as_bytes(), b".", body]);
    format!("sha256={}", hex::encode(mac))
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `message`.
fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    for part in message {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());

    let mut mac = [0u8; 32];
    mac.copy_from_slice(&outer.finalize());
    mac
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500..=599)
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Delay before retry number `attempt` (1 for the first retry).
///
/// Exponential from `initial`, capped at `max`, with the upper half jittered
/// so destinations that failed together do not retry in lockstep. A server's
/// `Retry-After` raises the delay, but never past `max`.
fn backoff_delay(
    attempt: u32,
    initial: Duration,
    max: Duration,
    retry_after: Option<Duration>,
    entropy: u64,
) -> Duration {
    let factor = 1u32
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u32::MAX);
    let ceiling = initial.saturating_mul(factor).min(max);
    let floor = ceiling / 2;
    let span_ms = (ceiling - floor).as_millis() as u64;
    let jittered = floor + Duration::from_millis(entropy % (span_ms + 1));
    match retry_after {
        Some(requested) => jittered.max(requested.min(max)),
        None => jittered,
    }
}

/// A request error with its URL removed, plus its cause chain.
fn describe_error(err: reqwest::Error) -> String {
    let kind = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect"
    } else {
        "request"
    };
    let err = err.without_url();
    let mut text = format!("{kind}: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_test_cases() {
        // Test case 2: short key.
        assert_eq!(
            hex::encode(hmac_sha256(
                b"Jefe",
                &[b"what do ya want ", b"for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: key longer than one block is hashed first.
        assert_eq!(
            hex::encode(hmac_sha256(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn signature_covers_timestamp_and_body() {
        let signed = signature(b"key", "1700000000", b"{}");
        assert_eq!(
            signed,
            format!(
                "sha256={}",
                hex::encode(hmac_sha256(b"key", &[b"1700000000.{}"]))
            )
        );
        assert_ne!(signed, signature(b"key", "1700000001", b"{}"));
    }

    #[test]
    fn backoff_doubles_is_capped_and_honors_retry_after() {
        let initial = Duration::from_millis(100);
        let max = Duration::from_millis(1_000);
        for entropy in [0, 7, 999, u64::MAX] {
            let first = backoff_delay(1, initial, max, None, entropy);
            assert!((50..=100).contains(&first.as_millis()), "{first:?}");
            let third = backoff_delay(3, initial, max, None, entropy);
            assert!((200..=400).contains(&third.as_millis()), "{third:?}");
            let capped = backoff_delay(19, initial, max, None, entropy);
            assert!((500..=1_000).contains(&capped.as_millis()), "{capped:?}");
        }
        assert_eq!(
            backoff_delay(1, initial, max, Some(Duration::from_millis(800)), 0),
            Duration::from_millis(800)
        );
        assert_eq!(
            backoff_delay(1, initial, max, Some(Duration::from_secs(3_600)), 0),
            max
        );
    }

    #[test]
    fn only_transient_statuses_are_retried() {
        for status in [408, 425, 429, 500, 502, 503, 599] {
            assert!(is_retryable_status(status), "{status}");
        }
        for status in [300, 301, 400, 401, 403, 404, 413, 422] {
            assert!(!is_retryable_status(status), "{status}");
        }
    }
}
