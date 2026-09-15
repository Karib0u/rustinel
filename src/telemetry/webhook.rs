//! Delivery counters for `[[alerts.webhook]]` destinations.
//!
//! Each destination owns its counters. The registry keeps weak references so
//! the snapshot reports the destinations of the running sink and nothing that
//! has been torn down.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use serde::{Deserialize, Serialize};

/// Counters for one webhook destination at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookSnapshot {
    /// The destination's configured name, or its host and port.
    pub name: String,
    /// `scheme://host[:port]`; the path is left out because it can hold a token.
    pub target: String,
    /// Configured queue capacity.
    pub capacity: usize,
    /// Alerts queued for delivery.
    pub queued: u64,
    /// Alerts the endpoint accepted with a 2xx response.
    pub delivered: u64,
    /// Alerts given up on after a non-retryable response or the last attempt.
    pub failed: u64,
    /// Retry attempts made, across all alerts.
    pub retries: u64,
    /// Alerts not queued because the queue was full.
    pub dropped_queue_full: u64,
    /// Alerts not queued because their JSON exceeded `max_payload_bytes`.
    pub dropped_oversized: u64,
    /// Alerts still queued or in flight when the shutdown grace period ended.
    pub abandoned_at_shutdown: u64,
    /// Deepest queue depth observed.
    pub high_water_mark: usize,
}

impl WebhookSnapshot {
    /// Alerts that never reached this destination.
    pub fn undelivered(&self) -> u64 {
        self.failed
            .saturating_add(self.dropped_queue_full)
            .saturating_add(self.dropped_oversized)
            .saturating_add(self.abandoned_at_shutdown)
    }

    /// One-line operator summary.
    pub fn describe(&self) -> String {
        format!(
            "{} ({}): {} delivered, {} failed, {} dropped (queue full), {} oversized, {} abandoned at shutdown, {} retries, peak depth {}/{}",
            self.name,
            self.target,
            self.delivered,
            self.failed,
            self.dropped_queue_full,
            self.dropped_oversized,
            self.abandoned_at_shutdown,
            self.retries,
            self.high_water_mark,
            self.capacity
        )
    }
}

/// Live counters for one destination.
#[derive(Debug)]
pub struct WebhookCounters {
    name: String,
    target: String,
    capacity: usize,
    queued: AtomicU64,
    delivered: AtomicU64,
    failed: AtomicU64,
    retries: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_oversized: AtomicU64,
    abandoned_at_shutdown: AtomicU64,
    high_water_mark: AtomicUsize,
}

static REGISTRY: LazyLock<Mutex<Vec<Weak<WebhookCounters>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

impl WebhookCounters {
    /// Create counters for a destination and publish them to the snapshot.
    pub fn register(name: String, target: String, capacity: usize) -> Arc<Self> {
        let counters = Arc::new(Self {
            name,
            target,
            capacity,
            queued: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            dropped_queue_full: AtomicU64::new(0),
            dropped_oversized: AtomicU64::new(0),
            abandoned_at_shutdown: AtomicU64::new(0),
            high_water_mark: AtomicUsize::new(0),
        });
        let mut registry = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        registry.retain(|entry| entry.strong_count() > 0);
        registry.push(Arc::downgrade(&counters));
        counters
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn record_queued(&self, depth: usize) {
        self.queued.fetch_add(1, Ordering::Relaxed);
        if depth > self.high_water_mark.load(Ordering::Relaxed) {
            self.high_water_mark.fetch_max(depth, Ordering::Relaxed);
        }
    }

    /// Returns the running total, for the rate-limited warning.
    pub fn record_dropped_queue_full(&self) -> u64 {
        self.high_water_mark
            .fetch_max(self.capacity, Ordering::Relaxed);
        self.dropped_queue_full.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Returns the running total, for the rate-limited warning.
    pub fn record_dropped_oversized(&self) -> u64 {
        self.dropped_oversized.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_delivered(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the running total, for the rate-limited warning.
    pub fn record_failed(&self) -> u64 {
        self.failed.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Alerts queued that have reached no outcome yet.
    pub fn pending(&self) -> u64 {
        let snapshot = self.snapshot();
        snapshot
            .queued
            .saturating_sub(snapshot.delivered)
            .saturating_sub(snapshot.failed)
            .saturating_sub(snapshot.abandoned_at_shutdown)
    }

    pub fn record_abandoned(&self, count: u64) {
        self.abandoned_at_shutdown
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> WebhookSnapshot {
        WebhookSnapshot {
            name: self.name.clone(),
            target: self.target.clone(),
            capacity: self.capacity,
            queued: self.queued.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed),
            dropped_oversized: self.dropped_oversized.load(Ordering::Relaxed),
            abandoned_at_shutdown: self.abandoned_at_shutdown.load(Ordering::Relaxed),
            high_water_mark: self.high_water_mark.load(Ordering::Relaxed),
        }
    }
}

/// Every registered destination that is still alive, in registration order.
pub fn snapshot() -> Vec<WebhookSnapshot> {
    REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(Weak::upgrade)
        .map(|counters| counters.snapshot())
        .collect()
}
