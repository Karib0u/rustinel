use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// Connection Aggregator
// ============================================================================

/// Protocol type for network connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Unknown,
}

/// Key for connection aggregation
/// Uses process image (not PID) to survive process restarts
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub process_image: String,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub protocol: Protocol,
}

/// Aggregated connection state
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub first_seen: u64,
    pub last_seen: u64,
    pub count: u64,
    pub pids: HashSet<u32>,
    /// Ring buffer of inter-connection intervals for beacon detection
    intervals: VecDeque<u64>,
    interval_buffer_size: usize,
}

impl ConnectionState {
    fn new(timestamp: u64, pid: u32, interval_buffer_size: usize) -> Self {
        let mut pids = HashSet::new();
        pids.insert(pid);
        Self {
            first_seen: timestamp,
            last_seen: timestamp,
            count: 1,
            pids,
            intervals: VecDeque::with_capacity(interval_buffer_size),
            interval_buffer_size,
        }
    }

    fn update(&mut self, timestamp: u64, pid: u32) {
        let delta = timestamp.saturating_sub(self.last_seen);
        self.last_seen = timestamp;
        self.count += 1;
        self.pids.insert(pid);

        // Store interval for beacon detection
        if self.intervals.len() >= self.interval_buffer_size {
            self.intervals.pop_front();
        }
        self.intervals.push_back(delta);
    }

    /// Calculate standard deviation of intervals (for beacon detection)
    /// Low stddev with regular intervals indicates potential beaconing
    #[allow(dead_code)]
    pub fn interval_stddev(&self) -> Option<f64> {
        if self.intervals.len() < 2 {
            return None;
        }

        let sum: u64 = self.intervals.iter().sum();
        let count = self.intervals.len() as f64;
        let mean = sum as f64 / count;

        let variance: f64 = self
            .intervals
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / count;

        Some(variance.sqrt())
    }
}

/// Aggregation metadata for connection metrics.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AggregationMeta {
    pub first_seen: u64,
    pub last_seen: u64,
    pub connection_count: u64,
    pub unique_pids: Vec<u32>,
}

/// Result of recording a connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregationResult {
    /// First connection in the current aggregate period.
    FirstConnection,
    /// Subsequent connection in the current aggregate period.
    Aggregated,
}

/// Thread-safe cache for network connection aggregation
/// Tracks repeated connections to the same destination without suppressing
/// events from the detection pipeline.
pub struct ConnectionAggregator {
    cache: RwLock<HashMap<ConnectionKey, ConnectionState>>,
    max_entries: usize,
    interval_buffer_size: usize,
    window_secs: u64,
    last_cleanup: AtomicU64,
}

impl ConnectionAggregator {
    const DEFAULT_WINDOW_SECS: u64 = 60;

    /// Create with default limits
    pub fn new() -> Self {
        Self::with_limits(20_000, 50)
    }

    /// Create with custom limits
    pub fn with_limits(max_entries: usize, interval_buffer_size: usize) -> Self {
        Self::with_limits_and_window(max_entries, interval_buffer_size, Self::DEFAULT_WINDOW_SECS)
    }

    /// Create with custom limits and a time window for aggregate state.
    ///
    /// A zero window starts a new aggregate period for every connection. The
    /// window controls metric aggregation only. Network events are never
    /// suppressed by the normalizer.
    pub fn with_limits_and_window(
        max_entries: usize,
        interval_buffer_size: usize,
        window_secs: u64,
    ) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries,
            interval_buffer_size,
            window_secs,
            last_cleanup: AtomicU64::new(0),
        }
    }

    /// Record a connection and determine its aggregate period.
    ///
    /// Returns `FirstConnection` for a new aggregate period or `Aggregated`
    /// for a repeat within the current period.
    pub fn record(
        &self,
        process_image: &str,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: Protocol,
        pid: u32,
    ) -> AggregationResult {
        self.record_at(now_secs(), process_image, dest_ip, dest_port, protocol, pid)
    }

    /// Record a connection at a supplied timestamp.
    ///
    /// This is useful for deterministic callers and tests that need to verify
    /// aggregate-window expiration without waiting for wall-clock time.
    pub fn record_at(
        &self,
        timestamp: u64,
        process_image: &str,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: Protocol,
        pid: u32,
    ) -> AggregationResult {
        let key = ConnectionKey {
            process_image: process_image.to_string(),
            dest_ip,
            dest_port,
            protocol,
        };

        let mut cache = self.cache.write().unwrap();

        if let Some(state) = cache.get_mut(&key) {
            if timestamp.saturating_sub(state.first_seen) >= self.window_secs {
                *state = ConnectionState::new(timestamp, pid, self.interval_buffer_size);
                return AggregationResult::FirstConnection;
            }

            state.update(timestamp, pid);
            return AggregationResult::Aggregated;
        }

        // First connection in this aggregate period - insert and emit.
        cache.insert(
            key,
            ConnectionState::new(timestamp, pid, self.interval_buffer_size),
        );

        // Trim if over capacity
        if cache.len() > self.max_entries {
            self.trim_cache(&mut cache);
        }

        AggregationResult::FirstConnection
    }

    /// Get aggregation metadata for a connection metric.
    #[allow(dead_code)]
    pub fn get_meta(
        &self,
        process_image: &str,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: Protocol,
    ) -> Option<AggregationMeta> {
        let key = ConnectionKey {
            process_image: process_image.to_string(),
            dest_ip,
            dest_port,
            protocol,
        };

        let cache = self.cache.read().unwrap();
        cache.get(&key).map(|state| AggregationMeta {
            first_seen: state.first_seen,
            last_seen: state.last_seen,
            connection_count: state.count,
            unique_pids: state.pids.iter().copied().collect(),
        })
    }

    /// Get current cache size
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Check if aggregation is enabled for given config
    /// Placeholder for future config integration
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        true
    }

    fn trim_cache(&self, cache: &mut HashMap<ConnectionKey, ConnectionState>) {
        let len = cache.len();
        if len <= self.max_entries {
            return;
        }

        let now = now_secs();
        let last = self.last_cleanup.load(std::sync::atomic::Ordering::Relaxed);

        // Avoid expensive trimming more than once per second, but still enforce cap.
        if now.saturating_sub(last) < 1 {
            let extra = cache.len().saturating_sub(self.max_entries);
            let keys: Vec<ConnectionKey> = cache.keys().take(extra).cloned().collect();
            for key in keys {
                cache.remove(&key);
            }
            return;
        }

        if self
            .last_cleanup
            .compare_exchange(
                last,
                now,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            let extra = cache.len().saturating_sub(self.max_entries);
            let keys: Vec<ConnectionKey> = cache.keys().take(extra).cloned().collect();
            for key in keys {
                cache.remove(&key);
            }
            return;
        }

        // Remove oldest entries (by last_seen) until under limit
        let mut timestamps: Vec<u64> = cache.values().map(|s| s.last_seen).collect();
        timestamps.sort_unstable();
        let cutoff = timestamps[len / 2];
        cache.retain(|_, state| state.last_seen >= cutoff);

        // If still over, remove by insertion order
        if cache.len() > self.max_entries {
            let extra = cache.len() - self.max_entries;
            let keys: Vec<ConnectionKey> = cache.keys().take(extra).cloned().collect();
            for key in keys {
                cache.remove(&key);
            }
        }
    }
}

impl Default for ConnectionAggregator {
    fn default() -> Self {
        Self::new()
    }
}
