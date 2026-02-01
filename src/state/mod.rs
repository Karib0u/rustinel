use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use crate::utils::lookup_account_sid;

/// Thread-safe cache for SID -> Domain\User resolution
pub struct SidCache {
    cache: Arc<RwLock<HashMap<String, String>>>,
    #[cfg(windows)]
    resolver_tx: std::sync::mpsc::SyncSender<String>,
    #[cfg(windows)]
    pending: Arc<RwLock<HashSet<String>>>,
}

impl SidCache {
    /// Create a new SidCache with common well-known SIDs pre-warmed
    pub fn new() -> Self {
        let mut cache = HashMap::new();
        cache.insert("S-1-5-18".to_string(), "NT AUTHORITY\\SYSTEM".to_string());
        cache.insert(
            "S-1-5-19".to_string(),
            "NT AUTHORITY\\LOCAL SERVICE".to_string(),
        );
        cache.insert(
            "S-1-5-20".to_string(),
            "NT AUTHORITY\\NETWORK SERVICE".to_string(),
        );

        let cache = Arc::new(RwLock::new(cache));

        #[cfg(windows)]
        {
            let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
            let cache_ref = Arc::clone(&cache);
            let pending = Arc::new(RwLock::new(HashSet::new()));
            let pending_ref = Arc::clone(&pending);

            let _ = std::thread::Builder::new()
                .name("sid-resolver".to_string())
                .spawn(move || {
                    while let Ok(sid) = rx.recv() {
                        if sid.is_empty() {
                            continue;
                        }

                        if cache_ref.read().unwrap().contains_key(&sid) {
                            if let Ok(mut pending) = pending_ref.write() {
                                pending.remove(&sid);
                            }
                            continue;
                        }

                        if let Ok(resolved) = lookup_account_sid(&sid) {
                            if let Ok(mut cache) = cache_ref.write() {
                                cache.insert(sid.clone(), resolved);
                            }
                        }

                        if let Ok(mut pending) = pending_ref.write() {
                            pending.remove(&sid);
                        }
                    }
                });

            Self {
                cache,
                resolver_tx: tx,
                pending,
            }
        }

        #[cfg(not(windows))]
        {
            Self { cache }
        }
    }

    /// Resolve a SID string to a Domain\User string, caching the result
    pub fn resolve(&self, sid: &str) -> Option<String> {
        if sid.is_empty() {
            return None;
        }

        if let Some(cached) = self.cache.read().unwrap().get(sid) {
            return Some(cached.clone());
        }

        self.queue_resolution(sid);

        None
    }

    #[cfg(windows)]
    fn queue_resolution(&self, sid: &str) {
        if self.cache.read().unwrap().contains_key(sid) {
            return;
        }

        if let Ok(mut pending) = self.pending.write() {
            if pending.contains(sid) {
                return;
            }
            pending.insert(sid.to_string());
        }

        if self.resolver_tx.try_send(sid.to_string()).is_err() {
            if let Ok(mut pending) = self.pending.write() {
                pending.remove(sid);
            }
        }
    }

    #[cfg(not(windows))]
    fn queue_resolution(&self, _sid: &str) {}
}

impl Default for SidCache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DnsEntry {
    pub hostname: String,
    pub timestamp: u64,
}

/// Thread-safe cache for IP -> Hostname correlation
pub struct DnsCache {
    cache: RwLock<HashMap<IpAddr, DnsEntry>>,
    max_entries: usize,
    ttl_secs: u64,
}

impl DnsCache {
    /// Create a DNS cache with sane defaults (size cap + lazy TTL on hit)
    pub fn new() -> Self {
        Self::with_limits(10_000, 15 * 60)
    }

    /// Create a DNS cache with custom limits (useful for tests)
    pub fn with_limits(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries,
            ttl_secs,
        }
    }

    /// Update cache with a fresh IP -> hostname mapping
    pub fn update(&self, ip: IpAddr, hostname: String) {
        let now = now_secs();
        let mut cache = self.cache.write().unwrap();
        cache.insert(
            ip,
            DnsEntry {
                hostname,
                timestamp: now,
            },
        );

        if cache.len() > self.max_entries {
            trim_dns_cache(&mut cache, self.max_entries);
        }
    }

    /// Lookup hostname by IP with lazy TTL expiry check (no write on hit)
    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let cache = self.cache.read().unwrap();
        let entry = cache.get(ip)?;
        if now_secs().saturating_sub(entry.timestamp) >= self.ttl_secs {
            return None;
        }
        Some(entry.hostname.clone())
    }

    /// Return current cache size (primarily for tests/metrics)
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn trim_dns_cache(cache: &mut HashMap<IpAddr, DnsEntry>, max_entries: usize) {
    let len = cache.len();
    if len <= max_entries {
        return;
    }

    let mut timestamps: Vec<u64> = cache.values().map(|entry| entry.timestamp).collect();
    timestamps.sort_unstable();
    let cutoff = timestamps[len / 2];
    cache.retain(|_, entry| entry.timestamp >= cutoff);

    if cache.len() > max_entries {
        let extra = cache.len() - max_entries;
        let keys: Vec<IpAddr> = cache.keys().take(extra).cloned().collect();
        for key in keys {
            cache.remove(&key);
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata associated with a process
#[derive(Debug, Clone)]
pub struct ProcessMetadata {
    pub image_name: String,
    #[allow(dead_code)]
    pub command_line: Option<String>,
    #[allow(dead_code)]
    pub user: Option<String>,
    /// Process creation time as Windows FILETIME (u64)
    #[allow(dead_code)]
    pub creation_time: u64,
    /// Parent process ID
    #[allow(dead_code)]
    pub parent_pid: Option<u32>,
    /// Parent process image name (enriched at creation time)
    #[allow(dead_code)]
    pub parent_image: Option<String>,
    /// Parent process command line (enriched at creation time)
    #[allow(dead_code)]
    pub parent_command_line: Option<String>,
    /// PE metadata: Original filename from version info
    #[allow(dead_code)]
    pub original_filename: Option<String>,
    /// PE metadata: Product name
    #[allow(dead_code)]
    pub product: Option<String>,
    /// PE metadata: File description
    #[allow(dead_code)]
    pub description: Option<String>,
    /// Process working directory
    #[allow(dead_code)]
    pub current_directory: Option<String>,
    /// Process integrity level
    #[allow(dead_code)]
    pub integrity_level: Option<String>,
    /// Logon session ID
    #[allow(dead_code)]
    pub logon_id: Option<String>,
    /// Logon session GUID
    #[allow(dead_code)]
    pub logon_guid: Option<String>,
}

/// Thread-safe cache for process metadata
/// Uses compound key (PID, CreationTime) to handle Windows PID reuse
/// Uses RwLock to allow many concurrent readers (network events) and few writers (process start/stop)
pub struct ProcessCache {
    /// Primary storage: (PID, CreationTime) -> Metadata
    cache: RwLock<HashMap<(u32, u64), ProcessMetadata>>,
    /// Secondary index: PID -> Latest CreationTime (for O(1) lookup from events that only have PID)
    pid_index: RwLock<HashMap<u32, u64>>,
    /// Recently-dead processes retained briefly to avoid parent/child race conditions
    graveyard: RwLock<HashMap<u32, GraveyardEntry>>,
    last_graveyard_cleanup: AtomicU64,
}

impl ProcessCache {
    /// Create a new empty ProcessCache
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            pid_index: RwLock::new(HashMap::new()),
            graveyard: RwLock::new(HashMap::new()),
            last_graveyard_cleanup: AtomicU64::new(0),
        }
    }

    /// Add or update a process in the cache with compound key
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `creation_time` - Windows FILETIME (u64) from kernel event
    /// * `image` - Full path to executable
    /// * `cmd` - Command line arguments
    /// * `user` - User account name
    /// * `parent_pid` - Parent process ID
    /// * `parent_image` - Parent process image (pre-enriched)
    /// * `parent_command_line` - Parent process command line (pre-enriched)
    /// * `original_filename` - PE metadata: Original filename
    /// * `product` - PE metadata: Product name
    /// * `description` - PE metadata: File description
    /// * `current_directory` - Process working directory
    /// * `integrity_level` - Process integrity level
    /// * `logon_id` - Logon session ID
    /// * `logon_guid` - Logon session GUID
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &self,
        pid: u32,
        creation_time: u64,
        image: String,
        cmd: Option<String>,
        user: Option<String>,
        parent_pid: Option<u32>,
        parent_image: Option<String>,
        parent_command_line: Option<String>,
        original_filename: Option<String>,
        product: Option<String>,
        description: Option<String>,
        current_directory: Option<String>,
        integrity_level: Option<String>,
        logon_id: Option<String>,
        logon_guid: Option<String>,
    ) {
        // Lock order: pid_index -> cache to avoid deadlocks with readers.
        {
            let mut pid_index = self.pid_index.write().unwrap();
            let mut cache = self.cache.write().unwrap();

            cache.insert(
                (pid, creation_time),
                ProcessMetadata {
                    image_name: image,
                    command_line: cmd,
                    user,
                    creation_time,
                    parent_pid,
                    parent_image,
                    parent_command_line,
                    original_filename,
                    product,
                    description,
                    current_directory,
                    integrity_level,
                    logon_id,
                    logon_guid,
                },
            );

            // Update secondary index to point to the latest creation time
            pid_index.insert(pid, creation_time);
        }

        if let Ok(mut graveyard) = self.graveyard.write() {
            graveyard.remove(&pid);
        }

        self.cleanup_graveyard_if_needed(now_secs());
    }

    /// Remove a process from the cache (called on process exit)
    /// Removes both from primary storage and updates secondary index
    pub fn remove(&self, pid: u32, creation_time: u64) {
        // Lock order: pid_index -> cache to avoid deadlocks with readers.
        let removed_meta = {
            let mut pid_index = self.pid_index.write().unwrap();
            let mut cache = self.cache.write().unwrap();

            let meta = cache.remove(&(pid, creation_time));

            // Only remove from index if this was the latest creation_time
            if let Some(&indexed_time) = pid_index.get(&pid) {
                if indexed_time == creation_time {
                    pid_index.remove(&pid);
                }
            }

            meta
        };

        if let Some(meta) = removed_meta {
            let now = now_secs();
            if let Ok(mut graveyard) = self.graveyard.write() {
                graveyard.insert(
                    pid,
                    GraveyardEntry {
                        metadata: meta,
                        death_time: now,
                    },
                );
            }
            self.cleanup_graveyard_if_needed(now);
        }
    }

    /// Get the image name for a given PID (uses latest creation time)
    /// Returns None if the process is not in the cache
    pub fn get_image(&self, pid: u32) -> Option<String> {
        let creation_time = {
            let pid_index = self.pid_index.read().unwrap();
            pid_index.get(&pid).copied()
        };

        if let Some(creation_time) = creation_time {
            let cache = self.cache.read().unwrap();
            if let Some(meta) = cache.get(&(pid, creation_time)) {
                return Some(meta.image_name.clone());
            }
        }

        let now = now_secs();
        self.cleanup_graveyard_if_needed(now);
        let graveyard = self.graveyard.read().unwrap();
        let entry = graveyard.get(&pid)?;
        if now.saturating_sub(entry.death_time) > GRAVEYARD_TTL_SECS {
            return None;
        }
        Some(entry.metadata.image_name.clone())
    }

    /// Get full metadata for a given PID (uses latest creation time)
    #[allow(dead_code)]
    pub fn get_metadata(&self, pid: u32) -> Option<ProcessMetadata> {
        let creation_time = {
            let pid_index = self.pid_index.read().unwrap();
            pid_index.get(&pid).copied()
        };

        if let Some(creation_time) = creation_time {
            let cache = self.cache.read().unwrap();
            if let Some(meta) = cache.get(&(pid, creation_time)) {
                return Some(meta.clone());
            }
        }

        let now = now_secs();
        self.cleanup_graveyard_if_needed(now);
        let graveyard = self.graveyard.read().unwrap();
        let entry = graveyard.get(&pid)?;
        if now.saturating_sub(entry.death_time) > GRAVEYARD_TTL_SECS {
            return None;
        }
        Some(entry.metadata.clone())
    }

    /// Get full metadata for a given compound key (PID, CreationTime)
    /// This is the precise lookup method that avoids PID reuse issues
    #[allow(dead_code)]
    pub fn get_metadata_by_key(&self, pid: u32, creation_time: u64) -> Option<ProcessMetadata> {
        let cache = self.cache.read().unwrap();
        if let Some(meta) = cache.get(&(pid, creation_time)) {
            return Some(meta.clone());
        }

        let now = now_secs();
        self.cleanup_graveyard_if_needed(now);
        let graveyard = self.graveyard.read().unwrap();
        let entry = graveyard.get(&pid)?;
        if entry.metadata.creation_time != creation_time {
            return None;
        }
        if now.saturating_sub(entry.death_time) > GRAVEYARD_TTL_SECS {
            return None;
        }
        Some(entry.metadata.clone())
    }

    /// Get the current count of cached processes
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }

    /// Get the latest creation time for a given PID
    /// Used by enrichment logic to lookup parent metadata
    #[allow(dead_code)]
    pub fn get_latest_creation_time(&self, pid: u32) -> Option<u64> {
        let pid_index = self.pid_index.read().unwrap();
        pid_index.get(&pid).copied()
    }

    fn cleanup_graveyard_if_needed(&self, now: u64) {
        let last = self.last_graveyard_cleanup.load(Ordering::Relaxed);
        if now.saturating_sub(last) < GRAVEYARD_CLEANUP_INTERVAL_SECS {
            return;
        }
        if self
            .last_graveyard_cleanup
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        if let Ok(mut graveyard) = self.graveyard.write() {
            graveyard.retain(|_, entry| now.saturating_sub(entry.death_time) <= GRAVEYARD_TTL_SECS);
        }
    }
}

impl Default for ProcessCache {
    fn default() -> Self {
        Self::new()
    }
}

struct GraveyardEntry {
    metadata: ProcessMetadata,
    death_time: u64,
}

const GRAVEYARD_TTL_SECS: u64 = 60;
const GRAVEYARD_CLEANUP_INTERVAL_SECS: u64 = 10;

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

/// Aggregation metadata for summary events
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
    /// First connection - emit full event
    FirstConnection,
    /// Subsequent connection - suppress (aggregated)
    Aggregated,
}

/// Thread-safe cache for network connection aggregation
/// Reduces event volume by aggregating repeated connections to same destination
pub struct ConnectionAggregator {
    cache: RwLock<HashMap<ConnectionKey, ConnectionState>>,
    max_entries: usize,
    interval_buffer_size: usize,
    last_cleanup: AtomicU64,
}

impl ConnectionAggregator {
    /// Create with default limits
    pub fn new() -> Self {
        Self::with_limits(20_000, 50)
    }

    /// Create with custom limits
    pub fn with_limits(max_entries: usize, interval_buffer_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries,
            interval_buffer_size,
            last_cleanup: AtomicU64::new(0),
        }
    }

    /// Record a connection and determine if it should be emitted
    ///
    /// Returns `FirstConnection` if this is the first time seeing this connection key,
    /// or `Aggregated` if it's a repeat that should be suppressed.
    pub fn record(
        &self,
        process_image: &str,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: Protocol,
        pid: u32,
    ) -> AggregationResult {
        let now = now_secs();
        let key = ConnectionKey {
            process_image: process_image.to_string(),
            dest_ip,
            dest_port,
            protocol,
        };

        let mut cache = self.cache.write().unwrap();

        if let Some(state) = cache.get_mut(&key) {
            state.update(now, pid);
            return AggregationResult::Aggregated;
        }

        // First connection - insert and emit
        cache.insert(
            key,
            ConnectionState::new(now, pid, self.interval_buffer_size),
        );

        // Trim if over capacity
        if cache.len() > self.max_entries {
            self.trim_cache(&mut cache);
        }

        AggregationResult::FirstConnection
    }

    /// Get aggregation metadata for a connection (for summary events)
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

#[cfg(test)]
mod tests {
    use super::{AggregationResult, ConnectionAggregator, DnsCache, Protocol, SidCache};
    use std::net::IpAddr;

    #[test]
    fn sid_cache_prewarm_resolves() {
        let cache = SidCache::new();
        assert_eq!(
            cache.resolve("S-1-5-18"),
            Some("NT AUTHORITY\\SYSTEM".to_string())
        );
        assert_eq!(
            cache.resolve("S-1-5-19"),
            Some("NT AUTHORITY\\LOCAL SERVICE".to_string())
        );
        assert_eq!(
            cache.resolve("S-1-5-20"),
            Some("NT AUTHORITY\\NETWORK SERVICE".to_string())
        );
    }

    #[test]
    fn sid_cache_returns_none_for_empty() {
        let cache = SidCache::new();
        assert_eq!(cache.resolve(""), None);
    }

    #[test]
    fn sid_cache_returns_cached_entry() {
        let cache = SidCache::new();
        {
            let mut map = cache.cache.write().unwrap();
            map.insert("S-1-5-99".to_string(), "TEST\\User".to_string());
        }
        assert_eq!(cache.resolve("S-1-5-99"), Some("TEST\\User".to_string()));
    }

    #[test]
    fn dns_cache_resolves_recent_entry() {
        let cache = DnsCache::with_limits(10, 60);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.update(ip, "example.com".to_string());
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn dns_cache_expires_on_hit() {
        let cache = DnsCache::with_limits(10, 0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.update(ip, "example.com".to_string());
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn dns_cache_trims_to_limit() {
        let cache = DnsCache::with_limits(2, 60);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        let ip3: IpAddr = "9.9.9.9".parse().unwrap();

        cache.update(ip1, "one.example".to_string());
        cache.update(ip2, "two.example".to_string());
        cache.update(ip3, "three.example".to_string());

        assert!(cache.count() <= 2);
    }

    #[test]
    fn connection_aggregator_first_connection_emits() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = aggregator.record(
            "C:\\Windows\\System32\\svchost.exe",
            ip,
            443,
            Protocol::Tcp,
            1234,
        );
        assert_eq!(result, AggregationResult::FirstConnection);
        assert_eq!(aggregator.count(), 1);
    }

    #[test]
    fn connection_aggregator_repeat_connection_aggregates() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result1 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result2 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result3 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);

        assert_eq!(result1, AggregationResult::FirstConnection);
        assert_eq!(result2, AggregationResult::Aggregated);
        assert_eq!(result3, AggregationResult::Aggregated);
        assert_eq!(aggregator.count(), 1);
    }

    #[test]
    fn connection_aggregator_different_destinations_emit() {
        let aggregator = ConnectionAggregator::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let result1 = aggregator.record("C:\\app.exe", ip1, 443, Protocol::Tcp, 1234);
        let result2 = aggregator.record("C:\\app.exe", ip2, 443, Protocol::Tcp, 1234);

        assert_eq!(result1, AggregationResult::FirstConnection);
        assert_eq!(result2, AggregationResult::FirstConnection);
        assert_eq!(aggregator.count(), 2);
    }

    #[test]
    fn connection_aggregator_different_ports_emit() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result1 = aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        let result2 = aggregator.record("C:\\app.exe", ip, 80, Protocol::Tcp, 1234);

        assert_eq!(result1, AggregationResult::FirstConnection);
        assert_eq!(result2, AggregationResult::FirstConnection);
        assert_eq!(aggregator.count(), 2);
    }

    #[test]
    fn connection_aggregator_tracks_multiple_pids() {
        let aggregator = ConnectionAggregator::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1000);
        aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 2000);
        aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 3000);

        let meta = aggregator
            .get_meta("C:\\app.exe", ip, 443, Protocol::Tcp)
            .unwrap();
        assert_eq!(meta.connection_count, 3);
        assert_eq!(meta.unique_pids.len(), 3);
    }

    #[test]
    fn connection_aggregator_trims_to_limit() {
        let aggregator = ConnectionAggregator::with_limits(2, 10);

        for i in 0..5u8 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            aggregator.record("C:\\app.exe", ip, 443, Protocol::Tcp, 1234);
        }

        assert!(aggregator.count() <= 2);
    }
}
