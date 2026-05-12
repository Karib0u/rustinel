use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

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
