use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Metadata associated with a process
#[derive(Debug, Clone)]
pub struct ProcessMetadata {
    pub image_name: String,
    pub command_line: Option<String>,
    pub user: Option<String>,
    /// Platform-native process execution identity paired with the PID.
    pub creation_time: u64,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// Parent process image name (enriched at creation time)
    pub parent_image: Option<String>,
    /// Parent process command line (enriched at creation time)
    pub parent_command_line: Option<String>,
    /// PE metadata: Original filename from version info
    pub original_filename: Option<String>,
    /// PE metadata: Product name
    pub product: Option<String>,
    /// PE metadata: File description
    pub description: Option<String>,
    /// PE metadata: Company name
    pub company: Option<String>,
    /// PE metadata: File version
    pub file_version: Option<String>,
    /// Process working directory
    pub current_directory: Option<String>,
    /// Process integrity level
    pub integrity_level: Option<String>,
}

/// Thread-safe cache for process metadata
/// Uses a compound process identity to handle PID reuse and repeated exec.
/// Uses RwLock to allow many concurrent readers (network events) and few writers (process start/stop)
pub struct ProcessCache {
    /// Primary storage: (PID, CreationTime) -> Metadata
    cache: RwLock<HashMap<(u32, u64), ProcessMetadata>>,
    /// Compound keys ordered by creation time for efficient oldest-first eviction
    eviction_order: RwLock<BTreeSet<(u64, u32)>>,
    max_entries: usize,
    /// Recently-dead processes retained briefly to avoid parent/child race conditions
    graveyard: RwLock<HashMap<(u32, u64), GraveyardEntry>>,
    last_graveyard_cleanup: AtomicU64,
}

impl ProcessCache {
    /// Create a new empty ProcessCache
    pub fn new() -> Self {
        Self::with_max_entries(PROCESS_CACHE_MAX_ENTRIES)
    }

    /// Create an empty ProcessCache capped at `max_entries` processes
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            eviction_order: RwLock::new(BTreeSet::new()),
            max_entries,
            graveyard: RwLock::new(HashMap::new()),
            last_graveyard_cleanup: AtomicU64::new(0),
        }
    }

    /// Add or update a process in the cache with compound key
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `creation_time` - Platform-native execution identity from the sensor
    /// * `image` - Full path to executable
    /// * `cmd` - Command line arguments
    /// * `user` - User account name
    /// * `parent_pid` - Parent process ID
    /// * `parent_image` - Parent process image (pre-enriched)
    /// * `parent_command_line` - Parent process command line (pre-enriched)
    /// * `original_filename` - PE metadata: Original filename
    /// * `product` - PE metadata: Product name
    /// * `description` - PE metadata: File description
    /// * `company` - PE metadata: Company name
    /// * `file_version` - PE metadata: File version
    /// * `current_directory` - Process working directory
    /// * `integrity_level` - Process integrity level
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
        company: Option<String>,
        file_version: Option<String>,
        current_directory: Option<String>,
        integrity_level: Option<String>,
    ) {
        {
            let mut cache = self.cache.write().unwrap();
            let mut eviction_order = self.eviction_order.write().unwrap();

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
                    company,
                    file_version,
                    current_directory,
                    integrity_level,
                },
            );
            eviction_order.insert((creation_time, pid));

            while cache.len() > self.max_entries {
                let Some((oldest_creation_time, oldest_pid)) = eviction_order.pop_first() else {
                    break;
                };

                cache.remove(&(oldest_pid, oldest_creation_time));
            }
        }

        if let Ok(mut graveyard) = self.graveyard.write() {
            graveyard.remove(&(pid, creation_time));
        }

        self.cleanup_graveyard_if_needed(now_secs());
    }

    /// Remove a process from the cache (called on process exit)
    /// Moves the exact process identity into the short-lived graveyard.
    pub fn remove(&self, pid: u32, creation_time: u64) {
        let removed_meta = {
            let mut cache = self.cache.write().unwrap();
            let mut eviction_order = self.eviction_order.write().unwrap();

            let meta = cache.remove(&(pid, creation_time));
            eviction_order.remove(&(creation_time, pid));
            meta
        };

        if let Some(meta) = removed_meta {
            let now = now_secs();
            if let Ok(mut graveyard) = self.graveyard.write() {
                graveyard.insert(
                    (pid, creation_time),
                    GraveyardEntry {
                        metadata: meta,
                        death_time: now,
                    },
                );
            }
            self.cleanup_graveyard_if_needed(now);
        }
    }

    /// Get full metadata for a given compound key (PID, CreationTime)
    /// This is the precise lookup method that avoids PID reuse issues
    pub fn get_metadata_by_key(&self, pid: u32, creation_time: u64) -> Option<ProcessMetadata> {
        let cache = self.cache.read().unwrap();
        if let Some(meta) = cache.get(&(pid, creation_time)) {
            return Some(meta.clone());
        }

        let now = now_secs();
        self.cleanup_graveyard_if_needed(now);
        let graveyard = self.graveyard.read().unwrap();
        let entry = graveyard.get(&(pid, creation_time))?;
        if now.saturating_sub(entry.death_time) > GRAVEYARD_TTL_SECS {
            return None;
        }
        Some(entry.metadata.clone())
    }

    /// Get the current count of cached processes
    pub fn count(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
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
const PROCESS_CACHE_MAX_ENTRIES: usize = 65_536;

#[cfg(test)]
mod tests {
    use super::*;

    fn add_process(cache: &ProcessCache, pid: u32, creation_time: u64) {
        cache.add(
            pid,
            creation_time,
            format!("process-{pid}"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
    }

    #[test]
    fn missed_exit_events_do_not_grow_cache_past_limit() {
        let cache = ProcessCache::with_max_entries(2);

        add_process(&cache, 10, 100);
        add_process(&cache, 20, 200);
        add_process(&cache, 30, 300);

        assert_eq!(cache.count(), 2);
        assert!(cache.get_metadata_by_key(10, 100).is_none());
        assert!(cache.get_metadata_by_key(20, 200).is_some());
        assert!(cache.get_metadata_by_key(30, 300).is_some());
    }

    #[test]
    fn eviction_keeps_newest_identity_for_reused_pid() {
        let cache = ProcessCache::with_max_entries(1);

        add_process(&cache, 10, 100);
        add_process(&cache, 10, 200);

        assert!(cache.get_metadata_by_key(10, 100).is_none());
        assert!(cache.get_metadata_by_key(10, 200).is_some());
    }

    #[test]
    fn zero_entry_limit_keeps_cache_empty() {
        let cache = ProcessCache::with_max_entries(0);

        add_process(&cache, 10, 100);

        assert_eq!(cache.count(), 0);
        assert!(cache.get_metadata_by_key(10, 100).is_none());
    }

    #[test]
    fn graveyard_retains_each_reused_pid_identity() {
        let cache = ProcessCache::new();

        add_process(&cache, 10, 100);
        cache.remove(10, 100);
        add_process(&cache, 10, 200);
        cache.remove(10, 200);

        assert_eq!(
            cache
                .get_metadata_by_key(10, 100)
                .map(|meta| meta.creation_time),
            Some(100)
        );
        assert_eq!(
            cache
                .get_metadata_by_key(10, 200)
                .map(|meta| meta.creation_time),
            Some(200)
        );
    }
}
