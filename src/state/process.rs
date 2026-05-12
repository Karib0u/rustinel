use std::collections::HashMap;
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
