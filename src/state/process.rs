use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vocab::ProcessStartKey;

fn now_secs() -> u64 {
    epoch_secs(SystemTime::now())
}

fn epoch_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Metadata associated with a process
#[derive(Debug, Clone)]
pub struct ProcessMetadata {
    pub provenance: crate::models::Provenance,
    pub image_name: String,
    pub command_line: Option<String>,
    pub user: Option<String>,
    /// Platform-native process execution identity paired with the PID.
    pub creation_time: u64,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// Start key of the observed parent, paired with `parent_pid`.
    pub parent_start_time: Option<NonZeroU64>,
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
/// Keeps one live identity per PID, retaining previous identities briefly for
/// delayed events after PID reuse or repeated exec.
/// Uses RwLock to allow many concurrent readers (network events) and few writers (process start/stop)
pub struct ProcessCache {
    /// Live metadata and its indexes share a lock to keep lifecycle updates atomic.
    cache: RwLock<LiveProcesses>,
    max_entries: usize,
    /// Retired identities retained briefly to avoid parent/child race conditions
    graveyard: RwLock<ProcessGraveyard>,
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
            cache: RwLock::new(LiveProcesses::default()),
            max_entries,
            graveyard: RwLock::new(ProcessGraveyard::default()),
            last_graveyard_cleanup: AtomicU64::new(0),
        }
    }

    /// Add or update a process in the cache with compound key
    /// A different identity for the same PID retires the previous live metadata.
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
        self.add_with_provenance(
            pid,
            creation_time,
            image,
            cmd,
            user,
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
            Default::default(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_with_provenance(
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
        provenance: crate::models::Provenance,
    ) {
        self.insert(
            pid,
            ProcessMetadata {
                provenance,
                image_name: image,
                command_line: cmd,
                user,
                creation_time,
                parent_pid,
                parent_start_time: None,
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
            SystemTime::now(),
        );
    }

    pub(crate) fn insert(&self, pid: u32, metadata: ProcessMetadata, observed_at: SystemTime) {
        let now = epoch_secs(observed_at);
        let creation_time = metadata.creation_time;
        {
            let mut cache = self.cache.write().unwrap();
            let previous = cache
                .by_pid
                .get(&pid)
                .copied()
                .filter(|previous| *previous != creation_time)
                .and_then(|previous| cache.remove(pid, previous));

            cache.entries.insert((pid, creation_time), metadata);
            cache.by_pid.insert(pid, creation_time);
            cache.eviction_order.insert((creation_time, pid));

            while cache.entries.len() > self.max_entries {
                let Some((oldest_creation_time, oldest_pid)) = cache.eviction_order.pop_first()
                else {
                    break;
                };

                cache.remove(oldest_pid, oldest_creation_time);
            }

            let mut graveyard = self.graveyard.write().unwrap();
            graveyard.remove(pid, creation_time);
            if let Some(previous) = previous {
                graveyard.insert(pid, previous, now, self.max_entries);
            }
        }

        self.cleanup_graveyard_if_needed(now);
    }

    /// Register a forked process under its own stable identity while carrying
    /// forward the executable metadata of the exact parent generation.
    pub(crate) fn inherit(
        &self,
        child_pid: u32,
        child_creation_time: u64,
        parent_pid: u32,
        parent_creation_time: u64,
    ) -> bool {
        let Some(parent) = self.get_metadata_by_key(parent_pid, parent_creation_time) else {
            return false;
        };

        let parent_image = parent.image_name.clone();
        let parent_command_line = parent.command_line.clone();
        let mut provenance = parent.provenance.clone();
        provenance.mark_derived("Image");
        if parent.command_line.is_some() {
            provenance.mark_derived("CommandLine");
        }

        self.insert(
            child_pid,
            ProcessMetadata {
                creation_time: child_creation_time,
                parent_pid: Some(parent_pid),
                parent_start_time: NonZeroU64::new(parent_creation_time),
                parent_image: Some(parent_image),
                parent_command_line,
                provenance,
                ..parent
            },
            SystemTime::now(),
        );
        true
    }

    /// Follow exact parent identities with both tables locked in lifecycle order.
    /// The visitor receives zero-based depth (zero is the direct parent).
    pub(crate) fn visit_ancestors(
        &self,
        child: ProcessStartKey,
        parent: ProcessStartKey,
        observed_at: SystemTime,
        mut visit: impl FnMut(usize, &ProcessMetadata),
    ) {
        let now = epoch_secs(observed_at);
        let cache = self.cache.read().unwrap();
        let mut graveyard = None;
        let mut seen = [child; MAX_ANCESTORS + 1];
        let mut key = parent;
        for depth in 0..MAX_ANCESTORS {
            if seen[..=depth].contains(&key) {
                break;
            }
            let identity = (key.pid, key.start_time);
            let ancestor = cache.entries.get(&identity).or_else(|| {
                graveyard
                    .get_or_insert_with(|| self.graveyard.read().unwrap())
                    .entries
                    .get(&identity)
                    .filter(|entry| now.saturating_sub(entry.death_time) <= GRAVEYARD_TTL_SECS)
                    .map(|entry| &entry.metadata)
            });
            let Some(ancestor) = ancestor else {
                break;
            };
            visit(depth, ancestor);
            seen[depth + 1] = key;
            let (Some(pid), Some(start_time)) = (ancestor.parent_pid, ancestor.parent_start_time)
            else {
                break;
            };
            key = ProcessStartKey {
                pid,
                start_time: start_time.get(),
            };
        }
    }

    /// Remove a process from the cache (called on process exit)
    /// Moves the exact process identity into the short-lived graveyard.
    pub fn remove(&self, pid: u32, creation_time: u64) {
        let now = now_secs();
        {
            let mut cache = self.cache.write().unwrap();
            if let Some(meta) = cache.remove(pid, creation_time) {
                self.graveyard
                    .write()
                    .unwrap()
                    .insert(pid, meta, now, self.max_entries);
            }
        }
        self.cleanup_graveyard_if_needed(now);
    }

    /// Get full metadata for a given compound key (PID, CreationTime)
    /// This is the precise lookup method that avoids PID reuse issues
    pub fn get_metadata_by_key(&self, pid: u32, creation_time: u64) -> Option<ProcessMetadata> {
        let cache = self.cache.read().unwrap();
        if let Some(meta) = cache.entries.get(&(pid, creation_time)) {
            return Some(meta.clone());
        }

        let now = now_secs();
        self.cleanup_graveyard_if_needed(now);
        let graveyard = self.graveyard.read().unwrap();
        let entry = graveyard.entries.get(&(pid, creation_time))?;
        if now.saturating_sub(entry.death_time) > GRAVEYARD_TTL_SECS {
            return None;
        }
        Some(entry.metadata.clone())
    }

    /// Attach asynchronously resolved PE metadata to the exact process
    /// generation, including one that exited while resolution was in flight.
    pub(crate) fn enrich_pe_metadata(
        &self,
        pid: u32,
        creation_time: u64,
        metadata: &crate::vocab::PeMetadata,
    ) {
        if let Some(process) = self
            .cache
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get_mut(&(pid, creation_time))
        {
            apply_pe_metadata(process, metadata);
            return;
        }
        if let Some(process) = self
            .graveyard
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get_mut(&(pid, creation_time))
        {
            apply_pe_metadata(&mut process.metadata, metadata);
        }
    }

    /// Get the current count of cached processes
    pub fn count(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.entries.len()
    }

    pub fn retired_count(&self) -> usize {
        self.cleanup_graveyard_if_needed(now_secs());
        self.graveyard.read().unwrap().entries.len()
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
            graveyard.cleanup(now);
        }
    }
}

#[derive(Default)]
struct LiveProcesses {
    entries: HashMap<(u32, u64), ProcessMetadata>,
    by_pid: HashMap<u32, u64>,
    eviction_order: BTreeSet<(u64, u32)>,
}

impl LiveProcesses {
    fn remove(&mut self, pid: u32, creation_time: u64) -> Option<ProcessMetadata> {
        self.eviction_order.remove(&(creation_time, pid));
        if self.by_pid.get(&pid) == Some(&creation_time) {
            self.by_pid.remove(&pid);
        }
        self.entries.remove(&(pid, creation_time))
    }
}

#[derive(Default)]
struct ProcessGraveyard {
    entries: HashMap<(u32, u64), GraveyardEntry>,
    /// The full key breaks ties when a burst retires many identities in one second.
    death_order: BTreeSet<(u64, u32, u64)>,
}

impl ProcessGraveyard {
    fn remove(&mut self, pid: u32, creation_time: u64) {
        if let Some(entry) = self.entries.remove(&(pid, creation_time)) {
            self.death_order
                .remove(&(entry.death_time, pid, creation_time));
        }
    }

    fn insert(&mut self, pid: u32, metadata: ProcessMetadata, death_time: u64, max_entries: usize) {
        let creation_time = metadata.creation_time;
        self.remove(pid, creation_time);
        self.entries.insert(
            (pid, creation_time),
            GraveyardEntry {
                metadata,
                death_time,
            },
        );
        self.death_order.insert((death_time, pid, creation_time));

        while self.entries.len() > max_entries {
            let Some((_, oldest_pid, oldest_creation_time)) = self.death_order.pop_first() else {
                break;
            };
            self.entries.remove(&(oldest_pid, oldest_creation_time));
        }
    }

    fn cleanup(&mut self, now: u64) {
        while let Some(&(death_time, pid, creation_time)) = self.death_order.first() {
            if now.saturating_sub(death_time) <= GRAVEYARD_TTL_SECS {
                break;
            }
            self.death_order.pop_first();
            self.entries.remove(&(pid, creation_time));
        }
    }
}

fn apply_pe_metadata(process: &mut ProcessMetadata, metadata: &crate::vocab::PeMetadata) {
    process.original_filename = metadata.original_filename.clone();
    process.product = metadata.product.clone();
    process.description = metadata.description.clone();
    process.company = metadata.company.clone();
    process.file_version = metadata.file_version.clone();
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
const MAX_ANCESTORS: usize = 8;

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

    fn key(pid: u32, start_time: u64) -> ProcessStartKey {
        ProcessStartKey { pid, start_time }
    }

    fn ancestor_times(
        cache: &ProcessCache,
        child: ProcessStartKey,
        parent: ProcessStartKey,
        observed_at: SystemTime,
    ) -> Vec<u64> {
        let mut times = Vec::new();
        cache.visit_ancestors(child, parent, observed_at, |_, ancestor| {
            times.push(ancestor.creation_time);
        });
        times
    }

    #[test]
    fn ancestry_stops_at_eight_even_with_more_cached_forks() {
        let cache = ProcessCache::new();
        add_process(&cache, 1, 1);
        for pid in 2..=12 {
            assert!(cache.inherit(pid, pid.into(), pid - 1, (pid - 1).into()));
        }
        assert_eq!(
            ancestor_times(&cache, key(13, 13), key(12, 12), SystemTime::now()),
            (5..=12).rev().collect::<Vec<_>>()
        );
    }

    #[test]
    fn ancestry_stops_before_revisiting_an_identity() {
        let cache = ProcessCache::new();
        add_process(&cache, 1, 100);
        assert!(cache.inherit(2, 200, 1, 100));
        assert!(cache.inherit(1, 100, 2, 200)); // Malformed linkage.
        let now = SystemTime::now();
        assert_eq!(
            ancestor_times(&cache, key(3, 300), key(2, 200), now),
            [200, 100]
        );
        assert_eq!(ancestor_times(&cache, key(1, 100), key(2, 200), now), [200]);
        assert!(ancestor_times(&cache, key(2, 200), key(2, 200), now).is_empty());
    }

    #[test]
    fn ancestry_uses_retired_generations_until_ttl_then_stops_at_the_gap() {
        let cache = ProcessCache::new();
        let observed_at = UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        add_process(&cache, 1, 100);
        assert!(cache.inherit(2, 200, 1, 100));
        let mut replacement = cache.get_metadata_by_key(1, 100).unwrap();
        replacement.creation_time = 300;
        cache.insert(1, replacement, observed_at);

        // The same PID at a different generation can also be the descendant.
        let at_ttl = observed_at + std::time::Duration::from_secs(GRAVEYARD_TTL_SECS);
        assert_eq!(
            ancestor_times(&cache, key(1, 300), key(2, 200), at_ttl),
            [200, 100]
        );
        let past_ttl = at_ttl + std::time::Duration::from_secs(1);
        assert_eq!(
            ancestor_times(&cache, key(1, 300), key(2, 200), past_ttl),
            [200]
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
    fn new_identity_retires_previous_pid_metadata() {
        let cache = ProcessCache::with_max_entries(1);

        add_process(&cache, 10, 100);
        add_process(&cache, 10, 200);

        assert_eq!(cache.count(), 1);
        assert_eq!(cache.retired_count(), 1);
        assert!(cache.get_metadata_by_key(10, 100).is_some());
        assert!(cache.get_metadata_by_key(10, 200).is_some());
    }

    #[test]
    fn updating_the_same_identity_does_not_retire_it() {
        let cache = ProcessCache::new();
        add_process(&cache, 10, 100);
        add_process(&cache, 10, 100);

        assert_eq!(cache.count(), 1);
        assert_eq!(cache.retired_count(), 0);
        cache.remove(10, 100);
        add_process(&cache, 10, 100);
        assert_eq!(cache.count(), 1);
        assert_eq!(cache.retired_count(), 0);
        assert!(cache.graveyard.read().unwrap().death_order.is_empty());
    }

    #[test]
    fn delayed_exit_does_not_remove_the_current_identity() {
        let cache = ProcessCache::new();
        add_process(&cache, 10, 100);
        add_process(&cache, 10, 200);
        cache.remove(10, 100);

        assert_eq!(cache.count(), 1);
        assert!(cache.get_metadata_by_key(10, 200).is_some());
        cache.remove(10, 200);
        assert_eq!(cache.count(), 0);
        assert_eq!(cache.retired_count(), 2);
    }

    #[test]
    fn zero_entry_limit_keeps_cache_empty() {
        let cache = ProcessCache::with_max_entries(0);

        add_process(&cache, 10, 100);

        assert_eq!(cache.count(), 0);
        assert!(cache.get_metadata_by_key(10, 100).is_none());
        cache.remove(10, 100);
        assert_eq!(cache.retired_count(), 0);
        let cache = cache.cache.read().unwrap();
        assert!(cache.by_pid.is_empty());
        assert!(cache.eviction_order.is_empty());
    }

    #[test]
    fn process_churn_keeps_retired_metadata_bounded() {
        let cache = ProcessCache::with_max_entries(2);
        for pid in 0..20 {
            add_process(&cache, pid, u64::from(pid));
            cache.remove(pid, u64::from(pid));
            assert!(cache.retired_count() <= 2);
            let graveyard = cache.graveyard.read().unwrap();
            assert_eq!(graveyard.death_order.len(), graveyard.entries.len());
        }
        assert_eq!(cache.count(), 0);
        assert!(cache.get_metadata_by_key(19, 19).is_some());
        let cache = cache.cache.read().unwrap();
        assert!(cache.by_pid.is_empty());
        assert!(cache.eviction_order.is_empty());
    }

    #[test]
    fn graveyard_evicts_by_death_time_and_cleans_up_at_the_ttl_boundary() {
        let cache = ProcessCache::new();
        add_process(&cache, 10, 100);
        let metadata = cache.get_metadata_by_key(10, 100).unwrap();
        let mut graveyard = ProcessGraveyard::default();

        // Death order differs from PID order and insertion order.
        graveyard.insert(30, metadata.clone(), 10, 2);
        graveyard.insert(10, metadata.clone(), 20, 2);
        graveyard.insert(20, metadata, 15, 2);
        assert!(!graveyard.entries.contains_key(&(30, 100)));
        assert_eq!(graveyard.death_order.len(), 2);

        graveyard.cleanup(15 + GRAVEYARD_TTL_SECS);
        assert_eq!(graveyard.entries.len(), 2);
        graveyard.cleanup(16 + GRAVEYARD_TTL_SECS);
        assert!(!graveyard.entries.contains_key(&(20, 100)));
        assert!(graveyard.entries.contains_key(&(10, 100)));
        assert_eq!(graveyard.death_order.len(), 1);
        graveyard.cleanup(21 + GRAVEYARD_TTL_SECS);
        assert!(graveyard.entries.is_empty());
        assert!(graveyard.death_order.is_empty());
    }

    #[test]
    fn graveyard_replacement_and_equal_death_times_keep_the_index_bounded() {
        let cache = ProcessCache::new();
        add_process(&cache, 10, 100);
        let metadata = cache.get_metadata_by_key(10, 100).unwrap();
        let mut graveyard = ProcessGraveyard::default();

        graveyard.insert(10, metadata.clone(), 10, 2);
        graveyard.insert(10, metadata.clone(), 20, 2);
        assert_eq!(graveyard.entries.len(), 1);
        assert_eq!(graveyard.death_order.len(), 1);
        assert!(!graveyard.death_order.contains(&(10, 10, 100)));

        for pid in 11..30 {
            graveyard.insert(pid, metadata.clone(), 20, 2);
            assert_eq!(graveyard.entries.len(), 2);
            assert_eq!(graveyard.death_order.len(), 2);
        }
        graveyard.remove(29, 100);
        assert_eq!(graveyard.entries.len(), 1);
        assert_eq!(graveyard.death_order.len(), 1);
        graveyard.insert(30, metadata, 20, 0);
        assert!(graveyard.entries.is_empty());
        assert!(graveyard.death_order.is_empty());
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

    #[test]
    fn fork_inherits_only_from_the_exact_parent_identity() {
        let cache = ProcessCache::new();
        cache.add(
            10,
            100,
            "/usr/bin/server".into(),
            Some("server --prefork".into()),
            Some("service".into()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("/srv".into()),
            None,
        );

        assert!(!cache.inherit(20, 200, 10, 99));
        assert!(cache.get_metadata_by_key(20, 200).is_none());
        assert!(cache.inherit(20, 200, 10, 100));

        let child = cache.get_metadata_by_key(20, 200).unwrap();
        assert_eq!(child.image_name, "/usr/bin/server");
        assert_eq!(child.command_line.as_deref(), Some("server --prefork"));
        assert_eq!(child.parent_pid, Some(10));
        assert_eq!(child.parent_image.as_deref(), Some("/usr/bin/server"));
        assert_eq!(child.current_directory.as_deref(), Some("/srv"));
        assert!(child
            .provenance
            .entries()
            .iter()
            .any(|entry| entry.field == "Image"));
    }
}
