//! FileObject/FileKey to path resolution for Microsoft-Windows-Kernel-File.
//!
//! The Kernel-File events that carry real write semantics identify their target
//! only by kernel pointer. Measured on Windows 11 against the provider's own
//! manifest, event ID 16 (`Write`) and event ID 17 (`SetInformation`) carry
//! `FileObject` and `FileKey` and no name at all.
//!
//! The provider emits the names on separate events, expecting the consumer to
//! join the two:
//!
//! | event | identifiers | name |
//! | --- | --- | --- |
//! | 12 `Create` | `FileObject` | `FileName` |
//! | 10 `NameCreate` | `FileKey` | `FileName` |
//! | 26 `DeletePath` / 27 `RenamePath` | both | `FilePath` |
//! | 14 `Close` | both | — |
//! | 16 `Write` / 17 `SetInformation` | both | — |
//!
//! Note that `Create` carries no `FileKey` and `NameCreate` carries no
//! `FileObject`, which is why two indexes are needed rather than one: neither
//! identifier is present on every naming event.

use std::collections::{HashMap, VecDeque};

/// Maximum live entries kept per index.
///
/// Entries are evicted when the handle closes, so the steady state tracks the
/// number of open handles on the machine rather than total file activity. The
/// cap only binds when processes hold handles without closing them; at this
/// size the worst case is roughly 8192 paths per index, a few megabytes.
const DEFAULT_CAPACITY: usize = 8192;

/// A bounded `u64 -> path` index with FIFO eviction.
///
/// FIFO rather than LRU: the natural lifetime here is the handle's, eviction
/// on `Close` is the common path, and the cap exists only to stop a leaking
/// process from growing this without limit. Tracking recency would cost a
/// touch on every event on the hot path to improve a case that should not
/// happen in the first place.
struct BoundedIndex {
    entries: HashMap<u64, String>,
    /// Insertion order, used to pick the eviction victim. May contain keys
    /// already removed by `forget`; those are skipped when popped.
    order: VecDeque<u64>,
    capacity: usize,
}

impl BoundedIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn insert(&mut self, key: u64, path: &str) {
        // Re-inserting a live key updates the path in place; pushing the key
        // again would let one busy handle fill `order` with duplicates.
        if self.entries.insert(key, path.to_string()).is_none() {
            self.order.push_back(key);
        }

        while self.entries.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.entries.remove(&oldest);
                }
                None => break,
            }
        }

        // `forget` leaves tombstones behind. Compact once they could otherwise
        // grow the queue without bound.
        if self.order.len() > self.capacity.saturating_mul(2) {
            let entries = &self.entries;
            self.order.retain(|key| entries.contains_key(key));
        }
    }

    fn get(&self, key: u64) -> Option<&str> {
        self.entries.get(&key).map(String::as_str)
    }

    fn forget(&mut self, key: u64) {
        self.entries.remove(&key);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Joins Kernel-File naming events to the pathless events that follow them.
pub(super) struct FilePathCache {
    by_object: BoundedIndex,
    by_key: BoundedIndex,
}

impl FilePathCache {
    pub(super) fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            by_object: BoundedIndex::with_capacity(capacity),
            by_key: BoundedIndex::with_capacity(capacity),
        }
    }

    /// Record `path` against whichever identifiers this naming event carried.
    pub(super) fn learn(&mut self, file_object: Option<u64>, file_key: Option<u64>, path: &str) {
        if path.is_empty() {
            return;
        }
        if let Some(object) = file_object {
            self.by_object.insert(object, path);
        }
        if let Some(key) = file_key {
            self.by_key.insert(key, path);
        }
    }

    /// Recover the path for an event that carried only identifiers.
    ///
    /// `FileObject` is tried first: it is per-handle, so it cannot outlive the
    /// handle the event belongs to. `FileKey` is per-file and shared between
    /// handles, which makes it the better fallback but the weaker first guess.
    pub(super) fn resolve(&self, file_object: Option<u64>, file_key: Option<u64>) -> Option<&str> {
        file_object
            .and_then(|object| self.by_object.get(object))
            .or_else(|| file_key.and_then(|key| self.by_key.get(key)))
    }

    /// Drop the entry for a handle that has been closed.
    pub(super) fn forget_object(&mut self, file_object: u64) {
        self.by_object.forget(file_object);
    }

    /// Drop the entry for a name that has left the kernel's name cache.
    pub(super) fn forget_key(&mut self, file_key: u64) {
        self.by_key.forget(file_key);
    }

    /// Total live entries across both indexes.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.by_object.len() + self.by_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedIndex, FilePathCache, DEFAULT_CAPACITY};

    #[test]
    fn resolves_a_write_from_the_create_that_named_the_handle() {
        let mut cache = FilePathCache::new();
        // Event 12 Create: FileObject + FileName, no FileKey.
        cache.learn(Some(0xAAAA), None, r"\Device\HarddiskVolume3\tmp\a.txt");
        // Event 16 Write: both identifiers, no name.
        assert_eq!(
            cache.resolve(Some(0xAAAA), Some(0xBBBB)),
            Some(r"\Device\HarddiskVolume3\tmp\a.txt")
        );
    }

    #[test]
    fn falls_back_to_the_file_key_when_the_handle_was_never_named() {
        let mut cache = FilePathCache::new();
        // Event 10 NameCreate: FileKey + FileName, no FileObject.
        cache.learn(None, Some(0xBBBB), r"\Device\HarddiskVolume3\tmp\b.txt");
        assert_eq!(
            cache.resolve(Some(0xAAAA), Some(0xBBBB)),
            Some(r"\Device\HarddiskVolume3\tmp\b.txt")
        );
    }

    #[test]
    fn unknown_identifiers_do_not_resolve() {
        let cache = FilePathCache::new();
        assert_eq!(cache.resolve(Some(1), Some(2)), None);
        assert_eq!(cache.resolve(None, None), None);
    }

    #[test]
    fn closing_a_handle_releases_its_entry() {
        let mut cache = FilePathCache::new();
        cache.learn(
            Some(0xAAAA),
            Some(0xBBBB),
            r"\Device\HarddiskVolume3\tmp\c.txt",
        );
        assert_eq!(cache.len(), 2);

        cache.forget_object(0xAAAA);
        // The per-file key survives the handle; only the handle entry is gone.
        assert_eq!(cache.resolve(Some(0xAAAA), None), None);
        assert_eq!(
            cache.resolve(None, Some(0xBBBB)),
            Some(r"\Device\HarddiskVolume3\tmp\c.txt")
        );

        cache.forget_key(0xBBBB);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn empty_paths_are_not_recorded() {
        let mut cache = FilePathCache::new();
        cache.learn(Some(0xAAAA), Some(0xBBBB), "");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn stays_bounded_when_handles_are_never_closed() {
        let capacity = 64;
        let mut cache = FilePathCache::with_capacity(capacity);

        // A process that opens handles forever and closes none.
        for i in 0..capacity as u64 * 100 {
            cache.learn(Some(i), Some(i + 1_000_000), &format!("/tmp/file-{i}"));
        }

        assert_eq!(cache.len(), capacity * 2, "both indexes stay at capacity");
        // The most recent entry survives; the oldest has been evicted.
        let newest = capacity as u64 * 100 - 1;
        assert!(cache.resolve(Some(newest), None).is_some());
        assert!(cache.resolve(Some(0), None).is_none());
    }

    #[test]
    fn repeated_writes_to_one_handle_do_not_grow_the_index() {
        let mut index = BoundedIndex::with_capacity(8);
        for _ in 0..1000 {
            index.insert(42, "/tmp/hot.txt");
        }
        assert_eq!(index.len(), 1);
        assert_eq!(index.order.len(), 1, "no duplicate ordering entries");
    }

    #[test]
    fn eviction_tombstones_do_not_accumulate() {
        let capacity = 16;
        let mut index = BoundedIndex::with_capacity(capacity);

        // Churn: insert then immediately forget, which leaves a tombstone in
        // the ordering queue each time.
        for i in 0..capacity as u64 * 100 {
            index.insert(i, "/tmp/churn.txt");
            index.forget(i);
        }

        assert_eq!(index.len(), 0);
        assert!(
            index.order.len() <= capacity * 2 + 1,
            "ordering queue compacts instead of growing without bound, was {}",
            index.order.len()
        );
    }

    #[test]
    fn default_capacity_is_applied() {
        let cache = FilePathCache::new();
        assert_eq!(cache.by_object.capacity, DEFAULT_CAPACITY);
        assert_eq!(cache.by_key.capacity, DEFAULT_CAPACITY);
    }
}
