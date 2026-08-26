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
pub(super) const DEFAULT_CAPACITY: usize = 8192;

/// A bounded `u64 -> path` index with FIFO eviction.
///
/// FIFO rather than LRU: the natural lifetime here is the handle's, eviction
/// on `Close` is the common path, and the cap exists only to stop a leaking
/// process from growing this without limit. Tracking recency would cost a
/// touch on every event on the hot path to improve a case that should not
/// happen in the first place.
/// A live index entry, tagged with the queue slot that owns it.
struct Entry {
    path: String,
    /// Which `order` slot may evict this entry. Kernel pointers are recycled,
    /// so a key can be inserted, forgotten, and inserted again; without this
    /// tag the slot left behind by the first insert would evict the second.
    seq: u64,
}

pub(super) struct BoundedIndex {
    entries: HashMap<u64, Entry>,
    /// `(key, seq)` in insertion order, used to pick the eviction victim. A
    /// slot whose key is gone, or whose `seq` no longer matches the live entry,
    /// is stale and is discarded rather than acted on.
    order: VecDeque<(u64, u64)>,
    capacity: usize,
    next_seq: u64,
}

impl BoundedIndex {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            next_seq: 0,
        }
    }

    pub(super) fn insert(&mut self, key: u64, path: &str) {
        if let Some(entry) = self.entries.get_mut(&key) {
            // Re-inserting a live key updates the path but keeps its queue
            // slot; pushing again would let one busy handle fill `order` with
            // duplicates of itself.
            entry.path.clear();
            entry.path.push_str(path);
        } else {
            let seq = self.next_seq;
            // Unreachable in practice at u64 width, but this runs in an ETW
            // callback where a debug overflow panic would take the sensor down.
            self.next_seq = self.next_seq.wrapping_add(1);
            self.entries.insert(
                key,
                Entry {
                    path: path.to_string(),
                    seq,
                },
            );
            self.order.push_back((key, seq));
        }

        while self.entries.len() > self.capacity {
            match self.order.pop_front() {
                Some((oldest, seq)) => {
                    // Only evict when this slot still describes the live entry.
                    // A slot orphaned by forget-then-reinsert must not remove
                    // the newer entry that reused the key.
                    if self.entries.get(&oldest).is_some_and(|e| e.seq == seq) {
                        self.entries.remove(&oldest);
                    }
                }
                None => break,
            }
        }

        // `forget` and key reuse both leave stale slots behind. Compact once
        // they could otherwise grow the queue without bound.
        if self.order.len() > self.capacity.saturating_mul(2) {
            let entries = &self.entries;
            self.order
                .retain(|(key, seq)| entries.get(key).is_some_and(|e| e.seq == *seq));
        }
    }

    pub(super) fn get(&self, key: u64) -> Option<&str> {
        self.entries.get(&key).map(|entry| entry.path.as_str())
    }

    pub(super) fn forget(&mut self, key: u64) {
        self.entries.remove(&key);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
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
    fn reused_key_survives_eviction_of_its_own_stale_slot() {
        // The kernel recycles FILE_OBJECT addresses, so this is the ordinary
        // handle lifecycle: Create names a handle, Close releases it, and a
        // later Create names the same pointer value again. The slot the first
        // insert left in the ordering queue must not evict the second entry.
        // Other handles must be indexed between the forget and the reinsert.
        // That puts the orphaned slot ahead of theirs in the queue, so acting
        // on it evicts the reused key while genuinely older entries survive.
        let mut index = BoundedIndex::with_capacity(4);

        index.insert(0xAAAA, "/old/path.txt");
        index.forget(0xAAAA);

        index.insert(0xB, "/b.txt");
        index.insert(0xC, "/c.txt");
        index.insert(0xD, "/d.txt");

        index.insert(0xAAAA, "/new/path.txt");

        // One more entry puts the index over capacity and runs a single
        // eviction. The victim should be 0xB, the oldest live entry.
        index.insert(0xE, "/e.txt");

        assert_eq!(
            index.get(0xAAAA),
            Some("/new/path.txt"),
            "a reinserted key must not be evicted by the slot its previous \
             incarnation left behind"
        );
        assert_eq!(index.get(0xB), None, "the oldest live entry is the victim");
    }

    #[test]
    fn ordering_queue_stays_bounded_when_one_key_is_reused() {
        // Compaction only drops slots whose key is absent, so before the seq
        // tag a hot recycled handle grew `order` without limit even though the
        // index held a single live entry.
        let capacity = 16;
        let mut index = BoundedIndex::with_capacity(capacity);

        for _ in 0..10_000 {
            index.insert(0xBBBB, "/hot.txt");
            index.forget(0xBBBB);
        }
        index.insert(0xBBBB, "/hot.txt");

        assert_eq!(index.len(), 1);
        assert!(
            index.order.len() <= capacity * 2 + 1,
            "ordering queue grew to {} slots for a single live key",
            index.order.len()
        );
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
