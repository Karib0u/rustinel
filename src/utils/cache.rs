//! Shared eviction policy for the bounded, timestamp-ordered caches.
//!
//! Rustinel keeps several `HashMap` caches (DNS, file hashes, YARA verdicts,
//! connection state) capped at a maximum entry count, with each entry carrying a
//! second-precision timestamp. Trimming those maps back to exactly the cap makes
//! every subsequent insertion at capacity trim again, and second-precision
//! timestamps mean a burst usually shares a single timestamp, so a
//! "drop everything older than the median" pass can remove nothing at all.
//!
//! [`trim_to_headroom`] instead evicts down to a target *below* the cap, so one
//! trim buys headroom for many insertions, and it breaks timestamp ties instead
//! of stalling on them.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};

/// Fraction of the cap that survives a trim, expressed as a divisor of the
/// number of entries freed: `max / EVICTION_DIVISOR` entries are freed, i.e. the
/// cache is trimmed to 75% of its cap.
const EVICTION_DIVISOR: usize = 4;

/// Number of entries a cache is trimmed down to when it exceeds `max_entries`.
///
/// Always at most `max_entries`, and strictly below it whenever the cap leaves
/// room for that (`max_entries >= EVICTION_DIVISOR`).
pub fn trim_target(max_entries: usize) -> usize {
    max_entries - max_entries / EVICTION_DIVISOR
}

/// Evict the oldest entries of `map` until it holds at most [`trim_target`].
///
/// `timestamp` extracts the entry's age key (larger is newer). Entries older
/// than the cutoff are dropped wholesale; when entries tie on the cutoff
/// timestamp, enough of them are dropped to reach the target, so a trim always
/// frees `max_entries / 4` slots regardless of how many timestamps are equal.
///
/// Runs in O(n) on average (`select_nth_unstable`) rather than O(n log n), and
/// is a no-op while the map is within its cap.
pub fn trim_to_headroom<K, V, S, F>(map: &mut HashMap<K, V, S>, max_entries: usize, timestamp: F)
where
    K: Eq + Hash + Clone,
    S: BuildHasher,
    F: Fn(&V) -> u64,
{
    let len = map.len();
    if len <= max_entries {
        return;
    }

    let target = trim_target(max_entries);
    if target == 0 {
        map.clear();
        return;
    }

    let to_remove = len - target;
    let mut timestamps: Vec<u64> = map.values().map(&timestamp).collect();
    // The `to_remove`-th smallest timestamp is the oldest one that may survive;
    // everything strictly below it must go.
    let cutoff = *timestamps.select_nth_unstable(to_remove).1;
    map.retain(|_, value| timestamp(value) >= cutoff);

    // Whatever is still over target ties with the cutoff. Drop the surplus so a
    // burst of same-second entries cannot defeat the trim.
    if map.len() > target {
        let surplus = map.len() - target;
        let keys: Vec<K> = map
            .iter()
            .filter(|(_, value)| timestamp(value) == cutoff)
            .take(surplus)
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_of(timestamps: &[u64]) -> HashMap<usize, u64> {
        timestamps.iter().copied().enumerate().collect()
    }

    #[test]
    fn trim_target_leaves_a_quarter_of_the_cap_free() {
        assert_eq!(trim_target(100), 75);
        assert_eq!(trim_target(4), 3);
        assert_eq!(trim_target(1), 1);
        assert_eq!(trim_target(0), 0);
    }

    #[test]
    fn trim_is_a_no_op_within_the_cap() {
        let mut map = map_of(&[1, 2, 3]);
        trim_to_headroom(&mut map, 3, |ts| *ts);
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn trim_frees_headroom_when_every_timestamp_is_equal() {
        let mut map = map_of(&[7; 101]);
        trim_to_headroom(&mut map, 100, |ts| *ts);
        assert_eq!(map.len(), 75);
    }

    #[test]
    fn trim_drops_the_oldest_entries_first() {
        let mut map: HashMap<usize, u64> = (0..101).map(|i| (i, i as u64)).collect();
        trim_to_headroom(&mut map, 100, |ts| *ts);
        assert_eq!(map.len(), 75);
        // The 26 oldest went; the 75 newest stayed.
        assert!(map.keys().all(|key| *key >= 26));
    }

    #[test]
    fn trim_breaks_ties_on_the_cutoff_timestamp() {
        // 90 entries share the cutoff second, 11 are strictly newer.
        let mut timestamps = vec![5u64; 90];
        timestamps.extend(std::iter::repeat_n(9u64, 11));
        let mut map = map_of(&timestamps);

        trim_to_headroom(&mut map, 100, |ts| *ts);

        assert_eq!(map.len(), 75);
        // Every strictly newer entry survived; only cutoff-second entries were cut.
        assert_eq!(map.values().filter(|ts| **ts == 9).count(), 11);
    }

    #[test]
    fn one_trim_absorbs_many_subsequent_inserts() {
        let mut map = map_of(&[1; 100]);
        let mut trims = 0usize;

        for key in 100..125 {
            map.insert(key, 1);
            if map.len() > 100 {
                trims += 1;
                trim_to_headroom(&mut map, 100, |ts| *ts);
            }
        }

        // 25 inserts at capacity cost a single trim, not one per insert.
        assert_eq!(trims, 1);
        assert!(map.len() <= 100);
    }

    #[test]
    fn trim_clears_a_zero_capacity_cache() {
        let mut map = map_of(&[1, 2]);
        trim_to_headroom(&mut map, 0, |ts| *ts);
        assert!(map.is_empty());
    }
}
