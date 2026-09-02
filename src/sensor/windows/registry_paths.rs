//! `KeyObject` to path resolution for Microsoft-Windows-Kernel-Registry.
//!
//! The registry events that carry write semantics identify their target only by
//! kernel pointer. Measured on Windows 11 against the provider's own manifest,
//! `SetValueKey` (5), `DeleteValueKey` (6) and `DeleteKey` (3) all declare a
//! `KeyName` field and all deliver it **empty**; only `KeyObject` is populated.
//!
//! The provider emits the names on separate events, expecting the consumer to
//! join the two — the same design as Kernel-File:
//!
//! | event | identifiers | name |
//! | --- | --- | --- |
//! | 1 `CreateKey` | `BaseObject`, `KeyObject` | `BaseName` + `RelativeName` |
//! | 2 `OpenKey` | `BaseObject`, `KeyObject` | `BaseName` + `RelativeName` |
//! | 3 `DeleteKey` / 5 `SetValueKey` / 6 `DeleteValueKey` | `KeyObject` | — |
//! | 13 `CloseKey` | `KeyObject` | — |
//!
//! `OpenKey` therefore has to be subscribed even though it never produces
//! telemetry of its own: most writes land on keys that were opened rather than
//! created, and without it their path is unrecoverable.
//!
//! Two things break that join, and each gets its own tier here (#341):
//!
//! 1. **A key opened before the session was never named on it.** Explorer, the
//!    service host and svchost hold `Run`, `Winlogon` and IFEO keys open for
//!    the life of the boot, so a boot-start agent saw none of the writes
//!    through them, measured 0 of 10 on the lab host.
//!    [`super::registry_rundown`] seeds a fixed snapshot of those keys from
//!    the kernel handle table once the session is up.
//! 2. **`CloseKey` can be decoded before the write it followed.** Although the
//!    session disables per-processor buffering, measurements still found that
//!    a key opened, written and closed in one burst can arrive out of order.
//!    Evicting on `CloseKey` therefore threw away paths that were still needed.
//!    On the measured workload the grace index answers 152 of 735 resolutions, and
//!    adding it took the resolution rate from 83.6% to 98.7%.
//!
//! So a lookup consults three tiers, live index first: what the session has
//! named, then what was open before it, then what it has seen closed.

use std::collections::HashMap;

use super::file_paths::BoundedIndex;

/// Maximum live entries kept in the index.
///
/// Twice the Kernel-File capacity: a process holds far more open registry keys
/// than open file handles, and every entry is a short key path. Entries are
/// evicted on `CloseKey`, so the cap only binds when keys are held open
/// without closing.
const DEFAULT_CAPACITY: usize = 16384;

/// Number of closed keys kept resolvable after their `CloseKey`.
///
/// A write and the `CloseKey` that follows it can occasionally reach the
/// consumer in the opposite order. Evicting the instant `CloseKey` arrives
/// therefore loses the path of a write that has not been decoded yet, measured
/// as the whole of the residual drop rate once the startup snapshot was in
/// place.
///
/// Keeping the last few thousand closed keys covers that window. A lookup also
/// checks the event timestamps, so a later key that reuses the same
/// `CM_KEY_BODY` address cannot inherit the retired path.
const RECENTLY_CLOSED_CAPACITY: usize = 4096;

/// Maximum time by which a write may precede a close that was decoded first.
///
/// The session flush interval is one second. Two seconds covers a delayed
/// adjacent buffer while refusing old entries that happen to share a recycled
/// kernel pointer.
const CLOSE_REORDER_WINDOW_100NS: i64 = 2 * 10_000_000;

/// A bounded path index plus the event timestamp at which each key closed.
struct RecentlyClosedIndex {
    paths: BoundedIndex,
    closed_at: HashMap<u64, i64>,
}

impl RecentlyClosedIndex {
    fn new() -> Self {
        Self {
            paths: BoundedIndex::with_capacity(RECENTLY_CLOSED_CAPACITY),
            closed_at: HashMap::new(),
        }
    }

    fn insert(&mut self, key_object: u64, path: &str, closed_at: i64) {
        self.paths.insert(key_object, path);
        self.closed_at.insert(key_object, closed_at);

        // `BoundedIndex` evicts paths internally. Compact the parallel
        // timestamp map periodically so it stays bounded too.
        if self.closed_at.len() > RECENTLY_CLOSED_CAPACITY.saturating_mul(2) {
            let paths = &self.paths;
            self.closed_at.retain(|key, _| paths.get(*key).is_some());
        }
    }

    fn get(&self, key_object: u64, event_at: i64) -> Option<&str> {
        let closed_at = *self.closed_at.get(&key_object)?;
        let age = closed_at.checked_sub(event_at)?;
        if !(0..=CLOSE_REORDER_WINDOW_100NS).contains(&age) {
            return None;
        }
        self.paths.get(key_object)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.paths.len()
    }
}

/// Which tier of the index answered a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathSource {
    /// A naming event seen inside this session.
    Session,
    /// The startup handle-table snapshot: a key opened before the session, the
    /// case that used to be a dropped event.
    StartupSnapshot,
    /// A key whose `CloseKey` has already been decoded, but whose write had
    /// not been, the out-of-order case.
    RecentlyClosed,
}

/// A path recovered from the index, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Resolved<'a> {
    pub(super) path: &'a str,
    pub(super) source: PathSource,
}

/// Joins Kernel-Registry naming events to the pathless events that follow them.
pub(super) struct RegistryPathCache {
    by_key_object: BoundedIndex,
    /// Keys already open when the session started, from the handle table.
    ///
    /// Deliberately not the bounded index: these entries have to survive for
    /// the life of the agent: a `Run` key Explorer opened at boot is written
    /// hours later, and the index turns over in seconds under registry load.
    /// It is written once at startup and only ever shrinks, so its size is
    /// bounded by the machine's open key handles (measured: 5,908, ~0.5 MB).
    preexisting: HashMap<u64, String>,
    /// Keys whose `CloseKey` has been decoded, held for the reordering window.
    recently_closed: RecentlyClosedIndex,
}

impl RegistryPathCache {
    pub(super) fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            by_key_object: BoundedIndex::with_capacity(capacity),
            preexisting: HashMap::new(),
            recently_closed: RecentlyClosedIndex::new(),
        }
    }

    /// Install the handle-table snapshot. Called once, after the trace session
    /// is running so that no key falls between the snapshot and the first
    /// `OpenKey` event.
    pub(super) fn seed(&mut self, preexisting: HashMap<u64, String>) {
        self.preexisting = preexisting;
    }

    /// How many pre-existing keys the seed still covers.
    #[cfg(test)]
    fn preexisting_len(&self) -> usize {
        self.preexisting.len()
    }

    /// Index the key a naming event describes and return the composed path.
    ///
    /// `RelativeName` is relative to `BaseObject`, which is itself a key this
    /// index may already know. When the base cannot be resolved — it was opened
    /// before the session started — the relative name is kept on its own rather
    /// than dropped: a partial path still matches the `contains`-style rules
    /// that most registry Sigma rules use.
    pub(super) fn learn_at(
        &mut self,
        base_object: Option<u64>,
        key_object: Option<u64>,
        base_name: &str,
        relative_name: &str,
        event_at: i64,
    ) -> Option<String> {
        if relative_name.is_empty() {
            return None;
        }

        let path = if relative_name.starts_with('\\') {
            // Already an absolute NT path such as
            // `\REGISTRY\MACHINE\SYSTEM\ControlSet001\...`.
            relative_name.to_string()
        } else if !base_name.is_empty() {
            join(base_name, relative_name)
        } else {
            // The base is very often a root handle the process opened before
            // the session, which is exactly what the seed covers, so this goes
            // through the two-tier lookup rather than the index alone.
            match base_object.and_then(|base| self.resolve_at(Some(base), event_at)) {
                Some(base) => join(base.path, relative_name),
                None => relative_name.to_string(),
            }
        };

        // A failed open reports `KeyObject = 0`, 39% of `OpenKey` events on a
        // measured idle desktop. Indexing those would file every one of them
        // under the same null pointer and hand that path to any later event
        // that also carried none.
        match key_object {
            Some(object) if object != 0 => self.by_key_object.insert(object, &path),
            _ => {}
        }

        Some(path)
    }

    #[cfg(test)]
    fn learn(
        &mut self,
        base_object: Option<u64>,
        key_object: Option<u64>,
        base_name: &str,
        relative_name: &str,
    ) -> Option<String> {
        self.learn_at(base_object, key_object, base_name, relative_name, 0)
    }

    /// Recover the path for an event that carried only a `KeyObject`, and say
    /// which tier answered.
    ///
    /// The live index wins over the seed: if the pointer has been recycled for
    /// a new key, the `CreateKey`/`OpenKey` that produced it has already
    /// overwritten the index entry, and the stale snapshot must not shadow it.
    /// The tier is reported because it is the measure of what the handle-table
    /// seed is worth: writes it answers are writes that used to be dropped.
    pub(super) fn resolve_at(
        &self,
        key_object: Option<u64>,
        event_at: i64,
    ) -> Option<Resolved<'_>> {
        let object = key_object?;
        if object == 0 {
            return None;
        }
        if let Some(path) = self.by_key_object.get(object) {
            return Some(Resolved {
                path,
                source: PathSource::Session,
            });
        }
        if let Some(path) = self.preexisting.get(&object) {
            return Some(Resolved {
                path: path.as_str(),
                source: PathSource::StartupSnapshot,
            });
        }
        self.recently_closed
            .get(object, event_at)
            .map(|path| Resolved {
                path,
                source: PathSource::RecentlyClosed,
            })
    }

    #[cfg(test)]
    fn resolve(&self, key_object: Option<u64>) -> Option<Resolved<'_>> {
        self.resolve_at(key_object, 0)
    }

    /// Retire the entry for a key that has been closed.
    ///
    /// Retired rather than deleted: `CloseKey` can be decoded before the write
    /// it followed, so the path is moved into the bounded grace index instead
    /// of being dropped on the spot. It leaves both live tiers either way,
    /// which is what keeps the startup snapshot honest: once the handle is
    /// gone the kernel may hand that address to a different key, and a seed
    /// entry that outlived its handle would name the wrong one.
    pub(super) fn forget_at(&mut self, key_object: u64, event_at: i64) {
        let retired = self
            .by_key_object
            .get(key_object)
            .or_else(|| self.preexisting.get(&key_object).map(String::as_str))
            .map(str::to_string);

        self.by_key_object.forget(key_object);
        self.preexisting.remove(&key_object);

        if let Some(path) = retired {
            self.recently_closed.insert(key_object, &path, event_at);
        }
    }

    #[cfg(test)]
    fn forget(&mut self, key_object: u64) {
        self.forget_at(key_object, 1);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_key_object.len()
    }
}

fn join(base: &str, relative: &str) -> String {
    let mut path = String::with_capacity(base.len() + relative.len() + 1);
    path.push_str(base.trim_end_matches('\\'));
    path.push('\\');
    path.push_str(relative);
    path
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{PathSource, RegistryPathCache};

    /// The path only, for the assertions that do not care which tier answered.
    fn resolved(cache: &RegistryPathCache, key_object: u64) -> Option<String> {
        cache
            .resolve(Some(key_object))
            .map(|resolved| resolved.path.to_string())
    }

    fn snapshot(entries: &[(u64, &str)]) -> HashMap<u64, String> {
        entries
            .iter()
            .map(|(object, path)| (*object, (*path).to_string()))
            .collect()
    }

    #[test]
    fn resolves_a_value_write_from_the_open_that_named_the_key() {
        // The case from #279: SetValueKey carries an empty KeyName, so the
        // path can only come from the OpenKey that preceded it.
        let mut cache = RegistryPathCache::new();
        cache.learn(
            None,
            Some(0x1000),
            "",
            "\\REGISTRY\\USER\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        );

        assert_eq!(
            resolved(&cache, 0x1000).as_deref(),
            Some("\\REGISTRY\\USER\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        );
    }

    #[test]
    fn relative_name_is_composed_onto_the_base_key() {
        let mut cache = RegistryPathCache::new();
        cache.learn(None, Some(0x10), "", "\\REGISTRY\\USER\\S-1-5-21\\Software");
        let path = cache.learn(Some(0x10), Some(0x20), "", "Rustinel\\Run");

        assert_eq!(
            path.as_deref(),
            Some("\\REGISTRY\\USER\\S-1-5-21\\Software\\Rustinel\\Run")
        );
        assert_eq!(
            resolved(&cache, 0x20).as_deref(),
            Some("\\REGISTRY\\USER\\S-1-5-21\\Software\\Rustinel\\Run")
        );
    }

    #[test]
    fn base_name_wins_over_the_index_when_the_event_carries_one() {
        let mut cache = RegistryPathCache::new();
        let path = cache.learn(
            None,
            Some(0x30),
            "\\REGISTRY\\MACHINE\\SOFTWARE",
            "Policies",
        );

        assert_eq!(
            path.as_deref(),
            Some("\\REGISTRY\\MACHINE\\SOFTWARE\\Policies")
        );
    }

    #[test]
    fn an_unresolvable_base_keeps_the_relative_name() {
        // The key was opened before the session started. A partial path still
        // matches the `contains` rules registry Sigma rules are written with,
        // so it beats dropping the event.
        let mut cache = RegistryPathCache::new();
        let path = cache.learn(Some(0xdead), Some(0x40), "", "Software\\Rustinel279");

        assert_eq!(path.as_deref(), Some("Software\\Rustinel279"));
        assert_eq!(
            resolved(&cache, 0x40).as_deref(),
            Some("Software\\Rustinel279")
        );
    }

    #[test]
    fn a_nameless_event_teaches_nothing() {
        let mut cache = RegistryPathCache::new();
        assert_eq!(cache.learn(None, Some(0x50), "", ""), None);
        assert_eq!(resolved(&cache, 0x50), None);
    }

    #[test]
    fn unknown_key_objects_do_not_resolve() {
        let cache = RegistryPathCache::new();
        assert_eq!(resolved(&cache, 0x99), None);
        assert_eq!(cache.resolve(None), None);
    }

    #[test]
    fn closing_a_key_releases_its_live_entry() {
        // The live index is what has to stay bounded by the open-key count;
        // the closed path moves to the much smaller grace index, which
        // `a_write_decoded_after_its_close_still_resolves` covers.
        let mut cache = RegistryPathCache::new();
        cache.learn(None, Some(0x60), "", "\\REGISTRY\\MACHINE\\SOFTWARE");
        assert_eq!(cache.len(), 1);

        cache.forget(0x60);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn stays_bounded_when_keys_are_never_closed() {
        let mut cache = RegistryPathCache::with_capacity(8);
        for object in 0..64u64 {
            cache.learn(None, Some(object), "", "\\REGISTRY\\MACHINE\\SOFTWARE");
        }

        assert!(cache.len() <= 8, "index grew to {}", cache.len());
    }
    #[test]
    fn a_write_through_a_pre_session_handle_resolves_from_the_snapshot() {
        // #341: the key was opened before the trace session, so no naming
        // event for it will ever arrive and the index alone knows nothing.
        let run = "\\REGISTRY\\USER\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let mut cache = RegistryPathCache::new();
        assert_eq!(resolved(&cache, 0xdead_beef), None);

        cache.seed(snapshot(&[(0xdead_beef, run)]));

        let hit = cache.resolve(Some(0xdead_beef)).expect("seeded key");
        assert_eq!(hit.path, run);
        assert_eq!(hit.source, PathSource::StartupSnapshot);
        assert_eq!(cache.preexisting_len(), 1);
    }

    #[test]
    fn a_naming_event_shadows_a_recycled_snapshot_entry() {
        // The kernel may hand a closed key's address to a different key. The
        // naming event for the replacement has to win, or the snapshot would
        // put the old path on the new key's writes.
        let mut cache = RegistryPathCache::new();
        cache.seed(snapshot(&[(
            0x1000,
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Stale",
        )]));
        cache.learn(
            None,
            Some(0x1000),
            "",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Fresh",
        );

        let hit = cache.resolve(Some(0x1000)).expect("relearned key");
        assert_eq!(hit.path, "\\REGISTRY\\MACHINE\\SOFTWARE\\Fresh");
        assert_eq!(hit.source, PathSource::Session);
    }

    #[test]
    fn closing_a_key_releases_its_snapshot_entry_too() {
        let mut cache = RegistryPathCache::new();
        cache.seed(snapshot(&[(0x70, "\\REGISTRY\\MACHINE\\SOFTWARE")]));

        cache.forget(0x70);
        assert_eq!(cache.preexisting_len(), 0);
        // Retired into the grace tier, not deleted; see below.
        assert_eq!(
            cache.resolve(Some(0x70)).map(|hit| hit.source),
            Some(PathSource::RecentlyClosed)
        );
    }

    #[test]
    fn a_write_decoded_after_its_close_still_resolves() {
        // The `CloseKey` for a key that was opened, written and closed in one
        // burst can reach the consumer before the write does.
        let mut cache = RegistryPathCache::new();
        cache.learn(None, Some(0x80), "", "\\REGISTRY\\MACHINE\\SOFTWARE\\Fast");
        cache.forget(0x80);

        let hit = cache.resolve(Some(0x80)).expect("still resolvable");
        assert_eq!(hit.path, "\\REGISTRY\\MACHINE\\SOFTWARE\\Fast");
        assert_eq!(hit.source, PathSource::RecentlyClosed);
    }

    #[test]
    fn a_write_after_the_close_cannot_inherit_a_recycled_pointer() {
        let mut cache = RegistryPathCache::new();
        cache.learn_at(
            None,
            Some(0x81),
            "",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Old",
            10,
        );
        cache.forget_at(0x81, 20);

        assert_eq!(cache.resolve_at(Some(0x81), 21), None);
    }

    #[test]
    fn a_write_outside_the_reorder_window_does_not_use_a_closed_path() {
        let mut cache = RegistryPathCache::new();
        cache.learn_at(
            None,
            Some(0x82),
            "",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Old",
            10,
        );
        cache.forget_at(0x82, super::CLOSE_REORDER_WINDOW_100NS + 11);

        assert_eq!(cache.resolve_at(Some(0x82), 10), None);
    }

    #[test]
    fn the_close_grace_is_bounded_and_yields_to_a_reused_pointer() {
        // The grace period must not become a second cache: a pointer the
        // kernel hands to a new key is named by that key's own event, and
        // that has to win over the retired path.
        let mut cache = RegistryPathCache::new();
        cache.learn(None, Some(0x90), "", "\\REGISTRY\\MACHINE\\SOFTWARE\\Old");
        cache.forget(0x90);
        cache.learn(None, Some(0x90), "", "\\REGISTRY\\MACHINE\\SOFTWARE\\New");

        let hit = cache.resolve(Some(0x90)).expect("relearned key");
        assert_eq!(hit.path, "\\REGISTRY\\MACHINE\\SOFTWARE\\New");
        assert_eq!(hit.source, PathSource::Session);
    }

    #[test]
    fn the_close_grace_does_not_grow_without_bound() {
        let mut cache = RegistryPathCache::new();
        for object in 1..(super::RECENTLY_CLOSED_CAPACITY as u64 * 4) {
            cache.learn(None, Some(object), "", "\\REGISTRY\\MACHINE\\SOFTWARE");
            cache.forget(object);
        }

        assert!(
            cache.recently_closed.len() <= super::RECENTLY_CLOSED_CAPACITY,
            "grace index grew to {}",
            cache.recently_closed.len()
        );
        // The oldest closes are gone; the newest are still covered.
        assert_eq!(resolved(&cache, 1), None);
        assert!(resolved(&cache, super::RECENTLY_CLOSED_CAPACITY as u64 * 4 - 1).is_some());
    }

    #[test]
    fn the_snapshot_survives_the_index_turning_over() {
        // The seed exists because a Run key opened at boot is written hours
        // later, long after the bounded index has cycled through it.
        let mut cache = RegistryPathCache::with_capacity(8);
        cache.seed(snapshot(&[(0x9999, "\\REGISTRY\\MACHINE\\SOFTWARE\\Boot")]));
        for object in 0..64u64 {
            cache.learn(None, Some(object), "", "\\REGISTRY\\MACHINE\\SOFTWARE");
        }

        assert_eq!(
            resolved(&cache, 0x9999).as_deref(),
            Some("\\REGISTRY\\MACHINE\\SOFTWARE\\Boot")
        );
    }

    #[test]
    fn a_pre_session_base_key_completes_a_relative_name() {
        // The second thing the snapshot buys: a process whose HKCU root handle
        // predates the session used to yield a bare relative name.
        let mut cache = RegistryPathCache::new();
        cache.seed(snapshot(&[(0x10, "\\REGISTRY\\USER\\S-1-5-21")]));

        let path = cache.learn(Some(0x10), Some(0x20), "", "Software\\Microsoft");
        assert_eq!(
            path.as_deref(),
            Some("\\REGISTRY\\USER\\S-1-5-21\\Software\\Microsoft")
        );
    }

    #[test]
    fn a_failed_open_is_not_indexed_under_the_null_key_object() {
        // 39% of OpenKey events on a measured idle desktop are failures with
        // `KeyObject = 0`. Indexing them would file every failed open under
        // one pointer and hand that path to anything else carrying none.
        let mut cache = RegistryPathCache::new();
        cache.learn(None, Some(0), "", "\\REGISTRY\\MACHINE\\SOFTWARE\\Missing");

        assert_eq!(cache.len(), 0);
        assert_eq!(resolved(&cache, 0), None);
        assert_eq!(cache.resolve(Some(0)), None);
    }
}
