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

use super::file_paths::BoundedIndex;

/// Maximum live entries kept in the index.
///
/// Twice the Kernel-File capacity: a process holds far more open registry keys
/// than open file handles, and every entry is a short key path. Entries are
/// evicted on `CloseKey`, so the cap only binds when keys are held open
/// without closing.
const DEFAULT_CAPACITY: usize = 16384;

/// Joins Kernel-Registry naming events to the pathless events that follow them.
pub(super) struct RegistryPathCache {
    by_key_object: BoundedIndex,
}

impl RegistryPathCache {
    pub(super) fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            by_key_object: BoundedIndex::with_capacity(capacity),
        }
    }

    /// Index the key a naming event describes and return the composed path.
    ///
    /// `RelativeName` is relative to `BaseObject`, which is itself a key this
    /// index may already know. When the base cannot be resolved — it was opened
    /// before the session started — the relative name is kept on its own rather
    /// than dropped: a partial path still matches the `contains`-style rules
    /// that most registry Sigma rules use.
    pub(super) fn learn(
        &mut self,
        base_object: Option<u64>,
        key_object: Option<u64>,
        base_name: &str,
        relative_name: &str,
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
            match base_object.and_then(|base| self.by_key_object.get(base)) {
                Some(base) => join(base, relative_name),
                None => relative_name.to_string(),
            }
        };

        if let Some(object) = key_object {
            self.by_key_object.insert(object, &path);
        }

        Some(path)
    }

    /// Recover the path for an event that carried only a `KeyObject`.
    pub(super) fn resolve(&self, key_object: Option<u64>) -> Option<&str> {
        key_object.and_then(|object| self.by_key_object.get(object))
    }

    /// Drop the entry for a key that has been closed.
    pub(super) fn forget(&mut self, key_object: u64) {
        self.by_key_object.forget(key_object);
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
    use super::RegistryPathCache;

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
            cache.resolve(Some(0x1000)),
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
            cache.resolve(Some(0x20)),
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
        assert_eq!(cache.resolve(Some(0x40)), Some("Software\\Rustinel279"));
    }

    #[test]
    fn a_nameless_event_teaches_nothing() {
        let mut cache = RegistryPathCache::new();
        assert_eq!(cache.learn(None, Some(0x50), "", ""), None);
        assert_eq!(cache.resolve(Some(0x50)), None);
    }

    #[test]
    fn unknown_key_objects_do_not_resolve() {
        let cache = RegistryPathCache::new();
        assert_eq!(cache.resolve(Some(0x99)), None);
        assert_eq!(cache.resolve(None), None);
    }

    #[test]
    fn closing_a_key_releases_its_entry() {
        let mut cache = RegistryPathCache::new();
        cache.learn(None, Some(0x60), "", "\\REGISTRY\\MACHINE\\SOFTWARE");
        assert_eq!(cache.len(), 1);

        cache.forget(0x60);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.resolve(Some(0x60)), None);
    }

    #[test]
    fn stays_bounded_when_keys_are_never_closed() {
        let mut cache = RegistryPathCache::with_capacity(8);
        for object in 0..64u64 {
            cache.learn(None, Some(object), "", "\\REGISTRY\\MACHINE\\SOFTWARE");
        }

        assert!(cache.len() <= 8, "index grew to {}", cache.len());
    }
}
