use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[cfg(windows)]
use crate::utils::lookup_account_sid;
#[cfg(windows)]
use std::collections::HashSet;

/// Thread-safe cache for SID -> Domain\User resolution
pub struct SidCache {
    pub(crate) cache: Arc<RwLock<HashMap<String, String>>>,
    #[cfg(unix)]
    unix_cache: std::sync::Mutex<HashMap<u32, Option<String>>>,
    #[cfg(unix)]
    max_entries: usize,
    #[cfg(windows)]
    resolver_tx: std::sync::mpsc::SyncSender<String>,
    #[cfg(windows)]
    pending: Arc<RwLock<HashSet<String>>>,
}

impl SidCache {
    /// Create a new SidCache with common well-known SIDs pre-warmed
    pub fn new() -> Self {
        Self::with_max_entries(4096)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        let max_entries = max_entries.max(3);
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

                        // Negative results are cached as the raw SID too. A
                        // missing domain must not schedule a lookup per event.
                        let resolved = lookup_account_sid(&sid).unwrap_or_else(|_| sid.clone());
                        if let Ok(mut cache) = cache_ref.write() {
                            if cache.len() >= max_entries {
                                if let Some(victim) = cache
                                    .keys()
                                    .find(|key| {
                                        !matches!(
                                            key.as_str(),
                                            "S-1-5-18" | "S-1-5-19" | "S-1-5-20"
                                        )
                                    })
                                    .cloned()
                                {
                                    cache.remove(&victim);
                                }
                            }
                            cache.insert(sid.clone(), resolved);
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
            Self {
                cache,
                unix_cache: std::sync::Mutex::new(HashMap::new()),
                max_entries,
            }
        }
    }

    pub fn count(&self) -> usize {
        let count = self.cache.read().unwrap().len();
        #[cfg(unix)]
        let count = count + self.unix_cache.lock().unwrap().len();
        count
    }

    /// Cache successful and failed UID lookups, so an unknown UID does not
    /// cause an NSS lookup for every event. Called downstream of collectors.
    #[cfg(unix)]
    pub fn resolve_uid(&self, uid: u32) -> Option<String> {
        self.resolve_uid_with(uid, crate::utils::lookup_username_by_uid)
    }

    #[cfg(unix)]
    fn resolve_uid_with(
        &self,
        uid: u32,
        resolve: impl FnOnce(u32) -> Option<String>,
    ) -> Option<String> {
        let mut cache = self.unix_cache.lock().unwrap();
        if let Some(value) = cache.get(&uid) {
            return value.clone();
        }
        let value = resolve(uid);
        let capacity = self.max_entries.saturating_sub(3);
        if capacity != 0 {
            if cache.len() >= capacity {
                if let Some(key) = cache.keys().next().copied() {
                    cache.remove(&key);
                }
            }
            cache.insert(uid, value.clone());
        }
        value
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn successful_and_failed_user_lookups_are_cached_and_bounded() {
        let cache = SidCache::with_max_entries(5);
        assert_eq!(
            cache
                .resolve_uid_with(7, |_| Some("alice".into()))
                .as_deref(),
            Some("alice")
        );
        assert_eq!(
            cache
                .resolve_uid_with(7, |_| panic!("duplicate NSS lookup"))
                .as_deref(),
            Some("alice")
        );
        assert_eq!(cache.resolve_uid_with(8, |_| None), None);
        assert_eq!(
            cache.resolve_uid_with(8, |_| panic!("duplicate failed NSS lookup")),
            None
        );
        cache.resolve_uid_with(9, |_| Some("bob".into()));
        assert_eq!(cache.count(), 5);
    }
}
