use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[cfg(windows)]
use crate::utils::lookup_account_sid;
#[cfg(windows)]
use std::collections::HashSet;

/// Thread-safe cache for SID -> Domain\User resolution
pub struct SidCache {
    pub(crate) cache: Arc<RwLock<HashMap<String, String>>>,
    #[cfg(windows)]
    resolver_tx: std::sync::mpsc::SyncSender<String>,
    #[cfg(windows)]
    pending: Arc<RwLock<HashSet<String>>>,
}

impl SidCache {
    /// Create a new SidCache with common well-known SIDs pre-warmed
    pub fn new() -> Self {
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

                        if let Ok(resolved) = lookup_account_sid(&sid) {
                            if let Ok(mut cache) = cache_ref.write() {
                                cache.insert(sid.clone(), resolved);
                            }
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
            Self { cache }
        }
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
