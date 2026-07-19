use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::utils::file_identity::{self, FileIdentity};

const HASH_CACHE_MAX_ENTRIES: usize = 10_000;
const HASH_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

/// Normalize a file path for allowlist prefix matching.
/// Windows: convert to backslashes and lowercase (case-insensitive FS).
/// Linux:   keep as-is (case-sensitive FS, native forward-slash paths).
pub(crate) fn normalize_allowlist_path(path: &str) -> String {
    #[cfg(windows)]
    {
        path.trim().replace('/', "\\").to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        path.trim().to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashRequirements {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
}

#[derive(Debug, Clone)]
pub struct ComputedHashes {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct HashCacheEntry {
    hashes: ComputedHashes,
    timestamp: u64,
}

pub struct HashCache {
    entries: HashMap<FileIdentity, HashCacheEntry>,
    max_entries: usize,
    ttl_secs: u64,
}

impl Default for HashCache {
    fn default() -> Self {
        Self::new()
    }
}

impl HashCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: HASH_CACHE_MAX_ENTRIES,
            ttl_secs: HASH_CACHE_TTL_SECS,
        }
    }

    pub fn get_or_compute(
        &mut self,
        path: &Path,
        requirements: HashRequirements,
        buf: &mut [u8],
    ) -> anyhow::Result<ComputedHashes> {
        self.get_or_compute_with(path, requirements, buf, compute_hashes)
    }

    fn get_or_compute_with<F>(
        &mut self,
        path: &Path,
        requirements: HashRequirements,
        buf: &mut [u8],
        compute: F,
    ) -> anyhow::Result<ComputedHashes>
    where
        F: FnOnce(&mut File, HashRequirements, &mut [u8]) -> anyhow::Result<ComputedHashes>,
    {
        let mut file = File::open(path)?;
        let identity = file_identity::from_file(&file);
        if let Some(identity) = &identity {
            if let Some(entry) = self.entries.get(identity) {
                if !self.is_expired(entry) && file_identity::unchanged(&file, path, identity) {
                    return Ok(entry.hashes.clone());
                }
            }
        }

        let hashes = compute(&mut file, requirements, buf)?;
        if let Some(identity) = identity {
            if file_identity::unchanged(&file, path, &identity) {
                let now = now_secs();
                self.entries.insert(
                    identity,
                    HashCacheEntry {
                        hashes: hashes.clone(),
                        timestamp: now,
                    },
                );
                if self.entries.len() > self.max_entries {
                    self.trim();
                }
            }
        }

        Ok(hashes)
    }

    fn is_expired(&self, entry: &HashCacheEntry) -> bool {
        now_secs().saturating_sub(entry.timestamp) > self.ttl_secs
    }

    fn trim(&mut self) {
        if self.entries.len() <= self.max_entries {
            return;
        }

        let mut timestamps: Vec<u64> = self.entries.values().map(|entry| entry.timestamp).collect();
        timestamps.sort_unstable();
        let cutoff = timestamps[self.entries.len() / 2];
        self.entries.retain(|_, entry| entry.timestamp >= cutoff);

        if self.entries.len() > self.max_entries {
            let extra = self.entries.len() - self.max_entries;
            let keys: Vec<FileIdentity> = self.entries.keys().take(extra).cloned().collect();
            for key in keys {
                self.entries.remove(&key);
            }
        }
    }
}

fn compute_hashes(
    file: &mut File,
    requirements: HashRequirements,
    buf: &mut [u8],
) -> anyhow::Result<ComputedHashes> {
    let mut md5_hasher = requirements.md5.then(Md5::new);
    let mut sha1_hasher = requirements.sha1.then(Sha1::new);
    let mut sha256_hasher = requirements.sha256.then(Sha256::new);

    loop {
        let read = file.read(buf)?;
        if read == 0 {
            break;
        }
        if let Some(hasher) = md5_hasher.as_mut() {
            hasher.update(&buf[..read]);
        }
        if let Some(hasher) = sha1_hasher.as_mut() {
            hasher.update(&buf[..read]);
        }
        if let Some(hasher) = sha256_hasher.as_mut() {
            hasher.update(&buf[..read]);
        }
    }

    Ok(ComputedHashes {
        md5: md5_hasher.map(|h| hex::encode(h.finalize())),
        sha1: sha1_hasher.map(|h| hex::encode(h.finalize())),
        sha256: sha256_hasher.map(|h| hex::encode(h.finalize())),
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sha256_only() -> HashRequirements {
        HashRequirements {
            md5: false,
            sha1: false,
            sha256: true,
        }
    }

    #[test]
    fn unchanged_file_reuses_hash_cache_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write sample");
        let mut cache = HashCache::new();
        let mut buf = [0u8; 64];

        let first = cache
            .get_or_compute(&path, sha256_only(), &mut buf)
            .expect("first hash");
        cache
            .entries
            .values_mut()
            .next()
            .expect("cache entry")
            .hashes
            .sha256 = Some("cached".to_string());
        let second = cache
            .get_or_compute(&path, sha256_only(), &mut buf)
            .expect("cached hash");

        assert_ne!(first.sha256, second.sha256);
        assert_eq!(second.sha256.as_deref(), Some("cached"));
        assert_eq!(cache.entries.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_with_same_size_and_mtime_gets_new_hash() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write sample");
        let original_mtime = fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let mut cache = HashCache::new();
        let mut buf = [0u8; 64];
        let clean = cache
            .get_or_compute(&path, sha256_only(), &mut buf)
            .expect("clean hash");

        let replacement = tempdir.path().join("replacement.bin");
        fs::write(&replacement, b"evil!!").expect("write replacement");
        File::options()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .set_times(fs::FileTimes::new().set_modified(original_mtime))
            .expect("preserve mtime");
        fs::rename(&replacement, &path).expect("replace sample");

        let malicious = cache
            .get_or_compute(&path, sha256_only(), &mut buf)
            .expect("replacement hash");

        assert_ne!(clean.sha256, malicious.sha256);
        assert_eq!(cache.entries.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn file_changed_during_hashing_is_not_cached() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write sample");
        let mut cache = HashCache::new();
        let mut buf = [0u8; 64];

        cache
            .get_or_compute_with(&path, sha256_only(), &mut buf, |file, requirements, buf| {
                let hashes = compute_hashes(file, requirements, buf)?;
                fs::write(&path, b"evil!!").expect("mutate during hashing");
                Ok(hashes)
            })
            .expect("hash mutated file");

        assert!(cache.entries.is_empty());
    }
}
