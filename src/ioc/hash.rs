use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileIdentity {
    path: String,
    size: u64,
    mtime: u64,
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
        let identity = file_identity(path);
        if let Some(identity) = &identity {
            if let Some(entry) = self.entries.get(identity) {
                if !self.is_expired(entry) {
                    return Ok(entry.hashes.clone());
                }
            }
        }

        let hashes = compute_hashes(path, requirements, buf)?;
        if let Some(identity) = identity {
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
    path: &Path,
    requirements: HashRequirements,
    buf: &mut [u8],
) -> anyhow::Result<ComputedHashes> {
    let mut file = fs::File::open(path)?;

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

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = fs::metadata(path).ok()?;
    let size = metadata.len();
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_default();

    Some(FileIdentity {
        path: path.display().to_string(),
        size,
        mtime,
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
