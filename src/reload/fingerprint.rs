//! Metadata fingerprints used to detect rule, IOC, and configuration changes.

use std::collections::{hash_map::DefaultHasher, VecDeque};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::config::IocConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Fingerprint {
    digest: u64,
    file_count: u64,
    exists: bool,
}

pub(super) fn fingerprint_ioc_files(cfg: &IocConfig) -> Fingerprint {
    let mut hasher = DefaultHasher::new();
    let mut file_count = 0_u64;
    let mut exists = false;

    for path in [
        &cfg.hashes_path,
        &cfg.ips_path,
        &cfg.domains_path,
        &cfg.paths_regex_path,
    ] {
        path.hash(&mut hasher);
        let file_fp = fingerprint_file(path);
        file_fp.digest.hash(&mut hasher);
        file_fp.file_count.hash(&mut hasher);
        file_fp.exists.hash(&mut hasher);
        file_count += file_fp.file_count;
        exists = exists || file_fp.exists;
    }

    Fingerprint {
        digest: hasher.finish(),
        file_count,
        exists,
    }
}

pub(super) fn fingerprint_file(path: &Path) -> Fingerprint {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);

    match fs::metadata(path) {
        Ok(meta) => {
            meta.len().hash(&mut hasher);
            modified_nanos(&meta).hash(&mut hasher);
            Fingerprint {
                digest: hasher.finish(),
                file_count: 1,
                exists: true,
            }
        }
        Err(_) => Fingerprint {
            digest: hasher.finish(),
            file_count: 0,
            exists: false,
        },
    }
}

pub(super) fn fingerprint_dir(root: &Path, extensions: &[&str]) -> Fingerprint {
    let mut hasher = DefaultHasher::new();
    let mut file_count = 0_u64;

    let root = normalize_path(root);
    root.hash(&mut hasher);

    if !root.exists() || !root.is_dir() {
        return Fingerprint {
            digest: hasher.finish(),
            file_count: 0,
            exists: false,
        };
    }

    let mut queue = VecDeque::from([root.clone()]);
    while let Some(dir) = queue.pop_front() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                queue.push_back(path);
                continue;
            }

            if !matches_extension(&path, extensions) {
                continue;
            }

            if let Ok(meta) = entry.metadata() {
                let normalized = normalize_path(&path);
                normalized.hash(&mut hasher);
                meta.len().hash(&mut hasher);
                modified_nanos(&meta).hash(&mut hasher);
                file_count += 1;
            }
        }
    }

    Fingerprint {
        digest: hasher.finish(),
        file_count,
        exists: true,
    }
}

pub(super) fn normalize_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn matches_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let ext = ext.to_ascii_lowercase();
            extensions.iter().any(|candidate| ext == *candidate)
        })
        .unwrap_or(false)
}

fn modified_nanos(meta: &fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
