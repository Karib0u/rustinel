//! PE metadata parsing utilities
//!
//! Extracts version information from PE files to detect masquerading attacks.
//! Uses memory-mapped I/O for zero-copy parsing.

use memmap2::Mmap;
use pelite::pe64::{Pe, PeFile};
use pelite::resources::Resources;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tracing::debug;

use crate::utils::file_identity::{self, FileIdentity};

const PE_CACHE_MAX_ENTRIES: usize = 1024;

/// PE metadata extracted from version resources
#[derive(Debug, Clone)]
pub struct PeMetadata {
    /// OriginalFilename from version info (e.g., "cmd.exe")
    /// This is the primary indicator for masquerading detection
    pub original_filename: Option<String>,

    /// Product name (e.g., "Microsoft® Windows® Operating System")
    pub product: Option<String>,

    /// File description (e.g., "Windows Command Processor")
    pub description: Option<String>,

    /// Company name (e.g., "Microsoft Corporation")
    pub company: Option<String>,

    /// File version string (e.g., "10.0.22621.1 (WinBuild.160101.0800)")
    pub file_version: Option<String>,
}

/// The version-resource fields in the order the event structs and the process
/// cache take them: original filename, product, description, company, version.
pub type PeVersionFields = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Spread parsed metadata into [`PeVersionFields`], yielding all-`None` for an
/// image with no readable version resource.
pub fn version_fields(metadata: Option<PeMetadata>) -> PeVersionFields {
    metadata
        .map(|meta| {
            (
                meta.original_filename,
                meta.product,
                meta.description,
                meta.company,
                meta.file_version,
            )
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PeCacheKey {
    path: PathBuf,
    identity: FileIdentity,
}

struct PeCacheEntry {
    metadata: Option<PeMetadata>,
    last_used: u64,
}

struct PeMetadataCache {
    entries: HashMap<PeCacheKey, PeCacheEntry>,
    capacity: usize,
    access_counter: u64,
}

impl PeMetadataCache {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            access_counter: 0,
        }
    }

    fn get(&mut self, key: &PeCacheKey) -> Option<Option<PeMetadata>> {
        let entry = self.entries.get_mut(key)?;
        self.access_counter = self.access_counter.wrapping_add(1);
        entry.last_used = self.access_counter;
        Some(entry.metadata.clone())
    }

    fn insert(&mut self, key: PeCacheKey, metadata: Option<PeMetadata>) {
        self.access_counter = self.access_counter.wrapping_add(1);
        self.entries.insert(
            key,
            PeCacheEntry {
                metadata,
                last_used: self.access_counter,
            },
        );

        if self.entries.len() > self.capacity {
            let least_recent = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            if let Some(key) = least_recent {
                self.entries.remove(&key);
            }
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.access_counter = 0;
    }
}

/// Global bounded cache. File identity includes size and timestamps, so replacing
/// a binary at the same path cannot reuse metadata from the previous file.
static PE_CACHE: OnceLock<Mutex<PeMetadataCache>> = OnceLock::new();

fn get_cache() -> &'static Mutex<PeMetadataCache> {
    PE_CACHE.get_or_init(|| Mutex::new(PeMetadataCache::with_capacity(PE_CACHE_MAX_ENTRIES)))
}

/// Parse PE metadata from a file
///
/// # Arguments
/// * `path` - DOS path to the PE file (e.g., "C:\Windows\System32\cmd.exe")
///
/// # Returns
/// * `Some(PeMetadata)` if parsing succeeded
/// * `None` if:
///   - File doesn't exist (short-lived process)
///   - File is locked (sharing violation)
///   - Not a valid PE file
///   - No version resources present
///
/// # Performance
/// Uses a bounded in-memory LRU cache before memory-mapping and parsing the file.
///
/// # Thread Safety
/// This function is thread-safe and can be called from multiple threads concurrently.
pub fn parse_metadata<P: AsRef<Path>>(path: P) -> Option<PeMetadata> {
    let path = path.as_ref();
    let file = open_file(path)?;
    let Some(identity) = file_identity::from_file(&file) else {
        return parse_metadata_impl(path, &file);
    };
    let key = PeCacheKey {
        path: path.to_path_buf(),
        identity,
    };

    // Check cache first (fast path)
    if let Some(cached) = get_cache().lock().unwrap().get(&key) {
        return cached;
    }

    // Cache miss - parse from disk (slow path)
    let metadata = parse_metadata_impl(path, &file);

    // Store in cache (even if None, to avoid repeated failed attempts)
    get_cache().lock().unwrap().insert(key, metadata.clone());

    metadata
}

fn open_file(path: &Path) -> Option<File> {
    match File::open(path) {
        Ok(file) => Some(file),
        Err(error) => {
            // NotFound is expected for short-lived processes that exit before
            // their image can be inspected.
            if error.kind() != io::ErrorKind::NotFound {
                debug!(
                    "Failed to open file for PE parsing: {} - {}",
                    path.display(),
                    error
                );
            }
            None
        }
    }
}

/// Internal implementation of PE metadata parsing
fn parse_metadata_impl(path: &Path, file: &File) -> Option<PeMetadata> {
    // Memory-map the file (zero-copy)
    let mmap = match unsafe { Mmap::map(file) } {
        Ok(m) => m,
        Err(e) => {
            debug!("Failed to memory-map file: {} - {}", path.display(), e);
            return None;
        }
    };

    // Try to parse as 64-bit PE first
    let metadata = if let Ok(pe) = PeFile::from_bytes(&mmap) {
        pe.resources().ok().and_then(extract_version_info)
    } else {
        // If 64-bit parsing fails, try 32-bit
        match pelite::pe32::PeFile::from_bytes(&mmap) {
            Ok(pe) => {
                use pelite::pe32::Pe as Pe32;
                pe.resources().ok().and_then(extract_version_info)
            }
            Err(e) => {
                // Not a valid PE file or corrupted
                debug!("Failed to parse PE file: {} - {:?}", path.display(), e);
                return None;
            }
        }
    };

    if metadata.is_some() {
        debug!("Successfully parsed PE metadata: {}", path.display());
    }

    metadata
}

/// Extract version info from a PE resource directory
///
/// The resource directory type is shared between 32-bit and 64-bit images, so
/// both widths run through this single extraction.
fn extract_version_info(resources: Resources<'_>) -> Option<PeMetadata> {
    let version_info = resources.version_info().ok()?;

    // Extract common version fields using callback-based API
    let mut original_filename = None;
    let mut product = None;
    let mut description = None;
    let mut company = None;
    let mut file_version = None;

    // Iterate over all available languages (Windows exes often use 0x0409 US English, not default)
    for lang in version_info.translation() {
        version_info.strings(*lang, |key: &str, value: &str| match key {
            "OriginalFilename" if original_filename.is_none() => {
                original_filename = Some(value.to_string())
            }
            "ProductName" if product.is_none() => product = Some(value.to_string()),
            "FileDescription" if description.is_none() => description = Some(value.to_string()),
            "CompanyName" if company.is_none() => company = Some(value.to_string()),
            "FileVersion" if file_version.is_none() => file_version = Some(value.to_string()),
            _ => {}
        });
        // Early exit if we found all fields
        if original_filename.is_some()
            && product.is_some()
            && description.is_some()
            && company.is_some()
            && file_version.is_some()
        {
            break;
        }
    }

    // Only return Some if we found at least one field
    if original_filename.is_some()
        || product.is_some()
        || description.is_some()
        || company.is_some()
        || file_version.is_some()
    {
        Some(PeMetadata {
            original_filename,
            product,
            description,
            company,
            file_version,
        })
    } else {
        None
    }
}

/// Clear the PE metadata cache
/// This is useful for testing or if you need to force re-parsing
#[allow(dead_code)]
pub fn clear_cache() {
    let mut cache = get_cache().lock().unwrap();
    cache.clear();
    debug!("Cleared PE metadata cache");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    #[cfg(windows)]
    fn test_parse_cmd_exe() {
        // cmd.exe should always exist on Windows
        let path = r"C:\Windows\System32\cmd.exe";
        let metadata = parse_metadata(path);

        assert!(metadata.is_some(), "Should be able to parse cmd.exe");
        let meta = metadata.unwrap();

        // cmd.exe should have OriginalFilename
        assert!(
            meta.original_filename.is_some(),
            "cmd.exe should have OriginalFilename"
        );

        // Check that it contains "cmd" (case-insensitive)
        let original = meta.original_filename.unwrap().to_lowercase();
        assert!(
            original.contains("cmd"),
            "OriginalFilename should contain 'cmd'"
        );

        // CompanyName and FileVersion are present in the same version resource
        let company = meta.company.expect("cmd.exe should have CompanyName");
        assert!(
            company.to_lowercase().contains("microsoft"),
            "CompanyName should name Microsoft, got {company:?}"
        );

        let file_version = meta.file_version.expect("cmd.exe should have FileVersion");
        assert!(
            file_version.starts_with(|c: char| c.is_ascii_digit()),
            "FileVersion should start with a version number, got {file_version:?}"
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_cache_works() {
        clear_cache(); // Start fresh

        let path = r"C:\Windows\System32\cmd.exe";

        // First call - cache miss
        let meta1 = parse_metadata(path);

        // Second call - should be cache hit
        let meta2 = parse_metadata(path);

        // Both should return the same result
        assert_eq!(meta1.is_some(), meta2.is_some());
    }

    #[test]
    #[cfg(windows)]
    fn test_cache_is_bounded_and_least_recently_used() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut keys = Vec::new();
        for name in ["one.exe", "two.exe", "three.exe"] {
            let path = tempdir.path().join(name);
            fs::write(&path, name).expect("write cache fixture");
            let file = File::open(&path).expect("open cache fixture");
            keys.push(PeCacheKey {
                path,
                identity: file_identity::from_file(&file).expect("file identity"),
            });
        }

        let mut cache = PeMetadataCache::with_capacity(2);
        cache.insert(keys[0].clone(), None);
        cache.insert(keys[1].clone(), None);
        assert!(cache.get(&keys[0]).is_some());
        cache.insert(keys[2].clone(), None);

        assert_eq!(cache.entries.len(), 2);
        assert!(cache.get(&keys[0]).is_some());
        assert!(cache.get(&keys[1]).is_none());
        assert!(cache.get(&keys[2]).is_some());
    }

    #[test]
    #[cfg(windows)]
    fn test_replacing_file_invalidates_cached_metadata() {
        clear_cache();
        let windows_dir = PathBuf::from(std::env::var_os("WINDIR").expect("WINDIR"));
        let cmd = windows_dir.join("System32").join("cmd.exe");
        let notepad = windows_dir.join("System32").join("notepad.exe");
        let tempdir = tempfile::tempdir().expect("tempdir");
        let cached_path = tempdir.path().join("cached.exe");

        fs::copy(&cmd, &cached_path).expect("copy cmd.exe");
        let before = parse_metadata(&cached_path)
            .and_then(|metadata| metadata.original_filename)
            .expect("cmd.exe OriginalFilename");

        fs::copy(&notepad, &cached_path).expect("replace with notepad.exe");
        let after = parse_metadata(&cached_path)
            .and_then(|metadata| metadata.original_filename)
            .expect("notepad.exe OriginalFilename");

        assert_ne!(before.to_ascii_lowercase(), after.to_ascii_lowercase());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        // Should return None without panicking
        let metadata = parse_metadata(r"C:\nonexistent\file.exe");
        assert!(metadata.is_none());
    }
}
