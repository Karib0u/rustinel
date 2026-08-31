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
use std::path::Path;
use std::sync::RwLock;
use tracing::debug;

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

/// Global PE metadata cache: DOS Path -> PeMetadata
/// This prevents repeated disk I/O for frequently spawned processes (cmd.exe, svchost.exe)
static PE_CACHE: OnceLock<RwLock<HashMap<String, Option<PeMetadata>>>> = OnceLock::new();

use std::sync::OnceLock;

fn get_cache() -> &'static RwLock<HashMap<String, Option<PeMetadata>>> {
    PE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
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
/// Uses a two-layer caching strategy:
/// 1. Memory cache (HashMap) - checked first
/// 2. Disk read (memory-mapped) - only if cache miss
///
/// Typical latency:
/// - Cache hit: ~100ns
/// - Cache miss: ~1-5ms (disk I/O + parsing)
///
/// # Thread Safety
/// This function is thread-safe and can be called from multiple threads concurrently.
pub fn parse_metadata<P: AsRef<Path>>(path: P) -> Option<PeMetadata> {
    let path = path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    // Check cache first (fast path)
    {
        let cache = get_cache().read().unwrap();
        if let Some(cached) = cache.get(&path_str) {
            return cached.clone();
        }
    }

    // Cache miss - parse from disk (slow path)
    let metadata = parse_metadata_impl(path);

    // Store in cache (even if None, to avoid repeated failed attempts)
    {
        let mut cache = get_cache().write().unwrap();
        cache.insert(path_str.clone(), metadata.clone());
    }

    metadata
}

/// Internal implementation of PE metadata parsing
fn parse_metadata_impl(path: &Path) -> Option<PeMetadata> {
    // Try to open the file with shared read access
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            // Common errors:
            // - NotFound: Process already exited
            // - PermissionDenied: File locked or protected
            if e.kind() != io::ErrorKind::NotFound {
                debug!(
                    "Failed to open file for PE parsing: {} - {}",
                    path.display(),
                    e
                );
            }
            return None;
        }
    };

    // Memory-map the file (zero-copy)
    let mmap = match unsafe { Mmap::map(&file) } {
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
    let mut cache = get_cache().write().unwrap();
    cache.clear();
    debug!("Cleared PE metadata cache");
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_parse_nonexistent_file() {
        // Should return None without panicking
        let metadata = parse_metadata(r"C:\nonexistent\file.exe");
        assert!(metadata.is_none());
    }
}
