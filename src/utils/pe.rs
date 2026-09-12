//! PE metadata parsing utilities
//!
//! Extracts version information from PE files to detect masquerading attacks.
//! Uses memory-mapped I/O for zero-copy parsing.

use goblin::pe::{resource::StringFileInfo, PE};
use memmap2::Mmap;
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

    let pe = match PE::parse(&mmap) {
        Ok(pe) => pe,
        Err(error) => {
            // Not a valid PE file or corrupted
            debug!("Failed to parse PE file: {} - {:?}", path.display(), error);
            return None;
        }
    };
    let metadata = extract_version_info(&pe);

    if metadata.is_some() {
        debug!("Successfully parsed PE metadata: {}", path.display());
    }

    metadata
}

/// Extract version info from Goblin's unified PE32/PE32+ representation.
fn extract_version_info(pe: &PE<'_>) -> Option<PeMetadata> {
    let string_info = &pe.resource_data?.version_info?.string_info;
    metadata_from_strings(string_info)
}

fn metadata_from_strings(string_info: &StringFileInfo<'_>) -> Option<PeMetadata> {
    let original_filename = string_info.original_filename();
    let product = string_info.product_name();
    let description = string_info.file_description();
    let company = string_info.company_name();
    // Keep the FileVersion string. Goblin 0.10's fixed-info helper reads the
    // fixed file-date fields instead of the fixed file-version fields.
    let file_version = string_info.file_version();

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
    #[cfg(windows)]
    use std::fs;
    use std::io::Write;

    const RESOURCE_RVA: u32 = 0x1000;
    const RESOURCE_OFFSET: usize = 0x200;
    const VERSION_INFO_OFFSET: usize = 88;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn build_pe_with_version_info(version_info: &[u8]) -> Vec<u8> {
        let resource_size = VERSION_INFO_OFFSET + version_info.len();
        let raw_size = resource_size.div_ceil(0x200) * 0x200;
        let mut image = vec![0; RESOURCE_OFFSET + raw_size];

        image[0..2].copy_from_slice(b"MZ");
        write_u32(&mut image, 0x3c, 0x80);
        image[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        write_u16(&mut image, coff, 0x014c);
        write_u16(&mut image, coff + 2, 1);
        write_u16(&mut image, coff + 16, 0x00e0);
        write_u16(&mut image, coff + 18, 0x0102);

        let optional = coff + 20;
        write_u16(&mut image, optional, 0x010b);
        write_u32(&mut image, optional + 28, 0x0040_0000);
        write_u32(&mut image, optional + 32, 0x1000);
        write_u32(&mut image, optional + 36, 0x200);
        write_u16(&mut image, optional + 40, 6);
        write_u16(&mut image, optional + 48, 6);
        write_u32(&mut image, optional + 56, 0x2000);
        write_u32(&mut image, optional + 60, RESOURCE_OFFSET as u32);
        write_u16(&mut image, optional + 68, 3);
        write_u32(&mut image, optional + 72, 0x10_0000);
        write_u32(&mut image, optional + 76, 0x1000);
        write_u32(&mut image, optional + 80, 0x10_0000);
        write_u32(&mut image, optional + 84, 0x1000);
        write_u32(&mut image, optional + 92, 16);
        write_u32(&mut image, optional + 112, RESOURCE_RVA);
        write_u32(&mut image, optional + 116, resource_size as u32);

        let section = optional + 0x00e0;
        image[section..section + 5].copy_from_slice(b".rsrc");
        write_u32(&mut image, section + 8, resource_size as u32);
        write_u32(&mut image, section + 12, RESOURCE_RVA);
        write_u32(&mut image, section + 16, raw_size as u32);
        write_u32(&mut image, section + 20, RESOURCE_OFFSET as u32);
        write_u32(&mut image, section + 36, 0x4000_0040);

        let resource = &mut image[RESOURCE_OFFSET..];
        for (offset, value) in [
            (12, 1u32 << 16),
            (16, 16),
            (20, 0x8000_0018),
            (36, 1 << 16),
            (40, 1),
            (44, 0x8000_0030),
            (60, 1 << 16),
            (64, 0x0409),
            (68, 72),
            (72, RESOURCE_RVA + VERSION_INFO_OFFSET as u32),
            (76, version_info.len() as u32),
        ] {
            write_u32(resource, offset, value);
        }
        resource[VERSION_INFO_OFFSET..VERSION_INFO_OFFSET + version_info.len()]
            .copy_from_slice(version_info);

        image
    }

    fn resource_string(key: &str, value: &[u8], text: bool) -> Vec<u8> {
        let value_len = if text { value.len() / 2 } else { value.len() };
        let mut entry = vec![0; 6];
        for word in key.encode_utf16().chain(std::iter::once(0)) {
            entry.extend_from_slice(&word.to_le_bytes());
        }
        entry.resize(entry.len().next_multiple_of(4), 0);
        entry.extend_from_slice(value);
        entry.resize(entry.len().next_multiple_of(4), 0);
        let entry_len = entry.len() as u16;
        write_u16(&mut entry, 0, entry_len);
        write_u16(&mut entry, 2, value_len as u16);
        write_u16(&mut entry, 4, u16::from(text));
        entry
    }

    fn text_resource_string(key: &str, value: &str) -> Vec<u8> {
        let value = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        resource_string(key, &value, true)
    }

    fn valid_version_info() -> Vec<u8> {
        let mut fixed_info = [0; 52];
        write_u32(&mut fixed_info, 0, 0xfeef_04bd);
        write_u32(&mut fixed_info, 4, 0x0001_0000);
        write_u32(&mut fixed_info, 8, 0x0001_0002);
        write_u32(&mut fixed_info, 12, 0x0003_0004);
        // Goblin 0.10's fixed-info helper reads these file-date fields. Keep
        // them distinct from the FileVersion string to catch accidental use.
        write_u32(&mut fixed_info, 44, 0x0063_0062);
        write_u32(&mut fixed_info, 48, 0x0061_0060);

        let mut version_info = resource_string("VS_VERSION_INFO", &fixed_info, false);
        let string_file_info = version_info.len();
        version_info.extend(resource_string("StringFileInfo", &[], true));
        let string_table = version_info.len();
        version_info.extend(resource_string("040904E4", &[], true));
        for (key, value) in [
            ("OriginalFilename", "fixture.exe"),
            ("ProductName", "Fixture Product"),
            ("FileDescription", "Fixture Description"),
            ("CompanyName", "Fixture Company"),
            ("FileVersion", "9.8.7.6-string"),
        ] {
            version_info.extend(text_resource_string(key, value));
        }
        let total_len = version_info.len();
        write_u16(
            &mut version_info,
            string_table,
            (total_len - string_table) as u16,
        );
        write_u16(
            &mut version_info,
            string_file_info,
            (total_len - string_file_info) as u16,
        );
        write_u16(&mut version_info, 0, total_len as u16);
        version_info
    }

    #[test]
    fn test_truncated_version_resource_does_not_panic() {
        // The key ends at the node boundary, leaving no alignment padding.
        let malformed = [14u16, 0, 1, 65, 66, 67, 0]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let image = build_pe_with_version_info(&malformed);
        let mut file = tempfile::NamedTempFile::new().expect("create fixture");
        file.write_all(&image).expect("write fixture");
        file.flush().expect("flush fixture");

        assert!(parse_metadata_impl(file.path(), file.as_file()).is_none());
    }

    #[test]
    fn test_extracts_expected_version_strings() {
        let image = build_pe_with_version_info(&valid_version_info());
        let mut file = tempfile::NamedTempFile::new().expect("create fixture");
        file.write_all(&image).expect("write fixture");
        file.flush().expect("flush fixture");

        let metadata = parse_metadata_impl(file.path(), file.as_file()).expect("parse metadata");
        assert_eq!(metadata.original_filename.as_deref(), Some("fixture.exe"));
        assert_eq!(metadata.product.as_deref(), Some("Fixture Product"));
        assert_eq!(metadata.description.as_deref(), Some("Fixture Description"));
        assert_eq!(metadata.company.as_deref(), Some("Fixture Company"));
        assert_eq!(metadata.file_version.as_deref(), Some("9.8.7.6-string"));
    }

    #[test]
    fn test_truncated_pe_does_not_panic() {
        let mut file = tempfile::NamedTempFile::new().expect("create fixture");
        file.write_all(b"MZ").expect("write fixture");
        file.flush().expect("flush fixture");

        assert!(parse_metadata_impl(file.path(), file.as_file()).is_none());
    }

    #[test]
    fn test_valid_fixture_is_pe32() {
        let image = build_pe_with_version_info(&valid_version_info());
        let pe = PE::parse(&image).expect("parse fixture");
        assert!(!pe.is_64);
    }

    #[test]
    fn test_goblin_handles_pe32_plus() {
        let mut image = build_pe_with_version_info(&valid_version_info());
        let coff = 0x84;
        let optional = 0x84 + 20;
        let pe32_section = optional + 0x00e0;
        image.copy_within(pe32_section..pe32_section + 40, pe32_section + 16);
        image[pe32_section..pe32_section + 16].fill(0);
        write_u16(&mut image, coff + 16, 0x00f0);
        write_u16(&mut image, optional, 0x020b);
        write_u64(&mut image, optional + 24, 0x0040_0000);
        write_u64(&mut image, optional + 72, 0x10_0000);
        write_u64(&mut image, optional + 80, 0x1000);
        write_u64(&mut image, optional + 88, 0x10_0000);
        write_u64(&mut image, optional + 96, 0x1000);
        write_u32(&mut image, optional + 104, 0);
        write_u32(&mut image, optional + 108, 16);
        image[optional + 112..optional + 240].fill(0);
        write_u32(&mut image, optional + 128, RESOURCE_RVA);
        write_u32(
            &mut image,
            optional + 132,
            (VERSION_INFO_OFFSET + valid_version_info().len()) as u32,
        );

        let pe = PE::parse(&image).expect("parse PE32+ fixture");
        assert!(pe.is_64);
        assert_eq!(
            extract_version_info(&pe)
                .and_then(|metadata| metadata.original_filename)
                .as_deref(),
            Some("fixture.exe")
        );
    }

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
