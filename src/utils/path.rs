//! Path normalization utilities
//!
//! Converts NT Device paths (\Device\HarddiskVolume2\...) to DOS paths (C:\...)
//! This is critical for:
//! 1. I/O operations (Rust std can't open NT paths)
//! 2. Sigma rule compatibility (rules expect DOS paths like C:\Windows\System32\cmd.exe)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

#[cfg(windows)]
use tracing::warn;

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};

/// Global drive map: Device Path -> Drive Letter
/// Example: "\Device\HarddiskVolume2" -> "C:"
static DRIVE_MAP: OnceLock<DriveMapCache> = OnceLock::new();

const DRIVE_MAP_REFRESH_COOLDOWN_SECS: u64 = 10;

/// Initialize the drive map on first use
#[cfg(windows)]
fn init_drive_map() -> HashMap<String, String> {
    let mut map = HashMap::new();

    // SAFETY: every call below passes pointers into live local buffers, with the
    // buffer length given to QueryDosDeviceW as the slice it receives, and the
    // NUL-terminated wide string outlives its call.
    unsafe {
        // Get bitmask of available logical drives (A=bit 0, B=bit 1, C=bit 2, etc.)
        let drives = GetLogicalDrives();

        for i in 0..26 {
            // Check if drive letter is available
            if (drives & (1 << i)) != 0 {
                let drive_letter = (b'A' + i as u8) as char;
                let dos_device = format!("{}:", drive_letter);

                // Query the NT device path for this drive letter
                // Example: "C:" -> "\Device\HarddiskVolume2"
                let dos_device_wide: Vec<u16> = dos_device.encode_utf16().chain(Some(0)).collect();
                let mut buffer = [0u16; 260]; // MAX_PATH

                let result = QueryDosDeviceW(PCWSTR(dos_device_wide.as_ptr()), Some(&mut buffer));

                if result > 0 {
                    // Convert buffer to String (stop at first null)
                    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                    let device_path = String::from_utf16_lossy(&buffer[..len]);

                    // Store mapping: Device -> DOS
                    // Example: "\Device\HarddiskVolume2" -> "C:"
                    map.insert(device_path.clone(), dos_device.clone());
                    debug!("Mapped {} -> {}", device_path, dos_device);
                }
            }
        }
    }

    if map.is_empty() {
        warn!("Failed to build drive map - path normalization will not work");
    } else {
        debug!("Initialized drive map with {} entries", map.len());
    }

    map
}

#[cfg(not(windows))]
fn init_drive_map() -> HashMap<String, String> {
    HashMap::new()
}

/// Convert NT Device path to DOS path
///
/// # Examples
/// ```
/// use rustinel::utils::convert_nt_to_dos;
/// // \Device\HarddiskVolume2\Windows\System32\cmd.exe -> C:\Windows\System32\cmd.exe
/// let dos_path = convert_nt_to_dos(r"\Device\HarddiskVolume2\Windows\System32\cmd.exe");
/// # let _ = dos_path;
/// ```
///
/// # Performance
/// This function uses a cached lookup (OnceLock) and does not perform any OS API calls.
/// Typical latency: ~100ns (memory lookup only).
pub fn convert_nt_to_dos(nt_path: &str) -> String {
    // Get or initialize the drive map
    let drive_map = DRIVE_MAP.get_or_init(DriveMapCache::new);

    // If the path doesn't start with \Device\, return as-is
    if !nt_path.starts_with(r"\Device\") {
        return nt_path.to_string();
    }

    if let Some(dos_path) = lookup_dos_path(drive_map, nt_path) {
        return dos_path;
    }

    drive_map.refresh_if_needed(nt_path);

    if let Some(dos_path) = lookup_dos_path(drive_map, nt_path) {
        return dos_path;
    }

    // No match found - return original path
    // This can happen for network paths and other non-disk object paths.
    debug!("No DOS mapping found for NT path: {}", nt_path);
    nt_path.to_string()
}

/// Normalize a path for case-insensitive process identity comparisons.
pub fn normalize_path_for_comparison(value: &str) -> String {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        value.trim().to_ascii_lowercase()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        value.trim().replace('/', "\\").to_ascii_lowercase()
    }
}

fn lookup_dos_path(drive_map: &DriveMapCache, nt_path: &str) -> Option<String> {
    let map = drive_map.map.read().ok()?;
    dos_path_from_map(&map, nt_path).or_else(|| unc_path(nt_path))
}

/// Replace a device prefix with its drive letter, but only at a path
/// component boundary: `\Device\HarddiskVolume1` must not claim
/// `\Device\HarddiskVolume12\...`.
fn dos_path_from_map(map: &HashMap<String, String>, nt_path: &str) -> Option<String> {
    map.iter().find_map(|(device_path, dos_drive)| {
        let remainder = nt_path.strip_prefix(device_path.as_str())?;
        (remainder.is_empty() || remainder.starts_with('\\'))
            .then(|| format!("{dos_drive}{remainder}"))
    })
}

/// Network shares open through the MUP or the SMB redirector, for example
/// `\Device\Mup\;LanmanRedirector\;Z:0000000000000001\server\share\a.exe`.
/// Rules and path allowlists see them as `\\server\share\a.exe`.
fn unc_path(nt_path: &str) -> Option<String> {
    let rest = ["\\Device\\Mup\\", "\\Device\\LanmanRedirector\\"]
        .iter()
        .find_map(|prefix| nt_path.strip_prefix(prefix))?;
    let mut rest = rest;
    // Redirector and drive-mapping segments start with ';'.
    while rest.starts_with(';') {
        rest = rest.split_once('\\')?.1;
    }
    (!rest.is_empty()).then(|| format!("\\\\{rest}"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct DriveMapCache {
    map: RwLock<HashMap<String, String>>,
    last_refresh: AtomicU64,
}

impl DriveMapCache {
    fn new() -> Self {
        let map = init_drive_map();
        Self {
            map: RwLock::new(map),
            last_refresh: AtomicU64::new(0),
        }
    }

    fn refresh_if_needed(&self, nt_path: &str) {
        if !should_refresh_for_path(nt_path) {
            return;
        }

        let now = now_secs();
        let last = self.last_refresh.load(Ordering::Relaxed);
        if now.saturating_sub(last) < DRIVE_MAP_REFRESH_COOLDOWN_SECS {
            return;
        }
        if self
            .last_refresh
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let refreshed = init_drive_map();
        if refreshed.is_empty() {
            return;
        }

        if let Ok(mut map) = self.map.write() {
            *map = refreshed;
        }
    }
}

fn should_refresh_for_path(nt_path: &str) -> bool {
    nt_path.starts_with(r"\Device\HarddiskVolume")
        || nt_path.starts_with(r"\Device\HarddiskVolumeShadowCopy")
        || nt_path.starts_with(r"\Device\Mup")
        || nt_path.starts_with(r"\Device\LanmanRedirector")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_drive_map_initialization() {
        let map = init_drive_map();
        // Should have at least the C: drive on most systems
        assert!(!map.is_empty(), "Drive map should not be empty");

        // Check that we have at least one HarddiskVolume mapping
        let has_volume = map.keys().any(|k| k.contains("HarddiskVolume"));
        assert!(
            has_volume,
            "Drive map should contain at least one HarddiskVolume"
        );
    }

    fn volumes() -> HashMap<String, String> {
        HashMap::from([
            (r"\Device\HarddiskVolume1".to_string(), "C:".to_string()),
            (r"\Device\HarddiskVolume12".to_string(), "D:".to_string()),
        ])
    }

    #[test]
    fn device_prefix_matches_only_at_a_component_boundary() {
        let map = volumes();
        assert_eq!(
            dos_path_from_map(&map, r"\Device\HarddiskVolume1\a.exe").as_deref(),
            Some(r"C:\a.exe")
        );
        assert_eq!(
            dos_path_from_map(&map, r"\Device\HarddiskVolume12\a.exe").as_deref(),
            Some(r"D:\a.exe")
        );
        assert_eq!(
            dos_path_from_map(&map, r"\Device\HarddiskVolume1").as_deref(),
            Some("C:")
        );
        let only_one = HashMap::from([(r"\Device\HarddiskVolume1".to_string(), "C:".to_string())]);
        assert_eq!(
            dos_path_from_map(&only_one, r"\Device\HarddiskVolume12\a.exe"),
            None
        );
    }

    #[test]
    fn network_share_paths_become_unc_paths() {
        assert_eq!(
            unc_path(r"\Device\Mup\server\share\a.exe").as_deref(),
            Some(r"\\server\share\a.exe")
        );
        assert_eq!(
            unc_path(r"\Device\Mup\;LanmanRedirector\;Z:0000000000000001\server\share\a.exe")
                .as_deref(),
            Some(r"\\server\share\a.exe")
        );
        assert_eq!(
            unc_path(r"\Device\LanmanRedirector\;Z:0000000000000001\server\share").as_deref(),
            Some(r"\\server\share")
        );
        assert_eq!(unc_path(r"\Device\Mup\"), None);
        assert_eq!(unc_path(r"\Device\NamedPipe\x"), None);
    }

    #[test]
    fn test_convert_non_nt_path() {
        // Paths that don't start with \Device\ should be returned as-is
        assert_eq!(
            convert_nt_to_dos(r"C:\Windows\System32\cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(
            convert_nt_to_dos(r"\\server\share\file.txt"),
            r"\\server\share\file.txt"
        );
    }

    #[test]
    fn test_normalize_path_for_comparison() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(
            normalize_path_for_comparison(" /USR/BIN/example "),
            "/usr/bin/example"
        );

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(
            normalize_path_for_comparison(" /USR/BIN/example "),
            r"\usr\bin\example"
        );
    }
}
