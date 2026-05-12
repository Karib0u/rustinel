//! Process memory reader for YARA memory scanning.
//!
//! Reads selected memory regions from a live process into byte chunks that
//! can then be passed to `Scanner::scan_bytes`. All I/O failures are treated
//! as non-fatal: callers receive whatever chunks were successfully read.

mod types;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(windows, target_os = "linux")))]
mod unsupported;
#[cfg(windows)]
mod windows;

pub use types::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig};

use anyhow::Result;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(not(any(windows, target_os = "linux")))]
use unsupported as platform;
#[cfg(windows)]
use windows as platform;

/// Read selected memory regions from `pid` according to `cfg`.
/// Returns whatever chunks could be read; individual region failures are silently skipped.
pub fn read_process_memory_chunks(pid: u32, cfg: &MemoryScanConfig) -> Result<Vec<MemoryChunk>> {
    platform::read_process_memory_chunks(pid, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_scan_config_fields() {
        let cfg = MemoryScanConfig {
            max_process_bytes: 64 * 1024 * 1024,
            max_region_bytes: 8 * 1024 * 1024,
            include_private: true,
            include_image: false,
            include_mapped: false,
            delay_ms: 750,
        };
        assert_eq!(cfg.max_process_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.max_region_bytes, 8 * 1024 * 1024);
        assert!(cfg.include_private);
        assert!(!cfg.include_image);
        assert!(!cfg.include_mapped);
    }

    #[test]
    fn test_memory_region_kind_variants() {
        assert_ne!(MemoryRegionKind::Private, MemoryRegionKind::Image);
        assert_ne!(MemoryRegionKind::Mapped, MemoryRegionKind::Other);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_nonexistent_pid_returns_empty() {
        let cfg = MemoryScanConfig {
            max_process_bytes: 1024,
            max_region_bytes: 512,
            include_private: true,
            include_image: true,
            include_mapped: true,
            delay_ms: 0,
        };
        let result = read_process_memory_chunks(99_999_999, &cfg);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
