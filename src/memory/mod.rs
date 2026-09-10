//! Process memory reader for YARA memory scanning.
//!
//! Visits selected regions one at a time using a reusable buffer. Individual
//! region read failures are non-fatal and are skipped.

mod types;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(windows)]
mod windows;

pub use types::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig};

use anyhow::Result;
use std::ops::ControlFlow;
use std::time::Instant;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
use unsupported as platform;
#[cfg(windows)]
use windows as platform;

/// Read selected memory regions from `pid` according to `cfg`.
/// Returns whatever chunks could be read; individual region failures are silently skipped.
pub fn read_process_memory_chunks(pid: u32, cfg: &MemoryScanConfig) -> Result<Vec<MemoryChunk>> {
    let mut chunks = Vec::new();
    visit_process_memory_chunks(pid, cfg, None, |chunk| {
        chunks.push(chunk.clone());
        ControlFlow::Continue(())
    })?;
    Ok(chunks)
}

/// Visit each readable region before reading the next, retaining only one buffer.
/// The borrowed chunk is valid only during the callback. Return `Break` to stop.
/// No further region is read after `deadline`; an active OS read cannot be interrupted.
pub fn visit_process_memory_chunks(
    pid: u32,
    cfg: &MemoryScanConfig,
    deadline: Option<Instant>,
    visitor: impl FnMut(&MemoryChunk) -> ControlFlow<()>,
) -> Result<()> {
    platform::visit_process_memory_chunks(pid, cfg, deadline, visitor)
}

/// Shared byte limits and buffer lifecycle for all platform readers.
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
struct RegionReader<'a> {
    cfg: &'a MemoryScanConfig,
    deadline: Option<Instant>,
    total_bytes: usize,
    buffer: Vec<u8>,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
impl<'a> RegionReader<'a> {
    fn new(cfg: &'a MemoryScanConfig, deadline: Option<Instant>) -> Self {
        Self {
            cfg,
            deadline,
            total_bytes: 0,
            buffer: Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        self.total_bytes >= self.cfg.max_process_bytes
            || self.cfg.max_region_bytes == 0
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn read_region(
        &mut self,
        region: MemoryRegion,
        read: impl FnOnce(&mut [u8]) -> Option<usize>,
        visitor: &mut impl FnMut(&MemoryChunk) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if self.is_done() {
            return ControlFlow::Break(());
        }
        let size = region
            .size
            .min(self.cfg.max_region_bytes)
            .min(self.cfg.max_process_bytes - self.total_bytes);
        if size == 0 {
            return ControlFlow::Continue(());
        }
        // Reserve exactly so capacity stays within the region byte limit.
        if self.buffer.capacity() < size {
            self.buffer.reserve_exact(size - self.buffer.len());
        }
        self.buffer.resize(size, 0);
        if self.is_done() {
            return ControlFlow::Break(());
        }
        let Some(bytes_read) = read(&mut self.buffer) else {
            return ControlFlow::Continue(());
        };
        let bytes_read = bytes_read.min(size);
        if bytes_read == 0 {
            return ControlFlow::Continue(());
        }
        self.total_bytes += bytes_read;
        self.buffer.truncate(bytes_read);
        let chunk = MemoryChunk {
            base: region.base,
            bytes: std::mem::take(&mut self.buffer),
            region,
        };
        let result = visitor(&chunk);
        // Reclaim this region's payload before any later read.
        self.buffer = chunk.bytes;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_config() -> MemoryScanConfig {
        MemoryScanConfig {
            max_process_bytes: 10,
            max_region_bytes: 4,
            include_private: true,
            include_image: false,
            include_mapped: false,
            delay_ms: 0,
        }
    }

    fn region(base: u64) -> MemoryRegion {
        MemoryRegion {
            base,
            size: 20,
            readable: true,
            writable: true,
            executable: false,
            kind: MemoryRegionKind::Private,
        }
    }

    #[test]
    fn streaming_reclaims_previous_payload_before_later_reads() {
        use std::cell::Cell;
        let cfg = small_config();
        let mut reader = RegionReader::new(&cfg, None);
        let visited = Cell::new(0);
        let mut buffer_ptr = None;
        let mut lengths = Vec::new();
        for index in 0..3 {
            assert!(reader
                .read_region(
                    region(0x1000 + index),
                    |buffer| {
                        // Every previous scan finished before this read. The exact
                        // same allocation is available again, so no earlier payload
                        // can remain buffered alongside the current region.
                        assert_eq!(visited.get(), index);
                        if let Some(ptr) = buffer_ptr {
                            assert_eq!(buffer.as_ptr(), ptr);
                        } else {
                            buffer_ptr = Some(buffer.as_ptr());
                        }
                        buffer.fill(index as u8);
                        Some(buffer.len())
                    },
                    &mut |chunk| {
                        assert_eq!(chunk.base, 0x1000 + index);
                        assert_eq!(chunk.region.base, chunk.base);
                        assert_eq!(chunk.region.size, 20);
                        assert_eq!(chunk.region.kind, MemoryRegionKind::Private);
                        assert!(chunk.bytes.iter().all(|byte| *byte == index as u8));
                        assert!(chunk.bytes.capacity() <= cfg.max_region_bytes);
                        lengths.push(chunk.bytes.len());
                        visited.set(index + 1);
                        ControlFlow::Continue(())
                    },
                )
                .is_continue());
        }
        assert_eq!(lengths, [4, 4, 2]);
        assert!(reader.is_done());
        assert!(reader
            .read_region(
                region(0x2000),
                |_| panic!("process byte budget exhausted"),
                &mut |_| panic!("no further chunks"),
            )
            .is_break());
    }

    #[test]
    fn streaming_partial_and_failed_reads_preserve_byte_budget() {
        let cfg = small_config();
        let mut reader = RegionReader::new(&cfg, None);
        let mut lengths = Vec::new();
        for count in [None, Some(0), Some(2), Some(4), Some(4)] {
            assert!(reader
                .read_region(
                    region(0x1000),
                    |buffer| {
                        assert_eq!(buffer.len(), 4);
                        count
                    },
                    &mut |chunk| {
                        lengths.push(chunk.bytes.len());
                        ControlFlow::Continue(())
                    },
                )
                .is_continue());
        }
        assert_eq!(lengths, [2, 4, 4]);
        assert!(reader.is_done());
    }

    #[test]
    fn streaming_honors_deadline_and_zero_byte_limits() {
        for (process_limit, region_limit, deadline) in
            [(10, 4, Some(Instant::now())), (0, 4, None), (10, 0, None)]
        {
            let mut cfg = small_config();
            cfg.max_process_bytes = process_limit;
            cfg.max_region_bytes = region_limit;
            let mut reader = RegionReader::new(&cfg, deadline);
            assert!(reader
                .read_region(
                    region(0x1000),
                    |_| panic!("stopped reader must not read"),
                    &mut |_| panic!("stopped reader must not visit"),
                )
                .is_break());
        }
    }

    #[test]
    fn streaming_propagates_visitor_stop() {
        let cfg = small_config();
        let mut reader = RegionReader::new(&cfg, None);
        assert!(reader
            .read_region(region(0x1000), |buffer| Some(buffer.len()), &mut |_| {
                ControlFlow::Break(())
            },)
            .is_break());
        assert_eq!(reader.buffer.len(), 4);
    }

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
