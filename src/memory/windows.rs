use super::protection::{classify, Protection};
use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig, RegionReader};
use anyhow::Result;
use std::ops::ControlFlow;
use std::time::Instant;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

/// Per-process region counts, so an excluded region is distinguishable from a failed read.
/// `excluded_*` regions were never read; `read_failed` regions were eligible but unreadable.
#[derive(Default)]
struct RegionStats {
    eligible: usize,
    excluded_protection: usize,
    excluded_kind: usize,
    read_failed: usize,
}

pub fn visit_process_memory_chunks(
    pid: u32,
    cfg: &MemoryScanConfig,
    deadline: Option<Instant>,
    mut visitor: impl FnMut(&MemoryChunk) -> ControlFlow<()>,
) -> Result<()> {
    // SAFETY: OpenProcess takes a PID and access flags, with no pointer arguments.
    // The handle it returns is closed with CloseHandle below on every path that
    // reaches the end of the scan.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) | Err(_) => {
            tracing::trace!(
                target: "scanner",
                pid = pid,
                "YARA memory: OpenProcess failed (process may have exited)"
            );
            return Ok(());
        }
    };

    let mut reader = RegionReader::new(cfg, deadline);
    let mut address: usize = 0;
    let mut stats = RegionStats::default();

    loop {
        if reader.is_done() {
            break;
        }

        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `handle` is the live process handle opened above, and `mbi` is
        // a valid MEMORY_BASIC_INFORMATION whose size is passed as the length.
        let written = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if written == 0 {
            break;
        }

        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;

        address = match region_base.checked_add(region_size) {
            Some(next) => next,
            None => break,
        };

        if mbi.State != MEM_COMMIT {
            continue;
        }

        let (writable, executable) = match classify(mbi.Protect.0) {
            Protection::Readable {
                writable,
                executable,
            } => (writable, executable),
            Protection::Guard | Protection::NoAccess | Protection::Unreadable => {
                stats.excluded_protection += 1;
                continue;
            }
        };

        let kind = if mbi.Type == MEM_PRIVATE {
            MemoryRegionKind::Private
        } else if mbi.Type == MEM_IMAGE {
            MemoryRegionKind::Image
        } else if mbi.Type == MEM_MAPPED {
            MemoryRegionKind::Mapped
        } else {
            MemoryRegionKind::Other
        };

        let include = match kind {
            MemoryRegionKind::Private => cfg.include_private,
            MemoryRegionKind::Image => cfg.include_image,
            MemoryRegionKind::Mapped => cfg.include_mapped,
            MemoryRegionKind::Other => false,
        };

        if !include {
            stats.excluded_kind += 1;
            continue;
        }

        let region = MemoryRegion {
            base: region_base as u64,
            size: region_size,
            readable: true,
            writable,
            executable,
            kind,
        };

        stats.eligible += 1;
        if reader
            .read_region(
                region,
                |buf| {
                    let mut bytes_read = 0;
                    // SAFETY: `handle` is the live process handle opened above,
                    // `buf` is a writable buffer of exactly `buf.len()` bytes, and
                    // `bytes_read` outlives the call. A foreign address that cannot
                    // be read is reported as an error, never dereferenced here.
                    let result = unsafe {
                        ReadProcessMemory(
                            handle,
                            region_base as *const _,
                            buf.as_mut_ptr() as *mut _,
                            buf.len(),
                            Some(&mut bytes_read),
                        )
                    };
                    if result.is_err() || bytes_read == 0 {
                        stats.read_failed += 1;
                        tracing::trace!(
                            target: "scanner",
                            pid = pid,
                            base = format_args!("0x{:x}", region_base),
                            "YARA memory: ReadProcessMemory failed (normal for guard/exited process)"
                        );
                        None
                    } else {
                        Some(bytes_read)
                    }
                },
                &mut visitor,
            )
            .is_break()
        {
            break;
        }
    }

    // SAFETY: `handle` was opened above, is closed only here, and is not used
    // afterwards.
    unsafe {
        let _ = CloseHandle(handle);
    }

    tracing::debug!(
        target: "scanner",
        pid = pid,
        eligible = stats.eligible,
        excluded_protection = stats.excluded_protection,
        excluded_kind = stats.excluded_kind,
        read_failed = stats.read_failed,
        "YARA memory: region summary"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualProtect, MEM_RELEASE, MEM_RESERVE, PAGE_GUARD,
        PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };

    const PAGE_NOCACHE: u32 = 0x200;
    const PAGE_WRITECOMBINE: u32 = 0x400;

    fn scan_config() -> MemoryScanConfig {
        MemoryScanConfig {
            max_process_bytes: usize::MAX / 2,
            max_region_bytes: 1 << 20,
            include_private: true,
            include_image: false,
            include_mapped: false,
            delay_ms: 0,
        }
    }

    /// Whether a scanned chunk covers `page`. Matching by address avoids finding a copy of
    /// the marker on this test's own heap.
    fn page_is_scanned(page: usize) -> bool {
        let mut found = false;
        visit_process_memory_chunks(std::process::id(), &scan_config(), None, |chunk| {
            let start = chunk.base as usize;
            if (start..start + chunk.bytes.len()).contains(&page) {
                found = true;
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })
        .unwrap();
        found
    }

    /// Commit one private page, apply `protect`, and run `check` with the page address.
    fn with_page(protect: u32, check: impl FnOnce(usize)) {
        // SAFETY: the page is allocated, written within its 4096 bytes, and freed
        // here, and `check` only receives its address as an integer.
        unsafe {
            let page = VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            assert!(!page.is_null());
            std::ptr::write_bytes(page as *mut u8, 0x41, 4096);
            let mut old = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(page, 4096, PAGE_PROTECTION_FLAGS(protect), &mut old).unwrap();
            check(page as usize);
            let _ = VirtualFree(page, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn pages_with_modifier_bits_are_scanned() {
        for (name, protect) in [
            ("rw", 0x04),
            ("rw+nocache", 0x04 | PAGE_NOCACHE),
            ("rw+writecombine", 0x04 | PAGE_WRITECOMBINE),
            ("ro+nocache", 0x02 | PAGE_NOCACHE),
        ] {
            with_page(protect, |page| {
                assert!(page_is_scanned(page), "{name} page not scanned");
            });
        }
    }

    #[test]
    fn guard_and_no_access_pages_are_not_scanned() {
        for (name, protect) in [("guard", 0x04 | PAGE_GUARD.0), ("noaccess", 0x01)] {
            with_page(protect, |page| {
                assert!(!page_is_scanned(page), "{name} page was scanned");
            });
        }
    }
}
