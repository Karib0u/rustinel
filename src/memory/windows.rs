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
