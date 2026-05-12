use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig};
use anyhow::Result;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

fn is_readable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    matches!(
        protect,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

fn is_writable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    matches!(
        protect,
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

fn is_executable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    matches!(
        protect,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

pub fn read_process_memory_chunks(pid: u32, cfg: &MemoryScanConfig) -> Result<Vec<MemoryChunk>> {
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
            return Ok(Vec::new());
        }
    };

    let mut chunks = Vec::new();
    let mut address: usize = 0;
    let mut total_bytes: usize = 0;

    loop {
        if total_bytes >= cfg.max_process_bytes {
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

        let protect = mbi.Protect;
        if protect == PAGE_NOACCESS || protect.contains(PAGE_GUARD) || !is_readable(protect) {
            continue;
        }

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
            continue;
        }

        let read_size = region_size
            .min(cfg.max_region_bytes)
            .min(cfg.max_process_bytes - total_bytes);

        let mut buf = vec![0u8; read_size];
        let mut bytes_read: usize = 0;

        let ok = unsafe {
            ReadProcessMemory(
                handle,
                region_base as *const _,
                buf.as_mut_ptr() as *mut _,
                read_size,
                Some(&mut bytes_read),
            )
        };

        if ok.is_err() || bytes_read == 0 {
            tracing::trace!(
                target: "scanner",
                pid = pid,
                base = format_args!("0x{:x}", region_base),
                "YARA memory: ReadProcessMemory failed (normal for guard/exited process)"
            );
            continue;
        }

        buf.truncate(bytes_read);
        total_bytes += bytes_read;

        let region = MemoryRegion {
            base: region_base as u64,
            size: region_size,
            readable: true,
            writable: is_writable(protect),
            executable: is_executable(protect),
            kind,
        };

        chunks.push(MemoryChunk {
            base: region_base as u64,
            bytes: buf,
            region,
        });
    }

    unsafe {
        let _ = CloseHandle(handle);
    }

    Ok(chunks)
}
