//! macOS process-memory reader for YARA memory scanning.
//!
//! Uses Mach VM APIs to enumerate and read another process's memory:
//! `task_for_pid` to obtain the task port, `mach_vm_region` to walk regions,
//! and `mach_vm_read_overwrite` to copy region bytes. Regions are classified
//! with libproc's `regionfilename` (the macOS analog of `/proc/<pid>/maps`).
//!
//! `task_for_pid` is privileged: it requires root and, depending on the host,
//! SIP/AMFI relaxation or the appropriate entitlement. When it is denied this
//! returns an empty result, exactly like the Linux reader does on permission
//! errors, so memory scanning simply yields nothing rather than failing.

use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig};
use anyhow::Result;
use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_port::mach_port_deallocate;
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region};
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{vm_region_basic_info_data_64_t, vm_region_info_t, VM_REGION_BASIC_INFO_64};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

/// Number of 32-bit words in `vm_region_basic_info_data_64_t`, as required by
/// `mach_vm_region`'s `info_count` argument.
fn basic_info_count() -> mach2::message::mach_msg_type_number_t {
    (std::mem::size_of::<vm_region_basic_info_data_64_t>() / std::mem::size_of::<i32>())
        as mach2::message::mach_msg_type_number_t
}

fn classify(filename: Option<&str>, executable: bool) -> MemoryRegionKind {
    match filename {
        None => MemoryRegionKind::Private,
        Some(_) if executable => MemoryRegionKind::Image,
        Some(_) => MemoryRegionKind::Mapped,
    }
}

pub fn read_process_memory_chunks(pid: u32, cfg: &MemoryScanConfig) -> Result<Vec<MemoryChunk>> {
    let mut task: mach_port_t = MACH_PORT_NULL;
    let kr = unsafe { task_for_pid(mach_task_self(), pid as i32, &mut task) };
    if kr != KERN_SUCCESS {
        tracing::trace!(
            target: "scanner",
            pid = pid,
            kr = kr,
            "YARA memory: task_for_pid denied (needs root and SIP/entitlement)"
        );
        return Ok(Vec::new());
    }

    let mut chunks = Vec::new();
    let mut total_bytes: usize = 0;
    let mut address: mach_vm_address_t = 0;

    while total_bytes < cfg.max_process_bytes {
        let mut size: mach_vm_size_t = 0;
        let mut info = vm_region_basic_info_data_64_t::default();
        let mut info_count = basic_info_count();
        let mut object_name: mach_port_t = MACH_PORT_NULL;

        let kr = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                (&mut info as *mut vm_region_basic_info_data_64_t).cast::<i32>()
                    as vm_region_info_t,
                &mut info_count,
                &mut object_name,
            )
        };
        // mach_vm_region hands back a send right to the region's named memory
        // object, which we don't use. Release it so the loop does not leak a
        // Mach port per region (this can run over many regions and repeatedly
        // when memory scanning is enabled). On failure it stays MACH_PORT_NULL.
        if object_name != MACH_PORT_NULL {
            unsafe {
                let _ = mach_port_deallocate(mach_task_self(), object_name);
            }
        }
        // A non-success return marks the end of the address space.
        if kr != KERN_SUCCESS || size == 0 {
            break;
        }

        let readable = info.protection & VM_PROT_READ != 0;
        let executable = info.protection & VM_PROT_EXECUTE != 0;
        let writable = info.protection & VM_PROT_WRITE != 0;

        if readable {
            let filename = libproc::proc_pid::regionfilename(pid as i32, address)
                .ok()
                .filter(|name| !name.is_empty());
            let kind = classify(filename.as_deref(), executable);

            let include = match kind {
                MemoryRegionKind::Private => cfg.include_private,
                MemoryRegionKind::Image => cfg.include_image,
                MemoryRegionKind::Mapped => cfg.include_mapped,
                MemoryRegionKind::Other => false,
            };

            if include {
                let region_size = size as usize;
                let read_size = region_size
                    .min(cfg.max_region_bytes)
                    .min(cfg.max_process_bytes - total_bytes);

                if read_size > 0 {
                    if let Some(bytes) = read_region(task, address, read_size) {
                        total_bytes += bytes.len();
                        let region = MemoryRegion {
                            base: address,
                            size: region_size,
                            readable: true,
                            writable,
                            executable,
                            kind,
                        };
                        chunks.push(MemoryChunk {
                            base: address,
                            bytes,
                            region,
                        });
                    }
                }
            }
        }

        // Advance past this region; stop on overflow.
        address = match address.checked_add(size) {
            Some(next) => next,
            None => break,
        };
    }

    unsafe {
        let _ = mach_port_deallocate(mach_task_self(), task);
    }

    Ok(chunks)
}

/// Read up to `len` bytes at `address` from `task`. Returns `None` on failure.
fn read_region(task: mach_port_t, address: mach_vm_address_t, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut out_size: mach_vm_size_t = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(
            task,
            address,
            len as mach_vm_size_t,
            buf.as_mut_ptr() as mach_vm_address_t,
            &mut out_size,
        )
    };
    if kr != KERN_SUCCESS || out_size == 0 {
        return None;
    }
    buf.truncate(out_size as usize);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_region_by_filename_and_protection() {
        assert_eq!(classify(None, false), MemoryRegionKind::Private);
        assert_eq!(classify(None, true), MemoryRegionKind::Private);
        assert_eq!(
            classify(Some("/usr/lib/dyld"), true),
            MemoryRegionKind::Image
        );
        assert_eq!(
            classify(Some("/Users/a/file.dat"), false),
            MemoryRegionKind::Mapped
        );
    }

    #[test]
    fn read_nonexistent_pid_returns_empty() {
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
