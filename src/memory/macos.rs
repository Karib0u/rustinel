//! macOS process-memory reader for YARA memory scanning.
//!
//! Uses Mach VM APIs to enumerate and read another process's memory:
//! `task_for_pid` to obtain the task port, `mach_vm_region` to walk regions,
//! and `mach_vm_read_overwrite` to copy region bytes. Regions are classified
//! by their backing file from `PROC_PIDREGIONPATHINFO` (the macOS analog of
//! `/proc/<pid>/maps`), and the dyld shared cache counts as library memory.
//!
//! `task_for_pid` is privileged: it requires root and, depending on the host,
//! SIP/AMFI relaxation or the appropriate entitlement. A denial is returned as
//! an error so the memory worker reports a failed scan rather than a clean one.

use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig, RegionReader};
use anyhow::Result;
use libproc::proc_pid::{pidinfo, PIDInfo, PidInfoFlavor};
use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_port::mach_port_deallocate;
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region};
use mach2::vm_prot::{vm_prot_t, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{vm_region_basic_info_data_64_t, vm_region_info_t, VM_REGION_BASIC_INFO_64};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use std::ops::{ControlFlow, Range};
use std::time::Instant;

/// Number of 32-bit words in `vm_region_basic_info_data_64_t`, as required by
/// `mach_vm_region`'s `info_count` argument.
fn basic_info_count() -> mach2::message::mach_msg_type_number_t {
    (std::mem::size_of::<vm_region_basic_info_data_64_t>() / std::mem::size_of::<i32>())
        as mach2::message::mach_msg_type_number_t
}

/// `struct proc_regionwithpathinfo` from `<sys/proc_info.h>`, keeping only
/// the fields read here. The layout is the same on arm64 and x86_64.
#[repr(C)]
struct RegionWithPathInfo {
    /// `pri_protection`, `pri_max_protection` and `pri_inheritance`.
    _protection: [u32; 3],
    /// `pri_flags`.
    flags: u32,
    /// `proc_regioninfo` fields between `pri_flags` and `pri_address`.
    _region_rest: [u32; 16],
    /// Start of the VM entry the kernel described.
    address: u64,
    size: u64,
    /// `vnode_info`, the stat of the backing file.
    _vnode_info: [u64; 19],
    /// NUL-terminated path of the backing file; empty for anonymous memory.
    path: [u8; 1024],
}

const _: () = assert!(std::mem::size_of::<RegionWithPathInfo>() == 1272);

/// `PROC_REGION_SUBMAP` from `<sys/proc_info.h>`: the entry maps a nested
/// submap, which is how the kernel maps the dyld shared cache.
const PROC_REGION_SUBMAP: u32 = 1;

impl PIDInfo for RegionWithPathInfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::RegionPathInfo
    }
}

/// One VM entry of the target, recorded before any memory is read.
struct VmEntry {
    address: mach_vm_address_t,
    size: mach_vm_size_t,
    protection: vm_prot_t,
    /// The entry maps a nested submap.
    submap: bool,
    /// File backing the entry; `None` for anonymous memory.
    filename: Option<String>,
}

/// Submap flag and backing file of the entry that contains `address`.
///
/// libproc's `proc_regionfilename` cannot be used: the kernel lookup behind
/// it walks forward to the next file-backed entry, so anonymous memory just
/// below a mapping (such as a malloc region next to dyld) takes that file's
/// name and is skipped as `Mapped`. `PROC_PIDREGIONPATHINFO` describes the
/// entry itself, and its range is checked because an address in a hole is
/// answered with the following entry.
fn region_details(pid: u32, address: mach_vm_address_t) -> (bool, Option<String>) {
    let Ok(info) = pidinfo::<RegionWithPathInfo>(pid as i32, address) else {
        return (false, None);
    };
    if !region_contains(info.address, info.size, address) {
        return (false, None);
    }
    let len = info
        .path
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(info.path.len());
    let filename = (len > 0).then(|| String::from_utf8_lossy(&info.path[..len]).into_owned());
    (info.flags & PROC_REGION_SUBMAP != 0, filename)
}

fn region_contains(start: u64, size: u64, address: u64) -> bool {
    address >= start && address - start < size
}

/// Address ranges of the dyld shared cache: contiguous runs of entries that
/// start and end with a submap.
///
/// Only part of the cache is mapped as submaps. Its slid `__DATA` and
/// `__LINKEDIT` pieces sit between them as anonymous copy-on-write entries
/// with no path, which would otherwise count as private memory and use up the
/// scan budget before the malloc regions above the cache. A gap ends a run,
/// so the heap between two separate shared regions is never included.
fn shared_cache_ranges(entries: &[VmEntry]) -> Vec<Range<u64>> {
    let mut ranges = Vec::new();
    let mut current: Option<Range<u64>> = None;
    let mut previous_end = None;
    for entry in entries {
        if previous_end != Some(entry.address) {
            ranges.extend(current.take());
        }
        let end = entry.address.saturating_add(entry.size);
        if entry.submap {
            match &mut current {
                Some(range) => range.end = end,
                None => current = Some(entry.address..end),
            }
        }
        previous_end = Some(end);
    }
    ranges.extend(current);
    ranges
}

/// Shared-cache memory is library memory, like a file-backed dylib.
fn classify(filename: Option<&str>, executable: bool, shared_cache: bool) -> MemoryRegionKind {
    match filename {
        None if !shared_cache => MemoryRegionKind::Private,
        _ if executable => MemoryRegionKind::Image,
        _ => MemoryRegionKind::Mapped,
    }
}

/// Every VM entry of `task` in ascending address order.
fn vm_entries(task: mach_port_t, pid: u32) -> Vec<VmEntry> {
    let mut entries = Vec::new();
    let mut address: mach_vm_address_t = 0;
    loop {
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

        let (submap, filename) = region_details(pid, address);
        entries.push(VmEntry {
            address,
            size,
            protection: info.protection,
            submap,
            filename,
        });

        // Advance past this region; stop on overflow.
        address = match address.checked_add(size) {
            Some(next) => next,
            None => break,
        };
    }
    entries
}

pub fn visit_process_memory_chunks(
    pid: u32,
    cfg: &MemoryScanConfig,
    deadline: Option<Instant>,
    mut visitor: impl FnMut(&MemoryChunk) -> ControlFlow<()>,
) -> Result<()> {
    let mut task: mach_port_t = MACH_PORT_NULL;
    let kr = unsafe { task_for_pid(mach_task_self(), pid as i32, &mut task) };
    if kr != KERN_SUCCESS {
        anyhow::bail!(
            "task_for_pid failed for pid {pid} with kernel error {kr}; memory access may require root and SIP/AMFI relaxation"
        );
    }

    let entries = vm_entries(task, pid);
    let shared_cache = shared_cache_ranges(&entries);
    let mut reader = RegionReader::new(cfg, deadline);

    for entry in &entries {
        if reader.is_done() {
            break;
        }
        if entry.protection & VM_PROT_READ == 0 {
            continue;
        }
        let executable = entry.protection & VM_PROT_EXECUTE != 0;
        let writable = entry.protection & VM_PROT_WRITE != 0;
        let in_shared_cache = shared_cache
            .iter()
            .any(|range| range.contains(&entry.address));
        let kind = classify(entry.filename.as_deref(), executable, in_shared_cache);

        let include = match kind {
            MemoryRegionKind::Private => cfg.include_private,
            MemoryRegionKind::Image => cfg.include_image,
            MemoryRegionKind::Mapped => cfg.include_mapped,
            MemoryRegionKind::Other => false,
        };
        if !include {
            continue;
        }

        let address = entry.address;
        let region = MemoryRegion {
            base: address,
            size: entry.size as usize,
            readable: true,
            writable,
            executable,
            kind,
        };
        if reader
            .read_region(region, |buf| read_region(task, address, buf), &mut visitor)
            .is_break()
        {
            break;
        }
    }

    unsafe {
        let _ = mach_port_deallocate(mach_task_self(), task);
    }

    Ok(())
}

/// Read into the region buffer at `address`. Returns `None` on failure.
fn read_region(task: mach_port_t, address: mach_vm_address_t, buf: &mut [u8]) -> Option<usize> {
    let mut out_size: mach_vm_size_t = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(
            task,
            address,
            buf.len() as mach_vm_size_t,
            buf.as_mut_ptr() as mach_vm_address_t,
            &mut out_size,
        )
    };
    if kr != KERN_SUCCESS || out_size == 0 {
        return None;
    }
    Some(out_size as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_region_by_filename_and_protection() {
        assert_eq!(classify(None, false, false), MemoryRegionKind::Private);
        assert_eq!(classify(None, true, false), MemoryRegionKind::Private);
        assert_eq!(
            classify(Some("/usr/lib/dyld"), true, false),
            MemoryRegionKind::Image
        );
        assert_eq!(
            classify(Some("/Users/a/file.dat"), false, false),
            MemoryRegionKind::Mapped
        );
    }

    #[test]
    fn shared_cache_memory_is_library_memory() {
        assert_eq!(classify(None, true, true), MemoryRegionKind::Image);
        assert_eq!(classify(None, false, true), MemoryRegionKind::Mapped);
    }

    fn entry(address: u64, size: u64, submap: bool) -> VmEntry {
        VmEntry {
            address,
            size,
            protection: VM_PROT_READ,
            submap,
            filename: None,
        }
    }

    #[test]
    fn shared_cache_spans_contiguous_runs_between_submaps() {
        let entries = [
            entry(0x1000, 0x1000, false),
            // A run: submap, copy-on-write pieces, submap, trailing piece.
            entry(0x2000, 0x1000, true),
            entry(0x3000, 0x1000, false),
            entry(0x4000, 0x1000, false),
            entry(0x5000, 0x1000, true),
            entry(0x6000, 0x1000, false),
            // A gap ends the run, even with a later submap.
            entry(0x9000, 0x1000, false),
            entry(0xa000, 0x1000, true),
        ];
        assert_eq!(
            shared_cache_ranges(&entries),
            vec![0x2000..0x6000, 0xa000..0xb000]
        );
        assert!(shared_cache_ranges(&[entry(0x1000, 0x1000, false)]).is_empty());
    }

    /// The live shared cache must be found, and heap memory kept out of it.
    #[test]
    fn own_shared_cache_is_found_and_excludes_the_heap() {
        let heap = vec![0u8; 256 * 1024];
        let task = unsafe { mach_task_self() };
        let entries = vm_entries(task, std::process::id());
        let ranges = shared_cache_ranges(&entries);
        let in_cache = |address: u64| ranges.iter().any(|range| range.contains(&address));

        assert!(
            in_cache(libc::getpid as *const () as u64),
            "libsystem code should be in the shared cache: {ranges:x?}"
        );
        assert!(!in_cache(heap.as_ptr() as u64), "heap is not shared cache");
        assert!(
            !in_cache(&ranges as *const _ as u64),
            "stack is not shared cache"
        );
    }

    #[test]
    fn region_range_is_half_open() {
        assert!(region_contains(0x1000, 0x1000, 0x1000));
        assert!(region_contains(0x1000, 0x1000, 0x1fff));
        assert!(!region_contains(0x1000, 0x1000, 0x2000));
        assert!(!region_contains(0x1000, 0x1000, 0xfff));
        assert!(!region_contains(0x1000, 0, 0x1000));
    }

    /// Anonymous memory directly below a file mapping must stay private:
    /// `proc_regionfilename` names it after the file, which hid malloc
    /// regions next to dyld from memory scans.
    #[test]
    fn anonymous_region_below_a_file_mapping_has_no_filename() {
        use std::os::fd::AsRawFd;

        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let file = tempfile::NamedTempFile::new().expect("temp file");
        file.as_file().set_len(page as u64).expect("size temp file");

        // Reserve two pages, then map the file over the upper one so the
        // anonymous page sits immediately below it.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "anonymous mmap failed");
        let upper = unsafe { base.cast::<u8>().add(page) }.cast::<libc::c_void>();
        let mapped = unsafe {
            libc::mmap(
                upper,
                page,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_FIXED,
                file.as_file().as_raw_fd(),
                0,
            )
        };
        assert_eq!(mapped, upper, "file mmap failed");

        let pid = std::process::id();
        let (_, anonymous) = region_details(pid, base as u64);
        let (_, file_backed) = region_details(pid, upper as u64);
        unsafe { libc::munmap(base, 2 * page) };

        assert_eq!(anonymous, None);
        let file_name = file.path().file_name().unwrap().to_string_lossy();
        assert!(
            file_backed
                .as_deref()
                .is_some_and(|path| path.ends_with(&*file_name)),
            "file mapping should report its path, got {file_backed:?}"
        );
    }

    #[test]
    fn read_nonexistent_pid_reports_failure() {
        let cfg = MemoryScanConfig {
            max_process_bytes: 1024,
            max_region_bytes: 512,
            include_private: true,
            include_image: true,
            include_mapped: true,
            delay_ms: 0,
        };
        let result = super::super::read_process_memory_chunks(99_999_999, &cfg);
        let error = result.expect_err("task_for_pid should reject a nonexistent process");
        assert!(error.to_string().contains("task_for_pid failed"));
    }
}
