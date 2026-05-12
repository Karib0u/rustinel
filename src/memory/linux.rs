use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig};
use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

struct MapsEntry {
    start: u64,
    end: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    private: bool,
    path: Option<String>,
}

fn parse_maps_line(line: &str) -> Option<MapsEntry> {
    let mut parts = line.splitn(6, ' ');
    let addr_range = parts.next()?;
    let perms = parts.next()?;
    let _offset = parts.next()?;
    let _device = parts.next()?;
    let _inode = parts.next()?;
    let path = parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (start_str, end_str) = addr_range.split_once('-')?;
    let start = u64::from_str_radix(start_str, 16).ok()?;
    let end = u64::from_str_radix(end_str, 16).ok()?;

    let readable = perms.starts_with('r');
    let writable = perms.len() > 1 && perms.chars().nth(1) == Some('w');
    let executable = perms.len() > 2 && perms.chars().nth(2) == Some('x');
    let private = perms.len() > 3 && perms.chars().nth(3) == Some('p');

    Some(MapsEntry {
        start,
        end,
        readable,
        writable,
        executable,
        private,
        path,
    })
}

fn classify_region(path: Option<&str>) -> MemoryRegionKind {
    match path {
        None | Some("") => MemoryRegionKind::Private,
        Some(p) if p.starts_with('[') => MemoryRegionKind::Other,
        Some(_) => MemoryRegionKind::Mapped,
    }
}

pub fn read_process_memory_chunks(pid: u32, cfg: &MemoryScanConfig) -> Result<Vec<MemoryChunk>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let mem_path = format!("/proc/{}/mem", pid);

    let maps_content = match std::fs::read_to_string(&maps_path) {
        Ok(s) => s,
        Err(err) => {
            tracing::trace!(
                target: "scanner",
                pid = pid,
                error = %err,
                "YARA memory: cannot read /proc/<pid>/maps"
            );
            return Ok(Vec::new());
        }
    };

    let mut mem_file = match File::open(&mem_path) {
        Ok(f) => f,
        Err(err) => {
            tracing::trace!(
                target: "scanner",
                pid = pid,
                error = %err,
                "YARA memory: cannot open /proc/<pid>/mem"
            );
            return Ok(Vec::new());
        }
    };

    let mut chunks = Vec::new();
    let mut total_bytes: usize = 0;

    for line in maps_content.lines() {
        if total_bytes >= cfg.max_process_bytes {
            break;
        }

        let entry = match parse_maps_line(line) {
            Some(e) => e,
            None => continue,
        };

        if !entry.readable {
            continue;
        }

        let path_ref = entry.path.as_deref();
        if let Some(p) = path_ref {
            if matches!(p, "[vvar]" | "[vdso]" | "[vsyscall]") {
                continue;
            }
        }

        let kind = if entry.private && entry.path.is_none() {
            MemoryRegionKind::Private
        } else {
            classify_region(path_ref)
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

        let region_size = (entry.end - entry.start) as usize;
        let read_size = region_size
            .min(cfg.max_region_bytes)
            .min(cfg.max_process_bytes - total_bytes);

        if read_size == 0 {
            break;
        }

        if mem_file.seek(SeekFrom::Start(entry.start)).is_err() {
            continue;
        }

        let mut buf = vec![0u8; read_size];
        let bytes_read = match mem_file.read(&mut buf) {
            Ok(n) => n,
            Err(err) => {
                tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    base = format_args!("0x{:x}", entry.start),
                    error = %err,
                    "Unable to read memory region"
                );
                continue;
            }
        };

        if bytes_read == 0 {
            continue;
        }

        buf.truncate(bytes_read);
        total_bytes += bytes_read;

        let region = MemoryRegion {
            base: entry.start,
            size: region_size,
            readable: true,
            writable: entry.writable,
            executable: entry.executable,
            kind,
        };

        chunks.push(MemoryChunk {
            base: entry.start,
            bytes: buf,
            region,
        });
    }

    Ok(chunks)
}
