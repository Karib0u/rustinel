use super::{MemoryChunk, MemoryRegion, MemoryRegionKind, MemoryScanConfig, RegionReader};
use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::ops::ControlFlow;
use std::time::Instant;

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
        None | Some("" | "[heap]" | "[stack]") => MemoryRegionKind::Private,
        Some(p) if p.starts_with('[') => MemoryRegionKind::Other,
        Some(_) => MemoryRegionKind::Mapped,
    }
}

pub fn visit_process_memory_chunks(
    pid: u32,
    cfg: &MemoryScanConfig,
    deadline: Option<Instant>,
    mut visitor: impl FnMut(&MemoryChunk) -> ControlFlow<()>,
) -> Result<()> {
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
            return Ok(());
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
            return Ok(());
        }
    };

    let mut reader = RegionReader::new(cfg, deadline);

    for line in maps_content.lines() {
        if reader.is_done() {
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
        let region = MemoryRegion {
            base: entry.start,
            size: region_size,
            readable: true,
            writable: entry.writable,
            executable: entry.executable,
            kind,
        };

        if reader
            .read_region(
                region,
                |buf| {
                    mem_file.seek(SeekFrom::Start(entry.start)).ok()?;
                    match mem_file.read(buf) {
                        Ok(bytes_read) => Some(bytes_read),
                        Err(err) => {
                            tracing::trace!(
                                target: "scanner",
                                pid = pid,
                                base = format_args!("0x{:x}", entry.start),
                                error = %err,
                                "Unable to read memory region"
                            );
                            None
                        }
                    }
                },
                &mut visitor,
            )
            .is_break()
        {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_line_preserves_addresses_permissions_and_path() {
        let entry = parse_maps_line(
            "00400000-00452000 r-xp 00000000 08:02 123456   /tmp/program with spaces (deleted)",
        )
        .expect("valid file mapping");
        assert_eq!(entry.start, 0x00400000);
        assert_eq!(entry.end, 0x00452000);
        assert!(entry.readable);
        assert!(!entry.writable);
        assert!(entry.executable);
        assert!(entry.private);
        assert_eq!(
            entry.path.as_deref(),
            Some("/tmp/program with spaces (deleted)")
        );
    }

    #[test]
    fn parse_maps_line_handles_anonymous_and_named_mappings() {
        for (suffix, expected_path) in [
            ("", None),
            ("   ", None),
            ("   [heap]", Some("[heap]")),
            ("   [stack]", Some("[stack]")),
            ("   [vdso]", Some("[vdso]")),
        ] {
            let line = format!("7f000000-7f002000 rw-p 00000000 00:00 0{suffix}");
            let entry = parse_maps_line(&line).expect("valid anonymous mapping");
            assert_eq!(entry.start, 0x7f000000);
            assert_eq!(entry.end, 0x7f002000);
            assert!(entry.readable);
            assert!(entry.writable);
            assert!(!entry.executable);
            assert!(entry.private);
            assert_eq!(entry.path.as_deref(), expected_path);
        }
    }

    #[test]
    fn parse_maps_line_handles_shared_and_unreadable_mappings() {
        let shared = parse_maps_line("1000-2000 rw-s 00000000 00:01 1 /dev/shm/data")
            .expect("valid shared mapping");
        assert!(shared.readable);
        assert!(shared.writable);
        assert!(!shared.executable);
        assert!(!shared.private);
        assert_eq!(shared.path.as_deref(), Some("/dev/shm/data"));

        let unreadable =
            parse_maps_line("2000-3000 ---p 00000000 00:00 0").expect("valid unreadable mapping");
        assert!(!unreadable.readable);
        assert!(!unreadable.writable);
        assert!(!unreadable.executable);
        assert!(unreadable.private);
    }

    #[test]
    fn parse_maps_line_rejects_missing_fields_and_invalid_addresses() {
        for line in [
            "",
            "1000-2000 rw-p 00000000 00:00",
            "1000 rw-p 00000000 00:00 0",
            "invalid-2000 rw-p 00000000 00:00 0",
            "1000-invalid rw-p 00000000 00:00 0",
            "10000000000000000-2000 rw-p 00000000 00:00 0",
        ] {
            assert!(
                parse_maps_line(line).is_none(),
                "accepted invalid maps line: {line}"
            );
        }
    }

    #[test]
    fn classify_region_includes_heap_and_stack_as_private() {
        for path in [None, Some(""), Some("[heap]"), Some("[stack]")] {
            assert_eq!(classify_region(path), MemoryRegionKind::Private);
        }
        for path in ["/usr/bin/program", "/tmp/data with spaces", "/dev/shm/data"] {
            assert_eq!(classify_region(Some(path)), MemoryRegionKind::Mapped);
        }
        for path in [
            "[vdso]",
            "[vvar]",
            "[vvar_vclock]",
            "[vsyscall]",
            "[unknown]",
        ] {
            assert_eq!(classify_region(Some(path)), MemoryRegionKind::Other);
        }
    }

    #[test]
    fn private_filter_controls_live_heap_and_stack_reads() {
        let pid = std::process::id();
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        let mut cfg = MemoryScanConfig {
            max_process_bytes: 1024 * 1024,
            max_region_bytes: 1,
            include_private: true,
            include_image: false,
            include_mapped: false,
            delay_ms: 0,
        };
        // One byte per region keeps every mapping within the process budget.
        let chunks = super::super::read_process_memory_chunks(pid, &cfg).unwrap();
        for path in ["[heap]", "[stack]"] {
            let entry = maps
                .lines()
                .filter_map(parse_maps_line)
                .find(|entry| entry.path.as_deref() == Some(path))
                .unwrap_or_else(|| panic!("missing {path} mapping"));
            let chunk = chunks
                .iter()
                .find(|chunk| chunk.base == entry.start)
                .unwrap_or_else(|| panic!("did not read {path} mapping"));
            assert_eq!(chunk.region.kind, MemoryRegionKind::Private);
            assert_eq!(chunk.bytes.len(), 1);
        }

        cfg.include_private = false;
        assert!(super::super::read_process_memory_chunks(pid, &cfg)
            .unwrap()
            .is_empty());
    }
}
