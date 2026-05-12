/// Per-scan limits and region-type filters.
#[derive(Debug, Clone)]
pub struct MemoryScanConfig {
    /// Stop reading a process once this many bytes have been accumulated.
    pub max_process_bytes: usize,
    /// Clamp each region read to this many bytes.
    pub max_region_bytes: usize,
    pub include_private: bool,
    pub include_image: bool,
    pub include_mapped: bool,
    /// Milliseconds to wait before scanning (gives packers time to unpack).
    pub delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MemoryRegionKind {
    Private,
    Image,
    Mapped,
    Other,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: usize,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub kind: MemoryRegionKind,
}

#[derive(Debug)]
pub struct MemoryChunk {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub region: MemoryRegion,
}
