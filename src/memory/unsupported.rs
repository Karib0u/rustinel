use super::{MemoryChunk, MemoryScanConfig};
use anyhow::Result;

pub fn read_process_memory_chunks(_pid: u32, _cfg: &MemoryScanConfig) -> Result<Vec<MemoryChunk>> {
    Ok(Vec::new())
}
