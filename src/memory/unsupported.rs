use super::{MemoryChunk, MemoryScanConfig};
use anyhow::Result;
use std::ops::ControlFlow;
use std::time::Instant;

pub fn visit_process_memory_chunks(
    _pid: u32,
    _cfg: &MemoryScanConfig,
    _deadline: Option<Instant>,
    _visitor: impl FnMut(&MemoryChunk) -> ControlFlow<()>,
) -> Result<()> {
    Ok(())
}
