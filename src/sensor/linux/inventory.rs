//! Seed metadata once, then require kernel birth-time reconciliation before use.

use super::events::task_identity_abi::{InventoryIdentity, INVENTORY_CAPACITY};
use crate::{state::ProcessCache, utils::query_process_details};
use anyhow::{Context, Result};
use aya::{maps::HashMap, Ebpf};

unsafe impl aya::Pod for InventoryIdentity {}

pub fn seed(bpf: &mut Ebpf, cache: &ProcessCache) -> Result<()> {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    anyhow::ensure!(
        hz > 0 && hz <= 1_000_000,
        "unsupported proc clock frequency"
    );
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    anyhow::ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } == 0,
        "reading boot clock"
    );
    let identity_time = now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64;
    let mut inventory = HashMap::<_, u32, InventoryIdentity>::try_from(
        bpf.map_mut("PROCESS_INVENTORY")
            .context("missing process inventory map")?,
    )?;
    let mut count = 0;
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(details) = query_process_details(pid) else {
            continue;
        };
        let (Some(start_ticks), Some(image)) = (details.start_time, details.image) else {
            continue;
        };
        // A PID that changed lifetime while reading metadata cannot seed the cache.
        let current = crate::utils::query_process_identity(pid);
        if !current.is_some_and(|current| {
            current.start_time == Some(start_ticks) && current.image == image
        }) {
            continue;
        }
        let row = InventoryIdentity {
            start_ticks,
            clock_ticks_per_second: hz as u64,
            identity_time,
        };
        inventory.insert(pid, row, 0)?;
        cache.add(
            pid,
            identity_time,
            image,
            details.command_line,
            None,
            details.parent_process_id,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            details.current_directory,
            None,
        );
        count += 1;
        if count == INVENTORY_CAPACITY {
            break;
        }
    }
    tracing::info!(
        count,
        "startup process inventory awaits kernel birth-time reconciliation"
    );
    Ok(())
}
