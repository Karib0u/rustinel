//! Seed metadata once, then require kernel birth-time reconciliation before use.

use super::events::task_identity_abi::{InventoryIdentity, INVENTORY_CAPACITY};
use crate::{
    state::{HostState, InventorySnapshot},
    utils::query_process_details,
};
use anyhow::{Context, Result};
use aya::{maps::HashMap, Ebpf};

unsafe impl aya::Pod for InventoryIdentity {}

pub fn seed(bpf: &mut Ebpf, host: &HostState) -> Result<()> {
    let started = std::time::Instant::now();
    let mut snapshot = InventorySnapshot::default();
    let result = seed_inner(bpf, host, &mut snapshot);
    snapshot.skipped = snapshot.scanned.saturating_sub(snapshot.seeded);
    snapshot.duration_ms = started.elapsed().as_millis() as u64;
    snapshot.error = result.as_ref().err().map(|error| format!("{error:#}"));
    host.record_inventory(snapshot);
    result
}

fn seed_inner(bpf: &mut Ebpf, host: &HostState, snapshot: &mut InventorySnapshot) -> Result<()> {
    let cache = &host.processes;
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
    let capacity = host.limits().processes.min(INVENTORY_CAPACITY as usize);
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
        snapshot.scanned += 1;
        if snapshot.seeded >= capacity {
            continue;
        }
        let Some(details) = query_process_details(pid) else {
            continue;
        };
        let (Some(start_ticks), Some(image)) = (details.start_time, details.image) else {
            continue;
        };
        let user = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Uid:"))
                    .and_then(|uids| uids.split_whitespace().nth(1))
                    .and_then(|uid| uid.parse::<u32>().ok())
            })
            .map(|uid| {
                host.users
                    .resolve_uid(uid)
                    .unwrap_or_else(|| uid.to_string())
            });
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
            user,
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
        snapshot.seeded += 1;
    }
    Ok(())
}
