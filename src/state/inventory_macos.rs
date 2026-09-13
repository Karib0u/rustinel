use super::{HostState, InventorySnapshot};
use libproc::{
    bsd_info::BSDInfo,
    proc_pid::pidinfo,
    processes::{pids_by_type, ProcFilter},
};

impl HostState {
    pub(super) fn inventory_macos(&self) {
        let started = std::time::Instant::now();
        let mut snapshot = InventorySnapshot::default();
        match pids_by_type(ProcFilter::All) {
            Err(error) => snapshot.error = Some(error.to_string()),
            Ok(pids) => {
                for pid in pids.into_iter().filter(|pid| *pid != 0) {
                    snapshot.scanned += 1;
                    if snapshot.seeded >= self.limits().processes {
                        continue;
                    }
                    let Some(identity) = crate::utils::query_process_identity(pid) else {
                        continue;
                    };
                    let Some(start_time) = identity.start_time else {
                        continue;
                    };
                    let Ok(info) = pidinfo::<BSDInfo>(pid as i32, 0) else {
                        continue;
                    };
                    let command_line = crate::utils::query_process_command_line(pid);
                    let user = self
                        .users
                        .resolve_uid(info.pbi_uid)
                        .or_else(|| Some(info.pbi_uid.to_string()));
                    // Re-read after metadata to reject a PID that changed lifetime or image.
                    if !crate::utils::query_process_identity(pid).is_some_and(|current| {
                        current.start_time == Some(start_time) && current.image == identity.image
                    }) {
                        continue;
                    }
                    self.processes.add(
                        pid,
                        start_time,
                        identity.image,
                        command_line,
                        user,
                        Some(info.pbi_ppid),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                    snapshot.seeded += 1;
                }
            }
        }
        snapshot.skipped = snapshot.scanned - snapshot.seeded;
        snapshot.duration_ms = started.elapsed().as_millis() as u64;
        self.record_inventory(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_seeds_current_process_with_endpoint_security_identity() {
        let state = HostState::default();
        state.inventory_macos();
        let pid = std::process::id();
        let identity = crate::utils::query_process_identity(pid).unwrap();
        let metadata = state
            .processes
            .get_metadata_by_key(pid, identity.start_time.unwrap())
            .unwrap();
        assert_eq!(metadata.image_name, identity.image);
        let snapshot = state.snapshot().inventory.unwrap();
        assert!(snapshot.seeded > 0);
        assert_eq!(snapshot.scanned, snapshot.seeded + snapshot.skipped);
    }
}
