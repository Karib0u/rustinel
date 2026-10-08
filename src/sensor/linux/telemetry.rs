//! Linux eBPF sensor accounting.
//!
//! Owned by [`super::LinuxHostExtension`], so each runtime counts its own
//! rings and hooks.
//! The snapshot types live in `crate::telemetry` and are shared by every
//! platform, because `rustinel doctor` reads them on any host.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use super::abi::LINUX_EBPF_ABI_VERSION;
use crate::telemetry::{LinuxEbpfFamilySnapshot, LinuxEbpfFeatureSnapshot, LinuxEbpfSnapshot};

/// Linux ring-buffer program families, in snapshot order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxEbpfFamily {
    Process,
    Network,
    File,
    Dns,
}

impl LinuxEbpfFamily {
    pub const ALL: [Self; 4] = [Self::Process, Self::Network, Self::File, Self::Dns];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Network => "network",
            Self::File => "file",
            Self::Dns => "dns",
        }
    }

    pub const fn index(self) -> usize {
        match self {
            Self::Process => 0,
            Self::Network => 1,
            Self::File => 2,
            Self::Dns => 3,
        }
    }
}

/// Aggregated kernel counters copied from one per-CPU eBPF map row.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinuxEbpfKernelSample {
    pub kernel_seen: u64,
    pub kernel_submitted: u64,
    pub kernel_ring_full: u64,
    pub kernel_oversized: u64,
    pub kernel_map_full: u64,
}

#[derive(Debug, Default)]
struct LinuxEbpfFamilyCounters {
    kernel_seen: AtomicU64,
    kernel_submitted: AtomicU64,
    kernel_ring_full: AtomicU64,
    kernel_oversized: AtomicU64,
    kernel_map_full: AtomicU64,
    userspace_received: AtomicU64,
    userspace_decoded: AtomicU64,
    short_reads: AtomicU64,
    userspace_internal: AtomicU64,
    canonical_emitted: AtomicU64,
    userspace_dropped: AtomicU64,
    unresolved_file_events: AtomicU64,
}

impl LinuxEbpfFamilyCounters {
    const fn new() -> Self {
        Self {
            kernel_seen: AtomicU64::new(0),
            kernel_submitted: AtomicU64::new(0),
            kernel_ring_full: AtomicU64::new(0),
            kernel_oversized: AtomicU64::new(0),
            kernel_map_full: AtomicU64::new(0),
            userspace_received: AtomicU64::new(0),
            userspace_decoded: AtomicU64::new(0),
            short_reads: AtomicU64::new(0),
            userspace_internal: AtomicU64::new(0),
            canonical_emitted: AtomicU64::new(0),
            userspace_dropped: AtomicU64::new(0),
            unresolved_file_events: AtomicU64::new(0),
        }
    }
}

/// End-to-end Linux eBPF accounting.
#[derive(Debug)]
pub struct LinuxEbpfCounters {
    active: AtomicBool,
    families: [LinuxEbpfFamilyCounters; 4],
    features: Mutex<Vec<LinuxEbpfFeatureSnapshot>>,
}

impl LinuxEbpfCounters {
    pub(crate) const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            families: [
                LinuxEbpfFamilyCounters::new(),
                LinuxEbpfFamilyCounters::new(),
                LinuxEbpfFamilyCounters::new(),
                LinuxEbpfFamilyCounters::new(),
            ],
            features: Mutex::new(Vec::new()),
        }
    }

    pub fn activate(&self) {
        let mut features = self
            .features
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for feature in &mut *features {
            feature.active = linux_feature_is_active(feature);
        }
        self.active.store(true, Ordering::Release);
    }

    /// Record one attempted hook so snapshots expose both active coverage and
    /// named, family-local degradation.
    pub fn record_hook(
        &self,
        feature: &str,
        hook: &str,
        attached: bool,
        unavailable_reason: Option<&str>,
    ) {
        let mut features = self
            .features
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = match features.iter_mut().find(|state| state.feature == feature) {
            Some(state) => state,
            None => {
                features.push(LinuxEbpfFeatureSnapshot {
                    feature: feature.to_string(),
                    active: false,
                    attached_hooks: Vec::new(),
                    unavailable_hooks: Vec::new(),
                });
                features.last_mut().expect("feature was just inserted")
            }
        };
        if attached {
            state.attached_hooks.push(hook.to_string());
        } else {
            let reason = unavailable_reason.unwrap_or("unavailable");
            state.unavailable_hooks.push(format!("{hook}: {reason}"));
        }
    }

    pub fn set_kernel_sample(&self, family: LinuxEbpfFamily, sample: LinuxEbpfKernelSample) {
        let counters = &self.families[family.index()];
        counters
            .kernel_seen
            .store(sample.kernel_seen, Ordering::Relaxed);
        counters
            .kernel_submitted
            .store(sample.kernel_submitted, Ordering::Relaxed);
        counters
            .kernel_ring_full
            .store(sample.kernel_ring_full, Ordering::Relaxed);
        counters
            .kernel_oversized
            .store(sample.kernel_oversized, Ordering::Relaxed);
        counters
            .kernel_map_full
            .store(sample.kernel_map_full, Ordering::Relaxed);
    }

    pub fn record_received(&self, family: LinuxEbpfFamily) {
        self.families[family.index()]
            .userspace_received
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_decoded(&self, family: LinuxEbpfFamily) {
        self.families[family.index()]
            .userspace_decoded
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_short_read(&self, family: LinuxEbpfFamily) {
        self.families[family.index()]
            .short_reads
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_emitted(&self, family: LinuxEbpfFamily) {
        self.families[family.index()]
            .canonical_emitted
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_internal(&self, family: LinuxEbpfFamily) {
        self.families[family.index()]
            .userspace_internal
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped(&self, family: LinuxEbpfFamily) {
        self.families[family.index()]
            .userspace_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_unresolved_file(&self) {
        let counters = &self.families[LinuxEbpfFamily::File.index()];
        counters.userspace_dropped.fetch_add(1, Ordering::Relaxed);
        counters
            .unresolved_file_events
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Option<LinuxEbpfSnapshot> {
        if !self.active.load(Ordering::Acquire) {
            return None;
        }

        Some(LinuxEbpfSnapshot {
            abi_version: LINUX_EBPF_ABI_VERSION,
            features: self
                .features
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            families: LinuxEbpfFamily::ALL
                .into_iter()
                .map(|family| {
                    let counters = &self.families[family.index()];
                    let kernel_submitted = counters.kernel_submitted.load(Ordering::Relaxed);
                    let userspace_received = counters.userspace_received.load(Ordering::Relaxed);
                    LinuxEbpfFamilySnapshot {
                        ring: family.as_str().to_string(),
                        kernel_seen: counters.kernel_seen.load(Ordering::Relaxed),
                        kernel_submitted,
                        kernel_ring_full: counters.kernel_ring_full.load(Ordering::Relaxed),
                        kernel_oversized: counters.kernel_oversized.load(Ordering::Relaxed),
                        kernel_map_full: counters.kernel_map_full.load(Ordering::Relaxed),
                        userspace_received,
                        userspace_decoded: counters.userspace_decoded.load(Ordering::Relaxed),
                        short_reads: counters.short_reads.load(Ordering::Relaxed),
                        userspace_internal: counters.userspace_internal.load(Ordering::Relaxed),
                        canonical_emitted: counters.canonical_emitted.load(Ordering::Relaxed),
                        userspace_dropped: counters.userspace_dropped.load(Ordering::Relaxed),
                        unresolved_file_events: counters
                            .unresolved_file_events
                            .load(Ordering::Relaxed),
                        in_flight: kernel_submitted.saturating_sub(userspace_received),
                    }
                })
                .collect(),
        })
    }
}

fn linux_feature_is_active(feature: &LinuxEbpfFeatureSnapshot) -> bool {
    let attached = |hook: &str| feature.attached_hooks.iter().any(|value| value == hook);
    match feature.feature.as_str() {
        "process" => attached("handle_exec"),
        "network" => {
            (attached("handle_connect") && attached("handle_connect_exit"))
                || (attached("handle_stream_connect") && attached("handle_dgram_connect"))
        }
        "network_tuple" => {
            attached("handle_stream_connect")
                && attached("handle_dgram_connect")
                && (attached("handle_accept2") || attached("handle_accept4"))
        }
        "dns" => ["handle_sendto", "handle_sendmsg", "handle_sendmmsg"]
            .into_iter()
            .any(attached),
        "file" => [
            ("handle_openat", "handle_openat_exit"),
            ("handle_open", "handle_open_exit"),
            ("handle_creat", "handle_creat_exit"),
            ("handle_openat2", "handle_openat2_exit"),
            ("handle_unlinkat", "handle_unlinkat_exit"),
            ("handle_unlink", "handle_unlink_exit"),
            ("handle_renameat", "handle_renameat_exit"),
            ("handle_renameat2", "handle_renameat2_exit"),
            ("handle_rename", "handle_rename_exit"),
            ("handle_mkdir", "handle_mkdir_exit"),
            ("handle_mkdirat", "handle_mkdirat_exit"),
            ("handle_rmdir", "handle_rmdir_exit"),
        ]
        .into_iter()
        .any(|(entry, exit)| attached(entry) && attached(exit)),
        "file_identity" => {
            attached("open_fd")
                && (attached("handle_vfs_unlink_identity1")
                    || attached("handle_vfs_unlink_identity2"))
                && (attached("handle_vfs_rmdir_identity1")
                    || attached("handle_vfs_rmdir_identity2"))
                && (attached("handle_vfs_mkdir_identity1")
                    || attached("handle_vfs_mkdir_identity2"))
                && attached("handle_vfs_mkdir_identity_exit")
                && attached("handle_vfs_rename_identity")
        }
        _ => false,
    }
}

impl Default for LinuxEbpfCounters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_feature(feature: &str, hooks: &[&str]) -> LinuxEbpfFeatureSnapshot {
        LinuxEbpfFeatureSnapshot {
            feature: feature.to_string(),
            active: false,
            attached_hooks: hooks.iter().map(|hook| (*hook).to_string()).collect(),
            unavailable_hooks: Vec::new(),
        }
    }

    #[test]
    fn paired_linux_features_require_both_sides_of_a_hook() {
        assert!(!linux_feature_is_active(&linux_feature(
            "network",
            &["handle_connect_exit"]
        )));
        assert!(linux_feature_is_active(&linux_feature(
            "network",
            &["handle_connect", "handle_connect_exit"]
        )));
        assert!(linux_feature_is_active(&linux_feature(
            "file",
            &["handle_unlinkat", "handle_unlinkat_exit"]
        )));
    }

    #[test]
    fn socket_tier_requires_connect_pair_and_btf_selected_accept() {
        let connect = ["handle_stream_connect", "handle_dgram_connect"];
        assert!(linux_feature_is_active(&linux_feature("network", &connect)));
        assert!(!linux_feature_is_active(&linux_feature(
            "network_tuple",
            &connect
        )));
        for accept in ["handle_accept2", "handle_accept4"] {
            assert!(linux_feature_is_active(&linux_feature(
                "network_tuple",
                &[connect[0], connect[1], accept]
            )));
        }
        // Missing trampoline support leaves the syscall tier active.
        let fallback = ["handle_connect", "handle_connect_exit"];
        assert!(linux_feature_is_active(&linux_feature(
            "network", &fallback
        )));
        assert!(!linux_feature_is_active(&linux_feature(
            "network_tuple",
            &fallback
        )));
    }

    #[test]
    fn file_identity_requires_every_operation_family() {
        let hooks = [
            "open_fd",
            "handle_vfs_unlink_identity2",
            "handle_vfs_rmdir_identity2",
            "handle_vfs_mkdir_identity2",
            "handle_vfs_mkdir_identity_exit",
            "handle_vfs_rename_identity",
        ];
        assert!(linux_feature_is_active(&linux_feature(
            "file_identity",
            &hooks
        )));
        assert!(!linux_feature_is_active(&linux_feature(
            "file_identity",
            &hooks[..hooks.len() - 1]
        )));
    }
}
