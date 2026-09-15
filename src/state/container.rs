//! Linux cgroup and container resolution for process events.
//!
//! The eBPF sensor measures `cgroup_id` and the namespace inodes at exec time;
//! nothing here adds kernel collection. This module turns those identifiers
//! into a cgroup v2 path and, when the path belongs to a recognised container
//! runtime, a container ID and runtime name.
//!
//! Resolution runs on the host-state worker, after the event has left the ring
//! drain, and every answer is checked against the kernel's own identifier: a
//! cgroup path is accepted only when its cgroupfs inode equals the measured
//! `cgroup_id`. Namespace membership alone does not identify a container:
//! containers can share namespaces, and namespace inode numbers are recycled.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Container identity parsed from a cgroup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerIdentity {
    pub id: String,
    /// Runtime named by the cgroup layout. Absent when the layout carries an
    /// ID but no runtime marker, as the Kubernetes cgroupfs driver does.
    pub runtime: Option<&'static str>,
}

/// Runtimes whose systemd-driver scopes are `<prefix><64 hex>.scope`.
///
/// `crio-conmon-<id>` and `libpod-conmon-<id>` are the runtime monitors, not
/// the container; they fail the hex check and are rejected.
const SCOPE_PREFIXES: &[(&str, &str)] = &[
    ("cri-containerd-", "containerd"),
    ("docker-", "docker"),
    ("crio-", "cri-o"),
    ("libpod-", "podman"),
    ("nerdctl-", "containerd"),
];

/// Parse a cgroup v2 path into the innermost container it names.
///
/// The innermost match wins, so a Docker-in-Docker process reports the inner
/// container. Paths that name no container return `None`; that is the host.
pub fn parse_container_cgroup(path: &str) -> Option<ContainerIdentity> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (index, segment) in segments.iter().enumerate().rev() {
        let name = segment.strip_suffix(".scope").unwrap_or(segment);
        for (prefix, runtime) in SCOPE_PREFIXES {
            if let Some(id) = name.strip_prefix(prefix).filter(|id| is_container_id(id)) {
                return Some(ContainerIdentity {
                    id: id.to_string(),
                    runtime: Some(runtime),
                });
            }
        }
        if let Some(name) = segment
            .strip_prefix("lxc.payload.")
            .filter(|n| !n.is_empty())
        {
            return Some(ContainerIdentity {
                id: name.to_string(),
                runtime: Some("lxc"),
            });
        }
        if index == 1 && segments[0] == "lxc" {
            return Some(ContainerIdentity {
                id: segment.to_string(),
                runtime: Some("lxc"),
            });
        }
        // cgroupfs drivers name the container directory by its bare ID.
        if is_container_id(segment) {
            let runtime = segments[..index]
                .iter()
                .rev()
                .find_map(|ancestor| match *ancestor {
                    "docker" => Some("docker"),
                    "libpod_parent" => Some("podman"),
                    _ => None,
                });
            return Some(ContainerIdentity {
                id: segment.to_string(),
                runtime,
            });
        }
    }
    None
}

fn is_container_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Result of resolving one process event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerResolution {
    /// Cgroup v2 path, relative to the cgroup2 mount, for the measured id.
    pub cgroup_path: Option<String>,
    pub container: Option<ContainerIdentity>,
}

const MAX_CGROUPS: usize = 8192;
const MAX_WALK_DEPTH: usize = 32;
const MAX_WALK_ENTRIES: usize = MAX_CGROUPS * 8;
const MAX_WALK_DURATION: Duration = Duration::from_millis(10);
/// A cgroupfs walk is the fallback for a process that exited before its
/// `/proc` entry could be read. Each walk indexes a bounded part of the live
/// hierarchy, so later events in those cgroups hit the cache. The interval caps
/// a stream of unresolvable identifiers at four walks a second.
const MIN_WALK_INTERVAL: Duration = Duration::from_millis(250);

/// Bounded cgroup-id index for one host.
pub struct ContainerResolver {
    cgroup_root: Option<PathBuf>,
    proc_root: PathBuf,
    cgroups: HashMap<u64, String>,
    last_walk: Option<Instant>,
}

impl ContainerResolver {
    /// Resolver for the live host: the first cgroup2 mount.
    pub fn for_host() -> Self {
        let proc_root = PathBuf::from("/proc");
        let cgroup_root = std::fs::read_to_string(proc_root.join("self/mountinfo"))
            .ok()
            .and_then(|mountinfo| cgroup2_mount(&mountinfo));
        if cgroup_root.is_none() {
            tracing::warn!(
                "No cgroup2 mount found; Linux container context is unavailable on this host"
            );
        }
        Self::new(cgroup_root, proc_root)
    }

    pub fn new(cgroup_root: Option<PathBuf>, proc_root: PathBuf) -> Self {
        Self {
            cgroup_root,
            proc_root,
            cgroups: HashMap::new(),
            last_walk: None,
        }
    }

    /// `parent_pid` is the fork-measured parent. A short-lived process has
    /// often exited by the time it is enriched while its parent, usually in the
    /// same cgroup, has not.
    pub fn resolve(
        &mut self,
        pid: u32,
        parent_pid: Option<u32>,
        cgroup_id: Option<u64>,
    ) -> ContainerResolution {
        let cgroup_path = cgroup_id.and_then(|id| self.cgroup_path(pid, parent_pid, id));
        let container = cgroup_path.as_deref().and_then(parse_container_cgroup);

        ContainerResolution {
            cgroup_path,
            container,
        }
    }

    fn cgroup_path(&mut self, pid: u32, parent_pid: Option<u32>, id: u64) -> Option<String> {
        if let Some(path) = self.cgroups.get(&id) {
            return Some(path.clone());
        }
        let root = self.cgroup_root.clone()?;

        // Either PID may have been reused or moved; only a path whose inode is
        // the measured id is adopted.
        let from_proc = std::iter::once(pid)
            .chain(parent_pid)
            .find_map(|candidate| {
                std::fs::read_to_string(self.proc_root.join(format!("{candidate}/cgroup")))
                    .ok()
                    .and_then(|content| unified_cgroup_path(&content).map(str::to_string))
                    .filter(|path| directory_inode(&join_cgroup(&root, path)) == Some(id))
            });
        if let Some(path) = from_proc {
            self.remember(id, path.clone());
            return Some(path);
        }

        if self
            .last_walk
            .is_some_and(|last| last.elapsed() < MIN_WALK_INTERVAL)
        {
            return None;
        }
        self.last_walk = Some(Instant::now());
        self.walk(&root, MAX_WALK_ENTRIES);
        self.cgroups.get(&id).cloned()
    }

    fn remember(&mut self, id: u64, path: String) {
        if self.cgroups.len() >= MAX_CGROUPS && !self.cgroups.contains_key(&id) {
            self.cgroups.clear();
        }
        self.cgroups.insert(id, path);
    }

    fn walk(&mut self, root: &Path, max_entries: usize) -> usize {
        self.cgroups.clear();
        if let Some(inode) = directory_inode(root) {
            self.cgroups.insert(inode, String::from("/"));
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            return 0;
        };
        let started = Instant::now();
        // Keep one iterator per ancestor instead of preloading every child.
        // Memory and open directories are bounded by MAX_WALK_DEPTH, even
        // when a directory has more children than the cache can hold.
        let mut stack = vec![(entries, String::from("/"))];
        let mut inspected = 0;
        while !stack.is_empty()
            && self.cgroups.len() < MAX_CGROUPS
            && inspected < max_entries
            && started.elapsed() < MAX_WALK_DURATION
        {
            let (entries, relative) = stack.last_mut().unwrap();
            let Some(entry) = entries.next() else {
                stack.pop();
                continue;
            };
            inspected += 1;
            let Ok(entry) = entry else {
                continue;
            };
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let child = if relative == "/" {
                format!("/{name}")
            } else {
                format!("{relative}/{name}")
            };
            if let Some(inode) = directory_inode(&entry.path()) {
                self.cgroups.insert(inode, child.clone());
            }
            if stack.len() < MAX_WALK_DEPTH {
                if let Ok(entries) = std::fs::read_dir(entry.path()) {
                    stack.push((entries, child));
                }
            }
        }
        inspected
    }

    #[cfg(all(test, unix))]
    fn cached_cgroups(&self) -> usize {
        self.cgroups.len()
    }
}

fn join_cgroup(root: &Path, relative: &str) -> PathBuf {
    root.join(relative.trim_start_matches('/'))
}

#[cfg(unix)]
fn directory_inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.is_dir())
        .map(|metadata| metadata.ino())
}

#[cfg(not(unix))]
fn directory_inode(_path: &Path) -> Option<u64> {
    None
}

/// The cgroup v2 entry of `/proc/<pid>/cgroup` is the `0::<path>` line.
fn unified_cgroup_path(content: &str) -> Option<&str> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/'))
}

/// Mount point of the first cgroup2 filesystem in `/proc/self/mountinfo`.
///
/// That is `/sys/fs/cgroup` on a unified host and `/sys/fs/cgroup/unified` on
/// a hybrid one. A v1-only host has none, and `bpf_get_current_cgroup_id`
/// has nothing meaningful to report there either.
fn cgroup2_mount(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|line| {
        let (mount, filesystem) = line.split_once(" - ")?;
        if filesystem.split_whitespace().next()? != "cgroup2" {
            return None;
        }
        let mount_point = mount.split_whitespace().nth(4)?;
        Some(PathBuf::from(unescape_mountinfo(mount_point)))
    })
}

/// Undo the octal escapes mountinfo uses for space, tab, newline, and `\`.
fn unescape_mountinfo(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 4 <= bytes.len() {
            let digits = std::str::from_utf8(&bytes[index + 1..index + 4]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(digits, 8) {
                out.push(byte);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f0a3c1b2d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";
    const INNER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parsed(path: &str) -> Option<(String, Option<&'static str>)> {
        parse_container_cgroup(path).map(|identity| (identity.id, identity.runtime))
    }

    #[test]
    fn parses_systemd_driver_scopes() {
        for (path, runtime) in [
            (format!("/system.slice/docker-{ID}.scope"), "docker"),
            (
                format!(
                    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1b2c.slice/cri-containerd-{ID}.scope"
                ),
                "containerd",
            ),
            (
                format!("/kubepods.slice/kubepods-pod1b2c.slice/crio-{ID}.scope"),
                "cri-o",
            ),
            (format!("/machine.slice/libpod-{ID}.scope"), "podman"),
            (format!("/system.slice/nerdctl-{ID}.scope"), "containerd"),
        ] {
            assert_eq!(parsed(&path), Some((ID.to_string(), Some(runtime))), "{path}");
        }
    }

    #[test]
    fn parses_podman_cgroupns_and_rootless_layouts() {
        assert_eq!(
            parsed(&format!("/machine.slice/libpod-{ID}.scope/container")),
            Some((ID.to_string(), Some("podman")))
        );
        assert_eq!(
            parsed(&format!(
                "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{ID}.scope/container"
            )),
            Some((ID.to_string(), Some("podman")))
        );
    }

    #[test]
    fn parses_cgroupfs_driver_layouts() {
        assert_eq!(
            parsed(&format!("/docker/{ID}")),
            Some((ID.to_string(), Some("docker")))
        );
        assert_eq!(
            parsed(&format!("/machine.slice/libpod_parent/{ID}")),
            Some((ID.to_string(), Some("podman")))
        );
        assert_eq!(
            parsed(&format!("/kubepods/besteffort/pod1b2c-33/{ID}")),
            Some((ID.to_string(), None))
        );
    }

    #[test]
    fn parses_lxc_layouts() {
        assert_eq!(
            parsed("/lxc.payload.web01/system.slice/cron.service"),
            Some(("web01".to_string(), Some("lxc")))
        );
        assert_eq!(
            parsed("/lxc/web01"),
            Some(("web01".to_string(), Some("lxc")))
        );
        assert_eq!(parsed("/lxc.monitor.web01"), None);
    }

    #[test]
    fn innermost_container_wins() {
        assert_eq!(
            parsed(&format!("/system.slice/docker-{ID}.scope/docker/{INNER}")),
            Some((INNER.to_string(), Some("docker")))
        );
    }

    #[test]
    fn host_and_monitor_paths_name_no_container() {
        for path in [
            "/",
            "/init.scope",
            "/user.slice/user-1000.slice/session-915.scope",
            "/system.slice/docker.service",
            "/system.slice/containerd.service",
            &format!("/machine.slice/libpod-conmon-{ID}.scope"),
            &format!("/kubepods.slice/crio-conmon-{ID}.scope"),
            "/system.slice/docker-short.scope",
            &format!("/system.slice/docker-{}.scope", ID.to_uppercase()),
        ] {
            assert_eq!(parsed(path), None, "{path}");
        }
    }

    #[test]
    fn reads_the_unified_line_of_proc_cgroup() {
        assert_eq!(
            unified_cgroup_path("12:cpu,cpuacct:/docker/x\n0::/system.slice/a.scope\n"),
            Some("/system.slice/a.scope")
        );
        assert_eq!(unified_cgroup_path("1:name=systemd:/init.scope\n"), None);
    }

    #[test]
    fn finds_unified_and_hybrid_cgroup2_mounts() {
        let unified = "25 1 0:22 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n";
        assert_eq!(
            cgroup2_mount(unified),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
        let hybrid = "\
24 1 0:21 / /sys/fs/cgroup ro shared:8 - tmpfs tmpfs ro\n\
25 24 0:22 / /sys/fs/cgroup/unified rw shared:9 - cgroup2 cgroup2 rw\n";
        assert_eq!(
            cgroup2_mount(hybrid),
            Some(PathBuf::from("/sys/fs/cgroup/unified"))
        );
        let v1 = "24 1 0:21 / /sys/fs/cgroup ro shared:8 - tmpfs tmpfs ro\n";
        assert_eq!(cgroup2_mount(v1), None);
        let escaped = "25 1 0:22 / /mnt/cg\\040root rw - cgroup2 cgroup2 rw\n";
        assert_eq!(cgroup2_mount(escaped), Some(PathBuf::from("/mnt/cg root")));
    }

    /// These fixtures compare cgroupfs inode numbers, which exist only on Unix.
    #[cfg(unix)]
    mod filesystem {
        use super::*;

        struct Fixture {
            _temp: tempfile::TempDir,
            cgroup: PathBuf,
            proc_root: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let temp = tempfile::tempdir().unwrap();
                let cgroup = temp.path().join("cgroup");
                let proc_root = temp.path().join("proc");
                std::fs::create_dir_all(&cgroup).unwrap();
                std::fs::create_dir_all(&proc_root).unwrap();
                Self {
                    _temp: temp,
                    cgroup,
                    proc_root,
                }
            }

            fn cgroup(&self, relative: &str) -> u64 {
                let path = join_cgroup(&self.cgroup, relative);
                std::fs::create_dir_all(&path).unwrap();
                directory_inode(&path).unwrap()
            }

            fn process(&self, pid: u32, relative: &str) {
                let dir = self.proc_root.join(pid.to_string());
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("cgroup"), format!("0::{relative}\n")).unwrap();
            }

            fn resolver(&self) -> ContainerResolver {
                ContainerResolver::new(Some(self.cgroup.clone()), self.proc_root.clone())
            }
        }

        #[test]
        fn resolves_through_proc_only_when_the_inode_matches() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let id = fixture.cgroup(&scope);
            fixture.process(42, &scope);
            let mut resolver = fixture.resolver();

            let resolution = resolver.resolve(42, None, Some(id));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(scope.as_str()));
            assert_eq!(resolution.container.unwrap().id, ID);

            // A reused PID now sits in another cgroup: the measured id no longer
            // matches the path /proc reports, so that path must not be adopted.
            let other = fixture.cgroup("/user.slice/session-1.scope");
            fixture.process(43, "/user.slice/session-1.scope");
            let mut fresh = fixture.resolver();
            fresh.last_walk = Some(Instant::now());
            assert_eq!(fresh.resolve(43, None, Some(id)).cgroup_path, None);
            assert_eq!(
                fresh.resolve(43, None, Some(other)).cgroup_path.as_deref(),
                Some("/user.slice/session-1.scope")
            );
        }

        #[test]
        fn exited_process_resolves_through_its_live_parent() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let id = fixture.cgroup(&scope);
            fixture.process(50, &scope);
            let mut resolver = fixture.resolver();
            resolver.last_walk = Some(Instant::now());

            let resolution = resolver.resolve(51, Some(50), Some(id));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(scope.as_str()));
            assert_eq!(resolution.container.unwrap().runtime, Some("docker"));
        }

        #[test]
        fn host_process_has_a_path_but_no_container() {
            let fixture = Fixture::new();
            let session = "/user.slice/user-1000.slice/session-915.scope";
            let id = fixture.cgroup(session);
            fixture.process(7, session);
            let resolution = fixture.resolver().resolve(7, None, Some(id));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(session));
            assert_eq!(resolution.container, None);
        }

        #[test]
        fn exited_process_resolves_through_a_rate_limited_walk() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let id = fixture.cgroup(&scope);
            fixture.cgroup("/init.scope");
            let mut resolver = fixture.resolver();

            let resolution = resolver.resolve(99, None, Some(id));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(scope.as_str()));
            assert!(resolver.cached_cgroups() >= 3);

            let late = fixture.cgroup(&format!("/system.slice/docker-{INNER}.scope"));
            assert_eq!(resolver.resolve(100, None, Some(late)).cgroup_path, None);
        }

        #[test]
        fn walk_limits_directory_entries_in_a_wide_hierarchy() {
            let fixture = Fixture::new();
            for index in 0..20 {
                fixture.cgroup(&format!("/child-{index}"));
            }
            let mut resolver = fixture.resolver();
            resolver.walk(&fixture.cgroup, 4);
            // The root plus at most four inspected children. The cache's own
            // limit is much larger, so it cannot mask an unbounded scan.
            assert!(resolver.cached_cgroups() <= 5);
        }

        #[test]
        fn walk_counts_files_against_the_entry_budget() {
            let fixture = Fixture::new();
            for index in 0..20 {
                std::fs::write(fixture.cgroup.join(format!("file-{index}")), "").unwrap();
            }
            let mut resolver = fixture.resolver();
            assert_eq!(resolver.walk(&fixture.cgroup, 4), 4);
            assert_eq!(resolver.cached_cgroups(), 1);
        }

        #[test]
        fn missing_cgroup2_or_id_resolves_nothing() {
            let fixture = Fixture::new();
            let mut resolver = ContainerResolver::new(None, fixture.proc_root.clone());
            assert_eq!(
                resolver.resolve(1, None, Some(1)),
                ContainerResolution::default()
            );
            let mut resolver = fixture.resolver();
            assert_eq!(
                resolver.resolve(1, None, None),
                ContainerResolution::default()
            );
        }
    }
}
