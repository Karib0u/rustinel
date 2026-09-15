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
//! `cgroup_id`. Processes that entered a container's namespaces without joining
//! its cgroup (`nsenter`, `setns`) are attributed through the PID namespace of
//! a container process seen earlier, and only while that container's cgroup
//! still exists.

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
    /// The container was attributed through the PID namespace rather than
    /// the process's own cgroup.
    pub via_namespace: bool,
}

#[derive(Debug, Clone)]
struct NamespaceEntry {
    cgroup_id: u64,
    cgroup_path: String,
    container: ContainerIdentity,
}

const MAX_CGROUPS: usize = 8192;
const MAX_NAMESPACES: usize = 4096;
const MAX_WALK_DEPTH: usize = 32;
/// A cgroupfs walk is the fallback for a process that exited before its
/// `/proc` entry could be read. One walk indexes every live cgroup, so later
/// events in the same cgroups hit the cache. The interval caps a stream of
/// unresolvable identifiers (cgroups already removed) at four walks a second.
const MIN_WALK_INTERVAL: Duration = Duration::from_millis(250);

/// Bounded cgroup-id and namespace index for one host.
pub struct ContainerResolver {
    cgroup_root: Option<PathBuf>,
    proc_root: PathBuf,
    host_pid_ns: Option<u64>,
    cgroups: HashMap<u64, String>,
    namespaces: HashMap<u64, NamespaceEntry>,
    last_walk: Option<Instant>,
}

impl ContainerResolver {
    /// Resolver for the live host: the first cgroup2 mount and init's namespaces.
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
        let host_pid_ns = namespace_inode(&proc_root.join("1/ns/pid"));
        Self::new(cgroup_root, proc_root, host_pid_ns)
    }

    pub fn new(cgroup_root: Option<PathBuf>, proc_root: PathBuf, host_pid_ns: Option<u64>) -> Self {
        Self {
            cgroup_root,
            proc_root,
            host_pid_ns,
            cgroups: HashMap::new(),
            namespaces: HashMap::new(),
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
        pid_ns: Option<u64>,
    ) -> ContainerResolution {
        let cgroup_path = cgroup_id.and_then(|id| self.cgroup_path(pid, parent_pid, id));
        let container = cgroup_path.as_deref().and_then(parse_container_cgroup);

        if let (Some(container), Some(id), Some(path)) = (&container, cgroup_id, &cgroup_path) {
            if let Some(pid_ns) = pid_ns.filter(|ns| self.is_foreign_pid_ns(*ns)) {
                if self.namespaces.len() >= MAX_NAMESPACES && !self.namespaces.contains_key(&pid_ns)
                {
                    self.namespaces.clear();
                }
                self.namespaces.insert(
                    pid_ns,
                    NamespaceEntry {
                        cgroup_id: id,
                        cgroup_path: path.clone(),
                        container: container.clone(),
                    },
                );
            }
        }

        let mut resolution = ContainerResolution {
            cgroup_path,
            container,
            via_namespace: false,
        };
        if resolution.container.is_none() {
            if let Some(container) = pid_ns
                .filter(|ns| self.is_foreign_pid_ns(*ns))
                .and_then(|ns| self.container_for_namespace(ns))
            {
                resolution.container = Some(container);
                resolution.via_namespace = true;
            }
        }
        resolution
    }

    /// A namespace is only evidence of a container when it is known to differ
    /// from the host's. Without the host's inode no namespace is attributed.
    fn is_foreign_pid_ns(&self, ns: u64) -> bool {
        self.host_pid_ns.is_some_and(|host| host != ns)
    }

    fn container_for_namespace(&mut self, pid_ns: u64) -> Option<ContainerIdentity> {
        let entry = self.namespaces.get(&pid_ns)?;
        // Namespace inodes are recycled once the namespace dies. The entry is
        // trusted only while the container's own cgroup is still present, which
        // it is for as long as any process holds the namespace open.
        let live = self
            .cgroup_root
            .as_ref()
            .and_then(|root| directory_inode(&join_cgroup(root, &entry.cgroup_path)))
            == Some(entry.cgroup_id);
        if live {
            Some(entry.container.clone())
        } else {
            self.namespaces.remove(&pid_ns);
            None
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
        self.walk(&root);
        self.cgroups.get(&id).cloned()
    }

    fn remember(&mut self, id: u64, path: String) {
        if self.cgroups.len() >= MAX_CGROUPS && !self.cgroups.contains_key(&id) {
            self.cgroups.clear();
        }
        self.cgroups.insert(id, path);
    }

    fn walk(&mut self, root: &Path) {
        self.cgroups.clear();
        let mut stack = vec![(root.to_path_buf(), String::from("/"), 0usize)];
        while let Some((dir, relative, depth)) = stack.pop() {
            if self.cgroups.len() >= MAX_CGROUPS {
                break;
            }
            if let Some(inode) = directory_inode(&dir) {
                self.cgroups.insert(inode, relative.clone());
            }
            if depth >= MAX_WALK_DEPTH {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
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
                stack.push((entry.path(), child, depth + 1));
            }
        }
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

#[cfg(unix)]
fn namespace_inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|metadata| metadata.ino())
}

#[cfg(not(unix))]
fn namespace_inode(_path: &Path) -> Option<u64> {
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

            fn resolver(&self, host_pid_ns: Option<u64>) -> ContainerResolver {
                ContainerResolver::new(
                    Some(self.cgroup.clone()),
                    self.proc_root.clone(),
                    host_pid_ns,
                )
            }
        }

        const HOST_PID_NS: u64 = 4026531836;
        const CONTAINER_PID_NS: u64 = 4026532500;

        fn in_ns(pid_ns: u64) -> Option<u64> {
            Some(pid_ns)
        }

        #[test]
        fn resolves_through_proc_only_when_the_inode_matches() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let id = fixture.cgroup(&scope);
            fixture.process(42, &scope);
            let mut resolver = fixture.resolver(Some(HOST_PID_NS));

            let resolution = resolver.resolve(42, None, Some(id), in_ns(CONTAINER_PID_NS));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(scope.as_str()));
            assert_eq!(resolution.container.unwrap().id, ID);
            assert!(!resolution.via_namespace);

            // A reused PID now sits in another cgroup: the measured id no longer
            // matches the path /proc reports, so that path must not be adopted.
            let other = fixture.cgroup("/user.slice/session-1.scope");
            fixture.process(43, "/user.slice/session-1.scope");
            let mut fresh = fixture.resolver(Some(HOST_PID_NS));
            fresh.last_walk = Some(Instant::now());
            assert_eq!(
                fresh
                    .resolve(43, None, Some(id), in_ns(HOST_PID_NS))
                    .cgroup_path,
                None
            );
            assert_eq!(
                fresh
                    .resolve(43, None, Some(other), in_ns(HOST_PID_NS))
                    .cgroup_path
                    .as_deref(),
                Some("/user.slice/session-1.scope")
            );
        }

        #[test]
        fn exited_process_resolves_through_its_live_parent() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let id = fixture.cgroup(&scope);
            fixture.process(50, &scope);
            let mut resolver = fixture.resolver(Some(HOST_PID_NS));
            resolver.last_walk = Some(Instant::now());

            let resolution = resolver.resolve(51, Some(50), Some(id), in_ns(CONTAINER_PID_NS));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(scope.as_str()));
            assert_eq!(resolution.container.unwrap().runtime, Some("docker"));
        }

        #[test]
        fn host_process_has_a_path_but_no_container() {
            let fixture = Fixture::new();
            let session = "/user.slice/user-1000.slice/session-915.scope";
            let id = fixture.cgroup(session);
            fixture.process(7, session);
            let resolution =
                fixture
                    .resolver(Some(HOST_PID_NS))
                    .resolve(7, None, Some(id), in_ns(HOST_PID_NS));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(session));
            assert_eq!(resolution.container, None);
        }

        #[test]
        fn exited_process_resolves_through_a_rate_limited_walk() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let id = fixture.cgroup(&scope);
            fixture.cgroup("/init.scope");
            let mut resolver = fixture.resolver(Some(HOST_PID_NS));

            let resolution = resolver.resolve(99, None, Some(id), in_ns(HOST_PID_NS));
            assert_eq!(resolution.cgroup_path.as_deref(), Some(scope.as_str()));
            assert!(resolver.cached_cgroups() >= 3);

            let late = fixture.cgroup(&format!("/system.slice/docker-{INNER}.scope"));
            assert_eq!(
                resolver
                    .resolve(100, None, Some(late), in_ns(HOST_PID_NS))
                    .cgroup_path,
                None
            );
        }

        #[test]
        fn namespace_attribution_follows_a_live_container_cgroup() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let container_cgroup = fixture.cgroup(&scope);
            fixture.process(10, &scope);
            let session = "/user.slice/session-2.scope";
            let host_cgroup = fixture.cgroup(session);
            fixture.process(11, session);
            let mut resolver = fixture.resolver(Some(HOST_PID_NS));

            resolver.resolve(10, None, Some(container_cgroup), in_ns(CONTAINER_PID_NS));
            // nsenter from a host session into the container's PID namespace.
            let entered = resolver.resolve(11, None, Some(host_cgroup), in_ns(CONTAINER_PID_NS));
            assert_eq!(entered.cgroup_path.as_deref(), Some(session));
            assert_eq!(entered.container.as_ref().unwrap().id, ID);
            assert!(entered.via_namespace);

            // Once the container's cgroup is gone the recycled inode is not trusted.
            std::fs::remove_dir(join_cgroup(&fixture.cgroup, &scope)).unwrap();
            let after = resolver.resolve(11, None, Some(host_cgroup), in_ns(CONTAINER_PID_NS));
            assert_eq!(after.container, None);
        }

        #[test]
        fn host_pid_namespace_and_unknown_host_are_never_indexed() {
            let fixture = Fixture::new();
            let scope = format!("/system.slice/docker-{ID}.scope");
            let container_cgroup = fixture.cgroup(&scope);
            fixture.process(10, &scope);
            let session = "/user.slice/session-2.scope";
            let host_cgroup = fixture.cgroup(session);
            fixture.process(11, session);

            // `docker run --pid=host`: the container is still reported from its
            // cgroup, but the host PID namespace must not point at it.
            let mut resolver = fixture.resolver(Some(HOST_PID_NS));
            let shared = resolver.resolve(10, None, Some(container_cgroup), in_ns(HOST_PID_NS));
            assert_eq!(shared.container.unwrap().id, ID);
            assert_eq!(
                resolver
                    .resolve(11, None, Some(host_cgroup), in_ns(HOST_PID_NS))
                    .container,
                None
            );

            let mut blind = fixture.resolver(None);
            blind.resolve(10, None, Some(container_cgroup), in_ns(CONTAINER_PID_NS));
            assert_eq!(
                blind
                    .resolve(11, None, Some(host_cgroup), in_ns(CONTAINER_PID_NS))
                    .container,
                None
            );
        }

        #[test]
        fn missing_cgroup2_or_id_resolves_nothing() {
            let fixture = Fixture::new();
            let mut resolver = ContainerResolver::new(None, fixture.proc_root.clone(), None);
            assert_eq!(
                resolver.resolve(1, None, Some(1), None),
                ContainerResolution::default()
            );
            let mut resolver = fixture.resolver(Some(HOST_PID_NS));
            assert_eq!(
                resolver.resolve(1, None, None, in_ns(HOST_PID_NS)),
                ContainerResolution::default()
            );
        }
    }
}
