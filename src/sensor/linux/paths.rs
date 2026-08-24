//! Absolute-path reconstruction for Linux file events.
//!
//! `openat`, `unlinkat`, and `renameat*` take a *pathname argument*, not a
//! path: `("passwd", dirfd)` and `("passwd", AT_FDCWD)` are the same string
//! naming different files. The eBPF programs capture the directory descriptor
//! next to the name; this module turns the pair back into one absolute path.
//!
//! The base directory comes from `/proc`, which is the only place userspace can
//! read it from:
//!
//! - `AT_FDCWD` → `/proc/<pid>/cwd`
//! - any other descriptor → `/proc/<pid>/fd/<dfd>`
//!
//! ## Why `/proc` is not enough on its own
//!
//! `/proc` is read when the ring buffer is drained, milliseconds after the
//! syscall returned, and it answers for what the descriptor *number* points at
//! then. A process walking a directory tree recycles fd numbers far faster than
//! that: measured on a lab VM, three of six descriptor-relative deletes emitted
//! during one `shutil.rmtree` resolved to the wrong directory — silently, since
//! a stale answer is a well-formed absolute path.
//!
//! So the descriptor is named at the moment it is created instead. The sensor
//! reports every successful `openat` with `O_DIRECTORY` or `O_PATH`, and
//! [`DirFdIndex`] holds the resulting `(pid, fd) -> path`. A stale entry cannot
//! be read back: a `*at` call only succeeds if its `dfd` is a directory at that
//! moment, and any descriptor that is a directory was opened as one, which
//! overwrote the entry. That is what makes the index cheap — no close tracking,
//! no eviction protocol, only a cap on how much it may hold.
//!
//! `/proc` remains the fallback, for descriptors the index never saw:
//!
//! - opened before the sensor started;
//! - produced by `dup`, `fcntl(F_DUPFD)`, or inherited across `fork`;
//! - opened without `O_DIRECTORY` (legal — `open("/etc", O_RDONLY)` yields a
//!   usable `dfd`), though `opendir(3)` sets the flag, so libc, Go, Rust, and
//!   Python all land in the index.
//!
//! Those keep the race described above. A descriptor reused for a
//! *non*-directory is always caught, since `/proc/<pid>/fd` reports it as a
//! `socket:[…]`-style target rather than a path.
//!
//! When neither source names the descriptor the path is reported unresolved and
//! the caller drops the event, rather than emitting a bare relative name that
//! would match rules against the wrong file.
//!
//! `..` is resolved lexically rather than by walking the filesystem: the file
//! named by a delete or rename is frequently gone by drain time, so
//! `canonicalize` would fail on exactly the events that matter most. Lexical
//! resolution differs from the kernel's only when a component is a symlink.

use std::collections::HashMap;
use std::collections::VecDeque;

use super::events::{FILE_FLAG_AUX_PATH_TRUNCATED, FILE_FLAG_PATH_TRUNCATED};

/// `dfd` value meaning "resolve against the process working directory".
pub const AT_FDCWD: i32 = -100;

/// Suffix `/proc` appends to a link target whose directory has been unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// Directory descriptors this sensor watched being opened.
///
/// Bounded so a process that opens directories without ever being seen to close
/// them cannot grow it without limit; the oldest entry is evicted first, which
/// is also the one least likely to still be open.
pub struct DirFdIndex {
    paths: HashMap<(u32, i32), String>,
    order: VecDeque<(u32, i32)>,
    capacity: usize,
}

/// Descriptors held before eviction starts.
///
/// A busy host keeps a few thousand directory descriptors open across all
/// processes; at an average path length this is a few hundred KiB.
const DIR_FD_CAPACITY: usize = 8192;

impl DirFdIndex {
    pub fn new() -> Self {
        Self::with_capacity(DIR_FD_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            paths: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record the directory a newly opened descriptor refers to.
    pub fn insert(&mut self, pid: u32, fd: i32, path: String) {
        if fd < 0 {
            return;
        }
        let key = (pid, fd);
        // A repeat of a live key is the fd number being reused, so it keeps its
        // place in the queue rather than claiming a second slot.
        if self.paths.insert(key, path).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.paths.remove(&oldest);
            }
        }
    }

    fn get(&self, pid: u32, fd: i32) -> Option<&str> {
        self.paths.get(&(pid, fd)).map(String::as_str)
    }

    /// Forget everything a process held. Called when it exits, since its
    /// descriptor numbers become meaningless and a later PID reuse must not
    /// inherit them.
    pub fn forget_process(&mut self, pid: u32) {
        if self.paths.keys().all(|(owner, _)| *owner != pid) {
            return;
        }
        self.paths.retain(|(owner, _), _| *owner != pid);
        self.order.retain(|(owner, _)| *owner != pid);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.paths.len()
    }
}

impl Default for DirFdIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuild the absolute path named by a `*at` pathname argument.
///
/// Returns `None` when the name is relative and its base directory cannot be
/// recovered — the caller must not fall back to the raw name.
pub fn resolve_at_path(index: &DirFdIndex, pid: u32, dfd: i32, raw: &str) -> Option<String> {
    resolve_at_path_with(dfd, raw, |fd| {
        index
            .get(pid, fd)
            .map(str::to_string)
            .or_else(|| read_base_dir(pid, fd))
    })
}

/// [`resolve_at_path`] with the `/proc` lookup injected, so the resolution
/// rules can be tested without a live process.
fn resolve_at_path_with<F>(dfd: i32, raw: &str, read_base: F) -> Option<String>
where
    F: FnOnce(i32) -> Option<String>,
{
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with('/') {
        // Already absolute; still normalized, so `/tmp/../etc/passwd` and
        // `/etc/passwd` match the same rules.
        return Some(normalize_absolute(raw));
    }

    let base = read_base(dfd)?;
    Some(normalize_absolute(&format!("{base}/{raw}")))
}

/// Read the directory a descriptor refers to out of `/proc`.
fn read_base_dir(pid: u32, dfd: i32) -> Option<String> {
    let link = if dfd == AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else if dfd >= 0 {
        format!("/proc/{pid}/fd/{dfd}")
    } else {
        // Negative and not AT_FDCWD: the syscall would have failed with EBADF,
        // so there is nothing to resolve against.
        return None;
    };

    let target = std::fs::read_link(link).ok()?;
    Some(clean_link_target(target.to_str()?)?.to_string())
}

/// Reject `/proc` link targets that are not paths, and drop the `(deleted)`
/// marker from the ones that are.
fn clean_link_target(target: &str) -> Option<&str> {
    // An unlinked directory still names the file that was created inside it, so
    // the marker is dropped rather than the path.
    let target = target.strip_suffix(DELETED_SUFFIX).unwrap_or(target);
    // `socket:[12345]`, `pipe:[678]`, `anon_inode:inotify`: the descriptor was
    // a directory when the syscall succeeded, so a non-path target means it has
    // since been closed and reused.
    target.starts_with('/').then_some(target)
}

/// Collapse `.`, `..`, and repeated separators in an absolute path.
fn normalize_absolute(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                // `..` at the root stays at the root, matching the kernel.
                segments.pop();
            }
            other => segments.push(other),
        }
    }

    let mut out = String::with_capacity(path.len());
    for segment in segments {
        out.push('/');
        out.push_str(segment);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Describe which of an event's paths the kernel-side buffer cut short.
///
/// `None` when both are complete, so the marker costs nothing on the events
/// that dominate. Truncation removes a path's *suffix*, which is what
/// `endswith` rules and extension IOCs key on, so a consumer that sees this
/// knows a non-match is not evidence of absence.
pub fn truncation_marker(flags: u32, source_present: bool) -> Option<&'static str> {
    let target = flags & FILE_FLAG_PATH_TRUNCATED != 0;
    let source = source_present && flags & FILE_FLAG_AUX_PATH_TRUNCATED != 0;
    match (source, target) {
        (true, true) => Some("source,target"),
        (true, false) => Some("source"),
        (false, true) => Some("target"),
        (false, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(value: &str) -> impl FnOnce(i32) -> Option<String> + '_ {
        move |_| Some(value.to_string())
    }

    fn no_base() -> impl FnOnce(i32) -> Option<String> {
        |_| None
    }

    #[test]
    fn absolute_paths_are_kept_and_normalized() {
        assert_eq!(
            resolve_at_path_with(AT_FDCWD, "/tmp/payload.sh", no_base()).as_deref(),
            Some("/tmp/payload.sh")
        );
        assert_eq!(
            resolve_at_path_with(AT_FDCWD, "/tmp/../etc/passwd", no_base()).as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            resolve_at_path_with(AT_FDCWD, "//var//log/./syslog", no_base()).as_deref(),
            Some("/var/log/syslog")
        );
    }

    #[test]
    fn cwd_relative_paths_resolve_against_the_working_directory() {
        assert_eq!(
            resolve_at_path_with(AT_FDCWD, "payload.sh", base("/home/user")).as_deref(),
            Some("/home/user/payload.sh")
        );
        assert_eq!(
            resolve_at_path_with(AT_FDCWD, "../etc/shadow", base("/home/user")).as_deref(),
            Some("/home/etc/shadow")
        );
    }

    #[test]
    fn descriptor_relative_paths_resolve_against_the_descriptor() {
        // The same name under two descriptors must not produce the same path.
        let from_dirfd = resolve_at_path_with(7, "passwd", base("/etc"));
        let from_cwd = resolve_at_path_with(AT_FDCWD, "passwd", base("/home/user"));
        assert_eq!(from_dirfd.as_deref(), Some("/etc/passwd"));
        assert_eq!(from_cwd.as_deref(), Some("/home/user/passwd"));
        assert_ne!(from_dirfd, from_cwd);
    }

    #[test]
    fn relative_paths_without_a_base_are_unresolved() {
        assert!(resolve_at_path_with(7, "passwd", no_base()).is_none());
        assert!(resolve_at_path_with(AT_FDCWD, "passwd", no_base()).is_none());
    }

    #[test]
    fn empty_names_are_unresolved() {
        assert!(resolve_at_path_with(AT_FDCWD, "", base("/tmp")).is_none());
    }

    #[test]
    fn root_relative_traversal_stops_at_the_root() {
        assert_eq!(
            resolve_at_path_with(AT_FDCWD, "../../../../etc/passwd", base("/tmp")).as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            resolve_at_path_with(AT_FDCWD, "..", base("/")).as_deref(),
            Some("/")
        );
    }

    #[test]
    fn deleted_marker_is_stripped_from_link_targets() {
        assert_eq!(clean_link_target("/tmp/gone (deleted)"), Some("/tmp/gone"));
        assert_eq!(clean_link_target("/tmp/keep"), Some("/tmp/keep"));
    }

    #[test]
    fn non_path_link_targets_are_rejected() {
        assert_eq!(clean_link_target("socket:[12345]"), None);
        assert_eq!(clean_link_target("pipe:[678]"), None);
        assert_eq!(clean_link_target("anon_inode:inotify"), None);
    }

    #[test]
    fn negative_descriptors_other_than_at_fdcwd_have_no_base() {
        assert!(read_base_dir(std::process::id(), -3).is_none());
    }

    #[test]
    fn truncation_marker_names_the_incomplete_paths() {
        assert_eq!(truncation_marker(0, true), None);
        assert_eq!(
            truncation_marker(FILE_FLAG_PATH_TRUNCATED, false),
            Some("target")
        );
        assert_eq!(
            truncation_marker(FILE_FLAG_AUX_PATH_TRUNCATED, true),
            Some("source")
        );
        assert_eq!(
            truncation_marker(
                FILE_FLAG_PATH_TRUNCATED | FILE_FLAG_AUX_PATH_TRUNCATED,
                true
            ),
            Some("source,target")
        );
        // A source that was dropped for being unresolvable is not reported as
        // truncated: the field it would describe is not on the event.
        assert_eq!(truncation_marker(FILE_FLAG_AUX_PATH_TRUNCATED, false), None);
    }

    #[test]
    fn cwd_of_this_process_resolves() {
        let pid = std::process::id();
        let cwd = std::env::current_dir().expect("cwd should be readable");
        let resolved = resolve_at_path(&DirFdIndex::new(), pid, AT_FDCWD, "marker.txt")
            .expect("own cwd should resolve");
        assert_eq!(
            resolved,
            normalize_absolute(&format!("{}/marker.txt", cwd.display()))
        );
    }

    #[test]
    fn the_index_names_a_descriptor_proc_can_no_longer_name() {
        // The failure this exists for: by drain time the number has been reused,
        // so /proc answers for a different directory - or, as here, for a
        // process that no longer exists at all.
        let mut index = DirFdIndex::new();
        index.insert(7, 3, "/etc".to_string());

        assert_eq!(
            resolve_at_path(&index, 7, 3, "passwd").as_deref(),
            Some("/etc/passwd")
        );
        // Same descriptor number, different process: not this process's fd.
        assert!(resolve_at_path(&index, 8, 3, "passwd").is_none());
    }

    #[test]
    fn the_index_wins_over_proc() {
        // A live descriptor of this process, so /proc could answer too - the
        // index must be the one that does, since it was recorded at open time.
        use std::os::fd::AsRawFd;
        let dir = std::fs::File::open("/tmp").expect("/tmp should be openable");

        let mut index = DirFdIndex::new();
        index.insert(std::process::id(), dir.as_raw_fd(), "/etc".to_string());

        assert_eq!(
            resolve_at_path(&index, std::process::id(), dir.as_raw_fd(), "passwd").as_deref(),
            Some("/etc/passwd")
        );
    }

    #[test]
    fn reopening_a_descriptor_number_replaces_the_entry() {
        let mut index = DirFdIndex::new();
        index.insert(7, 3, "/etc".to_string());
        index.insert(7, 3, "/var/log".to_string());

        assert_eq!(
            resolve_at_path(&index, 7, 3, "syslog").as_deref(),
            Some("/var/log/syslog")
        );
        // One slot, not two: a hot recycled number must not push the bound.
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn the_index_is_bounded_and_evicts_oldest_first() {
        let mut index = DirFdIndex::with_capacity(2);
        index.insert(7, 3, "/first".to_string());
        index.insert(7, 4, "/second".to_string());
        index.insert(7, 5, "/third".to_string());

        assert_eq!(index.len(), 2);
        assert!(index.get(7, 3).is_none());
        assert_eq!(index.get(7, 4), Some("/second"));
        assert_eq!(index.get(7, 5), Some("/third"));
    }

    #[test]
    fn a_process_exit_forgets_its_descriptors() {
        // PIDs are reused; a new process must not inherit the old one's fds.
        let mut index = DirFdIndex::with_capacity(4);
        index.insert(7, 3, "/etc".to_string());
        index.insert(8, 3, "/var".to_string());

        index.forget_process(7);
        assert!(index.get(7, 3).is_none());
        assert_eq!(index.get(8, 3), Some("/var"));
        // The ordering queue is pruned too, so the freed slot is reusable.
        assert_eq!(index.len(), 1);
        index.insert(9, 3, "/srv".to_string());
        index.insert(10, 3, "/opt".to_string());
        index.insert(11, 3, "/run".to_string());
        assert_eq!(index.len(), 4);
    }

    #[test]
    fn negative_descriptors_are_never_indexed() {
        let mut index = DirFdIndex::new();
        index.insert(7, AT_FDCWD, "/etc".to_string());
        assert_eq!(index.len(), 0);
    }
}
