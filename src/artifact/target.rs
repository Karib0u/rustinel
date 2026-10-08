//! What the resolver opens: the target of one artifact job, the identity its
//! bytes must still have, and the platform-specific ways of reaching the file.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use super::written_file::WrittenFileSelector;
#[cfg(target_os = "linux")]
use super::ArtifactOpener;
use crate::models::{CanonicalEvent, EventFields, FileObjectIdentity};
use crate::scanner;
use crate::sensor::{Platform, SensorAction};
#[cfg(any(target_os = "linux", windows))]
use crate::utils::file_identity;
use crate::utils::file_identity::FileIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactKind {
    /// The executable of a process start.
    ProcessImage,
    /// A module loaded into a process. PE metadata, and `Hashes`/`Imphash`
    /// when a deferred-pass rule selects on them, are resolved.
    LoadedImage,
    /// A file named by a canonical file event and chosen by the
    /// [`WrittenFileSelector`].
    WrittenFile,
}

/// What the opened file must still be for its bytes to belong to the event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ExpectedIdentity {
    /// Object, size, and timestamps measured at exec. Any change rejects it.
    Exact(FileIdentity),
    /// The filesystem object a file event touched. Its content may have grown
    /// since the event, but a replacement at the same path is rejected.
    Object(FileObjectIdentity),
}

impl ExpectedIdentity {
    pub(super) fn matches(&self, opened: &FileIdentity) -> bool {
        match self {
            Self::Exact(expected) => expected == opened,
            Self::Object(expected) => opened.matches_object(expected),
        }
    }
}

/// Whether written files from `platform` are bound to their object when the
/// written-file worker receives them rather than by the sensor.
///
/// Kernel-File ETW names a file by kernel pointers (`FileObject`, `FileKey`)
/// that user mode cannot compare with an opened handle, and no event carries
/// the volume file ID. The worker reads that ID from the path milliseconds
/// after the event and well before [`super::written_file::WRITTEN_FILE_SETTLE_DELAY`], so a file
/// replaced during the settle delay is still rejected. Only a replacement
/// inside that first gap goes unnoticed, which the kernel-measured identity
/// on Linux and macOS also closes.
pub(super) fn measures_identity_on_arrival(platform: Platform) -> bool {
    cfg!(windows) && platform == Platform::Windows
}

#[cfg_attr(not(windows), allow(dead_code))] // Only Windows measures on arrival.
pub(super) enum ArrivalIdentity {
    Measured(FileObjectIdentity),
    /// Not a local volume, or not a platform that measures on arrival.
    Unsupported,
    OpenFailed,
}

#[cfg(windows)]
pub(super) fn arrival_identity(path: &Path) -> ArrivalIdentity {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    if !on_local_volume(path) {
        return ArrivalIdentity::Unsupported;
    }
    // Attribute-only access reads no content, so it breaks no oplock and
    // triggers no on-access content scan, and sharing everything leaves the
    // writer free to keep writing, rename, or delete.
    let opened = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .open(path);
    match opened.ok().as_ref().and_then(file_identity::from_file) {
        Some(identity) => ArrivalIdentity::Measured(identity.object()),
        None => ArrivalIdentity::OpenFailed,
    }
}

/// A drive-letter path on a fixed, removable, or RAM disk. Network opens can
/// block for seconds, which would stall every pending written file behind
/// them on the worker.
#[cfg(windows)]
pub(super) fn on_local_volume(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;

    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_RAMDISK: u32 = 6;

    let Some(std::path::Component::Prefix(prefix)) = path.components().next() else {
        return false;
    };
    let (std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter)) = prefix.kind()
    else {
        return false;
    };
    let root: Vec<u16> = std::ffi::OsStr::new(&format!("{}:\\", letter as char))
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: `root` is a NUL-terminated wide string that outlives the call.
    let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
    matches!(kind, DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_RAMDISK)
}

#[cfg(not(windows))]
pub(super) fn arrival_identity(_path: &Path) -> ArrivalIdentity {
    ArrivalIdentity::Unsupported
}

#[derive(Clone)]
pub(crate) struct ArtifactTarget {
    pub kind: ArtifactKind,
    pub(super) path: PathBuf,
    pub(super) display_path: String,
    pub(super) pid: u32,
    pub expected: Option<ExpectedIdentity>,
    /// Lifetime and executable measured before queueing a process-relative image.
    pub(super) process_identity: Option<crate::utils::ProcessIdentity>,
    #[cfg(target_os = "linux")]
    pub(super) linux_process_path: Option<LinuxProcessPath>,
    /// A written file changed in place. Unlike a create or rename, this cannot
    /// have put a different object at the path.
    pub(super) content_write: bool,
    /// `expected` was read from the path by the written-file worker.
    pub(super) measured_on_arrival: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(super) struct LinuxProcessPath {
    pub(super) contextual: PathBuf,
    executable_identity: Option<FileIdentity>,
    /// Never an agent-relative path, and only present for a confirmed host namespace.
    pub(super) host_fallback: Option<PathBuf>,
}

impl ArtifactTarget {
    /// Select an artifact without querying the subject or traversing its filesystem.
    pub(crate) fn select_event(
        event: &CanonicalEvent,
        written_files: Option<&WrittenFileSelector>,
    ) -> Option<Self> {
        let (kind, display_path, expected) = match &event.normalized().fields {
            EventFields::ProcessCreation(fields) if event.action == SensorAction::Start => (
                ArtifactKind::ProcessImage,
                fields.image.clone(),
                fields
                    .exec
                    .as_ref()
                    .and_then(|exec| exec.file_identity.clone())
                    .map(ExpectedIdentity::Exact),
            ),
            EventFields::ImageLoad(fields) => {
                (ArtifactKind::LoadedImage, fields.image_loaded.clone(), None)
            }
            EventFields::FileEvent(fields)
                if matches!(
                    event.action,
                    SensorAction::Create | SensorAction::Modify | SensorAction::Rename
                ) && written_files.is_some_and(|select| select(event, fields)) =>
            {
                (
                    ArtifactKind::WrittenFile,
                    fields.target_filename.clone(),
                    fields.file_identity.map(ExpectedIdentity::Object),
                )
            }
            _ => return None,
        };
        let display_path = display_path.filter(|path| !path.is_empty())?;
        let pid = event.pid.unwrap_or(0);
        let mut path = normalize_path(event.normalized().platform, &display_path);
        if kind == ArtifactKind::ProcessImage
            && event.normalized().platform == Platform::Linux
            && crate::utils::process::linux_exec_uses_proc(&display_path)
        {
            if pid == 0 {
                return None;
            }
            path = PathBuf::from(format!("/proc/{pid}/exe"));
        }
        Some(Self {
            kind,
            path,
            display_path,
            pid,
            expected,
            process_identity: None,
            #[cfg(target_os = "linux")]
            linux_process_path: None,
            content_write: kind == ArtifactKind::WrittenFile
                && event.action == SensorAction::Modify,
            measured_on_arrival: false,
        })
    }

    pub(super) fn capture_process_context(&mut self, event: &CanonicalEvent) {
        if self.kind != ArtifactKind::ProcessImage || event.normalized().platform != Platform::Linux
        {
            return;
        }
        let EventFields::ProcessCreation(fields) = &event.normalized().fields else {
            unreachable!();
        };
        if crate::utils::process::linux_exec_uses_proc(&self.display_path) {
            self.process_identity = Some(scanner::capture_process_identity(
                event,
                fields,
                self.pid,
                &self.display_path,
            ));
            #[cfg(target_os = "linux")]
            if self.expected.is_none() {
                self.expected = std::fs::metadata(&self.path).ok().map(|metadata| {
                    ExpectedIdentity::Exact(file_identity::from_metadata(&metadata))
                });
            }
        } else {
            #[cfg(target_os = "linux")]
            self.capture_linux_process_path(event, fields);
        }
    }

    #[cfg(target_os = "linux")]
    fn capture_linux_process_path(
        &mut self,
        event: &CanonicalEvent,
        fields: &crate::models::ProcessCreationFields,
    ) {
        use std::os::unix::fs::MetadataExt;

        let proc = PathBuf::from(format!("/proc/{}", self.pid));
        let image = Path::new(&self.display_path);
        let contextual = if image.is_absolute() {
            proc.join("root").join(image.strip_prefix("/").unwrap())
        } else {
            proc.join("cwd").join(image)
        };
        let host_namespace = std::fs::metadata("/proc/self/ns/mnt")
            .ok()
            .map(|metadata| metadata.ino());
        let event_namespace = fields
            .linux_identity
            .mount_namespace
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok());
        let in_host_namespace = event_namespace.is_some() && event_namespace == host_namespace;
        let cwd = (!image.is_absolute())
            .then(|| std::fs::read_link(proc.join("cwd")).ok())
            .flatten();
        let host_fallback = in_host_namespace
            .then(|| {
                if image.is_absolute() {
                    Some(image.to_path_buf())
                } else {
                    cwd.as_ref().map(|cwd| cwd.join(image))
                }
            })
            .flatten();
        let Some(current) = crate::utils::query_process_identity(self.pid) else {
            // An exited container may have used the same path for different bytes.
            // Missing relative cwd is never replaced with the agent's working directory.
            if let Some(path) = host_fallback {
                self.path = path;
                return;
            }
            self.path = contextual;
            self.process_identity = Some(scanner::capture_process_identity(
                event,
                fields,
                self.pid,
                &self.display_path,
            ));
            return;
        };

        let exe = proc.join("exe");
        // These proc reads do not traverse the subject's executable pathname.
        // Script/symlink path traversal is deferred to an isolated I/O slot.
        let executable_identity = std::fs::metadata(&exe)
            .ok()
            .map(|metadata| file_identity::from_metadata(&metadata));
        let same_path = if image.is_absolute() {
            image == Path::new(&current.image)
        } else {
            cwd.as_ref()
                .is_some_and(|cwd| cwd.join(image) == Path::new(&current.image))
        };
        let same_object = self.expected.as_ref().is_some_and(|expected| {
            executable_identity
                .as_ref()
                .is_some_and(|identity| expected.matches(identity))
        });
        let is_executable = same_path || same_object;
        self.path = if is_executable {
            exe
        } else {
            contextual.clone()
        };
        if is_executable && self.expected.is_none() {
            self.expected = executable_identity.clone().map(ExpectedIdentity::Exact);
        }
        let mut identity =
            scanner::capture_process_identity(event, fields, self.pid, &current.image);
        // The kernel's script argv and the interpreter's live argv can differ.
        // Lifetime, executable, and the artifact's file identity guard this read.
        identity.command_line_hash = None;
        // A fallback must have been bound to the event's lifetime while it was
        // observable, not to a reused PID that disappears before the worker runs.
        let host_fallback = host_fallback.filter(|_| identity.matches(&current).is_ok());
        self.linux_process_path = Some(LinuxProcessPath {
            contextual,
            executable_identity,
            host_fallback,
        });
        self.process_identity = Some(identity);
    }

    /// Called only in an isolated I/O worker, after validating the captured lifetime.
    #[cfg(target_os = "linux")]
    pub(super) fn resolve_linux_process_path(&mut self, open: &ArtifactOpener) {
        let Some(context) = &self.linux_process_path else {
            return;
        };
        if self.path != context.contextual || self.expected.is_some() {
            return;
        }
        let contextual_identity = open(&self.path)
            .and_then(|file| file.metadata())
            .ok()
            .map(|metadata| file_identity::from_metadata(&metadata));
        // A symlink to the executable is a binary, not a script. Scripts keep
        // their own bytes rather than scanning the interpreter's exe link.
        let is_executable =
            contextual_identity.is_some() && contextual_identity == context.executable_identity;
        if is_executable {
            self.path = PathBuf::from(format!("/proc/{}/exe", self.pid));
        }
        if self.expected.is_none() {
            self.expected = contextual_identity.map(ExpectedIdentity::Exact);
        }
    }
}

fn normalize_path(platform: Platform, path: &str) -> PathBuf {
    #[cfg(windows)]
    if platform == Platform::Windows {
        let cleaned = path.strip_prefix("\\??\\").unwrap_or(path);
        return PathBuf::from(crate::utils::convert_nt_to_dos(cleaned));
    }
    let _ = platform;
    PathBuf::from(path)
}

pub(crate) fn open_artifact(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "linux")]
    let file = if is_linux_process_path(path) {
        open_linux_process_path(path, libc::O_RDONLY | libc::O_NONBLOCK)?
    } else {
        options.open(path)?
    };
    #[cfg(not(target_os = "linux"))]
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn is_linux_process_path(path: &Path) -> bool {
    let Some(path) = path.strip_prefix("/proc").ok() else {
        return false;
    };
    let mut parts = path.iter();
    parts
        .next()
        .and_then(|pid| pid.to_str()?.parse::<u32>().ok())
        .is_some()
        && parts
            .next()
            .is_some_and(|part| part == "root" || part == "cwd")
}

/// Anchor absolute symlinks and `..` in the process root, including paths
/// relative to its cwd. A plain open of `/proc/pid/root/...` escapes to the
/// observer's root when it encounters an absolute symlink.
#[cfg(target_os = "linux")]
pub(super) fn open_linux_process_path(path: &Path, flags: i32) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let mut parts = path.strip_prefix("/proc").unwrap().components();
    let proc = Path::new("/proc").join(parts.next().unwrap());
    let context = parts.next().unwrap();
    let root = proc.join("root");
    let relative = if context.as_os_str() == "cwd" {
        let cwd = std::fs::read_link(proc.join("cwd"))?;
        let root_path = std::fs::read_link(&root)?;
        cwd.strip_prefix(root_path)
            .map_err(|_| io::Error::other("process cwd is outside its root"))?
            .join(parts.as_path())
    } else {
        parts.as_path().to_path_buf()
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(root)?;
    let name = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in process artifact path"))?;
    // Linux open_how: flags, mode, resolve. RESOLVE_IN_ROOT makes symlinks
    // and parent traversal follow the process filesystem rather than ours.
    let how = [(flags | libc::O_CLOEXEC) as u64, 0_u64, 0x10_u64];
    // SAFETY: the directory and NUL-terminated path outlive the syscall;
    // `how` has the three-u64 layout required by the Linux UAPI.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            name.as_ptr(),
            how.as_ptr(),
            std::mem::size_of_val(&how),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat2 returns an owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::artifact::test_support::*;
    use crate::sensor::Platform;

    #[test]
    fn linux_process_relative_images_use_the_subject_executable_link() {
        for image in [
            "/proc/self/fd/3",
            "/proc/thread-self/fd/3",
            "/dev/fd/3",
            "/proc/42/fd/3",
            "/proc/self/exe",
            "/memfd:payload (deleted)",
            "memfd:payload",
        ] {
            let event = process_event(Path::new(image), Platform::Linux);
            let target = ArtifactTarget::from_event(&event, None).unwrap();
            assert_eq!(target.path, Path::new("/proc/42/exe"));
            assert_eq!(target.display_path, image);
            let mut missing_pid = event;
            missing_pid.pid = None;
            assert!(ArtifactTarget::from_event(&missing_pid, None).is_none());
        }
        for platform in [Platform::MacOS, Platform::Windows] {
            let event = process_event(Path::new("/dev/fd/3"), platform);
            let target = ArtifactTarget::from_event(&event, None).unwrap();
            assert_eq!(target.path, Path::new("/dev/fd/3"));
            assert!(target.process_identity.is_none());
        }
    }
}
