//! Stable file identity used to validate cached file-content results.
//!
//! Identity is derived from an open handle. On Unix it includes device and
//! inode numbers plus size, mtime, and ctime. On Windows it includes volume
//! and file IDs plus size, last-write time, and change time. Other platforms
//! deliberately return no identity, which disables caching.

use std::fs::File;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FileIdentity {
    platform: PlatformFileIdentity,
    size: u64,
    modified: i128,
    changed: i128,
}

impl FileIdentity {
    #[cfg(unix)]
    pub(crate) fn matches_object(&self, expected: &crate::models::FileObjectIdentity) -> bool {
        matches!(
            self.platform,
            PlatformFileIdentity::Unix { device, inode }
                if device == expected.device && inode == expected.inode
        )
    }

    #[cfg(not(unix))]
    pub(crate) fn matches_object(&self, _expected: &crate::models::FileObjectIdentity) -> bool {
        false
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PlatformFileIdentity {
    Unix { device: u64, inode: u64 },
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PlatformFileIdentity {
    Windows { volume: u32, file_id: u64 },
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PlatformFileIdentity {}

#[cfg(unix)]
pub(crate) fn from_file(file: &File) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().ok()?;
    Some(FileIdentity {
        platform: PlatformFileIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        size: metadata.len(),
        modified: timestamp(metadata.mtime(), metadata.mtime_nsec()),
        changed: timestamp(metadata.ctime(), metadata.ctime_nsec()),
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn from_stat(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        platform: PlatformFileIdentity::Unix {
            device: stat.st_dev as u64,
            inode: stat.st_ino,
        },
        size: stat.st_size as u64,
        modified: timestamp(stat.st_mtime, stat.st_mtime_nsec),
        changed: timestamp(stat.st_ctime, stat.st_ctime_nsec),
    }
}

/// Convert the kernel's compact `dev_t` plus inode into the same object
/// identity used by identities measured from an open userspace handle.
#[cfg(target_os = "linux")]
pub(crate) fn from_linux_event(
    device: u32,
    inode: u64,
) -> Option<crate::models::FileObjectIdentity> {
    if inode == 0 {
        return None;
    }
    let major = device >> 20;
    let minor = device & 0x000f_ffff;
    Some(crate::models::FileObjectIdentity {
        device: libc::makedev(major, minor),
        inode,
    })
}

#[cfg(unix)]
fn timestamp(seconds: i64, nanos: i64) -> i128 {
    i128::from(seconds) * 1_000_000_000 + i128::from(nanos)
}

#[cfg(windows)]
pub(crate) fn from_file(file: &File) -> Option<FileIdentity> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO,
    };

    let handle = HANDLE(file.as_raw_handle());
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let mut basic = FILE_BASIC_INFO::default();
    unsafe {
        GetFileInformationByHandle(handle, &mut info).ok()?;
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
        .ok()?;
    }

    Some(FileIdentity {
        platform: PlatformFileIdentity::Windows {
            volume: info.dwVolumeSerialNumber,
            file_id: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        },
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        modified: i128::from(basic.LastWriteTime),
        changed: i128::from(basic.ChangeTime),
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn from_file(_file: &File) -> Option<FileIdentity> {
    None
}

pub(crate) fn from_path(path: &Path) -> Option<FileIdentity> {
    let file = File::open(path).ok()?;
    from_file(&file)
}

pub(crate) fn unchanged(file: &File, path: &Path, initial: &FileIdentity) -> bool {
    from_file(file).as_ref() == Some(initial) && from_path(path).as_ref() == Some(initial)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_device_encoding_matches_userspace_file_identity() {
        use std::os::unix::fs::MetadataExt;

        let file = tempfile::NamedTempFile::new().unwrap();
        let metadata = file.as_file().metadata().unwrap();
        let kernel_device = ((libc::major(metadata.dev()) as u32) << 20)
            | (libc::minor(metadata.dev()) as u32 & 0x000f_ffff);
        assert_eq!(
            from_linux_event(kernel_device, metadata.ino()),
            Some(crate::models::FileObjectIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        );
        assert_eq!(from_linux_event(kernel_device, 0), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn esf_stat_matches_open_file_identity() {
        use std::os::fd::AsRawFd;
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // fstat initializes the entire stat on success.
        assert_eq!(
            unsafe { libc::fstat(file.as_file().as_raw_fd(), stat.as_mut_ptr()) },
            0
        );
        let stat = unsafe { stat.assume_init() };
        assert_eq!(Some(from_stat(&stat)), from_file(file.as_file()));
    }

    #[test]
    fn replacement_with_same_size_and_mtime_has_different_identity() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("sample.bin");
        fs::write(&path, b"clean!").expect("write clean file");
        let original = File::open(&path).expect("open clean file");
        let identity = from_file(&original).expect("stable identity");
        let times = fs::FileTimes::new().set_modified(
            original
                .metadata()
                .expect("metadata")
                .modified()
                .expect("mtime"),
        );

        let replacement = tempdir.path().join("replacement.bin");
        fs::write(&replacement, b"evil!!").expect("write replacement");
        File::options()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .set_times(times)
            .expect("preserve mtime");
        fs::rename(&replacement, &path).expect("replace original");

        assert_ne!(from_path(&path), Some(identity.clone()));
        assert!(!unchanged(&original, &path, &identity));
    }
}
