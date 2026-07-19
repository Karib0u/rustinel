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
