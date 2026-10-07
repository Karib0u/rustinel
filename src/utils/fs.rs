//! Filesystem permission helpers for security-sensitive output.
//!
//! Recordings and alerts describe endpoint activity in detail, so their files
//! must not be placed in directories controlled by another account.

use std::fs;
use std::io;
use std::path::Path;

/// Create a private directory when absent, or validate its existing owner.
/// Existing directory permissions are never changed.
pub fn ensure_output_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(directory)?;
        let metadata = fs::metadata(directory)?;
        let entry = fs::symlink_metadata(directory)?;
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || entry.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "output directory {} is not owned by the current user or is not a directory",
                    directory.display()
                ),
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        fs::create_dir_all(directory)?;
        let handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(directory)?;
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "output directory is a link or is not a directory",
            ));
        }
        check_windows_owner(&handle, directory)?;
    }
    Ok(())
}

/// Open a regular owner-controlled file without following its final symlink.
pub fn open_output_file(path: &Path, append: bool) -> io::Result<fs::File> {
    open_owned_file(path, append, false)
}

/// Create a new regular file, failing with [`io::ErrorKind::AlreadyExists`]
/// when anything, including a dangling symlink, already occupies the path.
/// The existence check and the creation are one atomic operation, so a
/// destination that appears after an earlier validation is still refused.
pub fn create_new_output_file(path: &Path) -> io::Result<fs::File> {
    open_owned_file(path, false, true)
}

fn open_owned_file(path: &Path, append: bool, exclusive: bool) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(true);
    }
    if append {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("output file {} is not a regular file", path.display()),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("output file {} is a link", path.display()),
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "output file {} is not owned by the current user",
                    path.display()
                ),
            ));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    check_windows_owner(&file, path)?;
    if !append && !exclusive {
        file.set_len(0)?;
    }
    Ok(file)
}

/// Fail unless `file` is owned by SYSTEM or the Administrators group.
#[cfg(windows)]
pub(crate) fn check_windows_owner(file: &fs::File, path: &Path) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };

    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status.0 != 0 {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    let allowed = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    if !allowed {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not owned by SYSTEM or Administrators",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Restrict a file to owner-only read/write.
#[cfg(unix)]
pub fn restrict_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn restrict_file_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Whether anything, including a dangling symlink, occupies `path`.
pub fn path_is_occupied(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Whether two paths name the same file: the same canonical path, or on Unix
/// the same device and inode, which also catches hard links.
pub fn same_file(a: &Path, b: &Path) -> bool {
    if let (Ok(a), Ok(b)) = (fs::canonicalize(a), fs::canonicalize(b)) {
        if a == b {
            return true;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (fs::metadata(a), fs::metadata(b)) {
            return a.dev() == b.dev() && a.ino() == b.ino();
        }
    }
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exclusive_creation_refuses_existing_files_and_dangling_links() {
        let temp = tempfile::tempdir().expect("tempdir");
        let existing = temp.path().join("existing");
        fs::write(&existing, b"evidence").expect("write");
        let err = create_new_output_file(&existing).expect_err("existing file refused");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&existing).expect("read"), b"evidence");

        let link = temp.path().join("dangling");
        std::os::unix::fs::symlink(temp.path().join("missing"), &link).expect("symlink");
        assert!(create_new_output_file(&link).is_err());
        assert!(!temp.path().join("missing").exists());
    }

    #[test]
    fn same_file_sees_symlinks_and_hard_links() {
        let temp = tempfile::tempdir().expect("tempdir");
        let original = temp.path().join("a");
        fs::write(&original, b"x").expect("write");
        let soft = temp.path().join("soft");
        let hard = temp.path().join("hard");
        std::os::unix::fs::symlink(&original, &soft).expect("symlink");
        fs::hard_link(&original, &hard).expect("hard link");
        let other = temp.path().join("other");
        fs::write(&other, b"x").expect("write");

        assert!(same_file(&original, &soft));
        assert!(same_file(&original, &hard));
        assert!(!same_file(&original, &other));
    }

    #[test]
    fn restricts_file_to_the_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let directory = temp.path().join("captures");
        fs::create_dir(&directory).expect("create dir");
        let file = directory.join("session.ndjson");
        fs::write(&file, b"{}").expect("write file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("relax file");

        restrict_file_permissions(&file).expect("restrict file");

        assert_eq!(
            fs::metadata(&file)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn refuses_directory_owned_by_another_user() {
        if unsafe { libc::geteuid() } != 0 {
            let error = ensure_output_directory(Path::new("/"))
                .expect_err("root-owned directory must be refused");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("not owned"));
        }
    }
}
