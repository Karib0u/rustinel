//! Filesystem permission helpers for security-sensitive output.
//!
//! Recordings and alerts describe endpoint activity in detail, so their files
//! are owner-only. On Windows the managed install layout carries the ACLs and
//! these helpers are no-ops.

// `fs` is only reachable from the Unix implementations below; the Windows
// no-ops would leave it unused.
#[cfg(unix)]
use std::fs;
use std::io;
use std::path::Path;

/// Restrict a directory to owner-only access.
#[cfg(unix)]
pub fn restrict_directory_permissions(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub fn restrict_directory_permissions(_directory: &Path) -> io::Result<()> {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn restricts_directory_and_file_to_the_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let directory = temp.path().join("captures");
        fs::create_dir(&directory).expect("create dir");
        let file = directory.join("session.ndjson");
        fs::write(&file, b"{}").expect("write file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("relax file");

        restrict_directory_permissions(&directory).expect("restrict dir");
        restrict_file_permissions(&file).expect("restrict file");

        assert_eq!(
            fs::metadata(&directory)
                .expect("dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&file)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
