//! Protected DACLs for the managed Windows install tree.
//!
//! `C:\ProgramData` lets every user create subdirectories, and anything created
//! beneath it inherits that right. The privileged service loads detection
//! inputs and writes alerts under the managed tree, so setup replaces the
//! inherited DACL with an explicit, protected one and refuses a pre-existing
//! tree that a non-administrator owns or that redirects through a reparse point.

use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, READ_CONTROL,
};

/// Who may use a managed directory besides SYSTEM and Administrators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ManagedAccess {
    /// Users may read and execute, never create, modify, or delete.
    UsersRead,
    /// Only SYSTEM and Administrators may open the directory.
    AdminOnly,
}

impl ManagedAccess {
    fn sddl(self) -> &'static str {
        // P: protected, so nothing is inherited from C:\ProgramData or
        // C:\Program Files. OICI: the ACEs flow to every file and subdirectory.
        // 0x1200a9 is FILE_GENERIC_READ | FILE_GENERIC_EXECUTE.
        match self {
            Self::UsersRead => "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
            Self::AdminOnly => "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        }
    }
}

/// Verify `path` is a trusted tree, then replace every DACL with `access`.
///
/// Separately secured subtrees in `excluded` are inspected but not changed.
///
/// The tree is checked again after the DACL lands, because entries created
/// before that point may have been added while the old DACL still allowed it.
pub(super) fn secure_directory(
    path: &Path,
    access: ManagedAccess,
    excluded: &[PathBuf],
) -> Result<()> {
    ensure_trusted_tree(path)?;
    secure_tree(path, access, excluded)?;
    ensure_trusted_tree(path)
}

fn ensure_trusted_tree(path: &Path) -> Result<()> {
    if ensure_trusted_path(path)? {
        for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
            ensure_trusted_tree(&entry.path())?;
        }
    }
    Ok(())
}

fn secure_tree(path: &Path, access: ManagedAccess, excluded: &[PathBuf]) -> Result<()> {
    if excluded.iter().any(|child| child == path) {
        return Ok(());
    }
    let is_dir = ensure_trusted_path(path)?;
    apply_protected_dacl(path, access)
        .with_context(|| format!("restrict permissions on {}", path.display()))?;
    if is_dir {
        for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
            secure_tree(&entry.path(), access, excluded)?;
        }
    }
    Ok(())
}

fn ensure_trusted_path(path: &Path) -> Result<bool> {
    let handle = fs::OpenOptions::new()
        .access_mode(READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .with_context(|| format!("open managed path {}", path.display()))?;
    let metadata = handle
        .metadata()
        .with_context(|| format!("inspect managed path {}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        bail!(
            "managed path {} is a link or reparse point; remove it and rerun setup",
            path.display()
        );
    }
    crate::utils::fs::check_windows_owner(&handle, path)
        .map_err(|err| anyhow::anyhow!("{err}; remove or re-own it and rerun setup"))?;
    Ok(metadata.is_dir())
}

fn apply_protected_dacl(path: &Path, access: ManagedAccess) -> io::Result<()> {
    let sddl = wide(std::ffi::OsStr::new(access.sddl()));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(io::Error::other)?;

    let result = set_dacl_from_descriptor(path, descriptor);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result
}

fn set_dacl_from_descriptor(path: &Path, descriptor: PSECURITY_DESCRIPTOR) -> io::Result<()> {
    let mut present = windows::core::BOOL::default();
    let mut defaulted = windows::core::BOOL::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        .map_err(io::Error::other)?;
    if !present.as_bool() || dacl.is_null() {
        return Err(io::Error::other(
            "generated security descriptor has no DACL",
        ));
    }

    let name = wide(path.as_os_str());
    // Inherited ACEs propagate to children. secure_tree also replaces each
    // child's DACL to remove any explicit write grants or protected DACLs.
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if status.0 != 0 {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    Ok(())
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{
        CreateRestrictedToken, ImpersonateLoggedOnUser, RevertToSelf, DISABLE_MAX_PRIVILEGE,
        LUA_TOKEN, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// A directory under `C:\ProgramData`, where Users inherit create rights.
    struct ProgramDataDir(PathBuf);

    impl ProgramDataDir {
        fn new(name: &str) -> Self {
            let root = std::env::var_os("ProgramData").expect("ProgramData");
            let path = Path::new(&root).join(format!("{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for ProgramDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn dacl_sddl(path: &Path) -> String {
        let name = wide(path.as_os_str());
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        assert_eq!(status.0, 0, "read DACL of {}", path.display());
        let mut text = PWSTR::null();
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
        }
        .expect("format DACL");
        let sddl = unsafe { text.to_string() }.expect("UTF-16 SDDL");
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        sddl
    }

    fn users_aces(sddl: &str) -> Vec<&str> {
        sddl.split('(')
            .filter(|ace| ace.ends_with(";BU)"))
            .collect()
    }

    /// Setup runs elevated, so the directories it creates are owned by
    /// Administrators. An unelevated test run cannot reproduce that.
    fn running_elevated(path: &Path) -> bool {
        let handle = fs::OpenOptions::new()
            .access_mode(READ_CONTROL.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(path)
            .expect("open test directory");
        crate::utils::fs::check_windows_owner(&handle, path).is_ok()
    }

    fn write_as_limited_user(path: &Path) -> io::Result<()> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
                &mut token,
            )
            .expect("open process token");
        }
        let mut limited = HANDLE::default();
        unsafe {
            CreateRestrictedToken(
                token,
                LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
                None,
                None,
                None,
                &mut limited,
            )
            .expect("create limited token");
            ImpersonateLoggedOnUser(limited).expect("impersonate limited user");
        }
        let result = fs::write(path, "probe\n");
        unsafe {
            RevertToSelf().expect("restore process identity");
            CloseHandle(limited).expect("close limited token");
            CloseHandle(token).expect("close process token");
        }
        result
    }

    #[test]
    fn replaces_inherited_users_write_across_the_tree() {
        let dir = ProgramDataDir::new("rustinel-acl-test");
        if !running_elevated(&dir.0) {
            eprintln!("skipping: test directory is not owned by Administrators");
            return;
        }
        let child_dir = dir.0.join("rules").join("current");
        fs::create_dir_all(&child_dir).expect("create child directory");
        let child_file = child_dir.join("rule.yml");
        fs::write(&child_file, "title: test\n").expect("write child file");

        secure_directory(&dir.0, ManagedAccess::UsersRead, &[]).expect("secure directory");

        for path in [&dir.0, &child_dir, &child_file] {
            let sddl = dacl_sddl(path);
            let users = users_aces(&sddl);
            assert!(
                !users.is_empty() && users.iter().all(|ace| ace.contains(";0x1200a9;;;BU)")),
                "Users must be read/execute only on {}: {sddl}",
                path.display()
            );
        }
        assert!(
            dacl_sddl(&dir.0).starts_with("D:P"),
            "root DACL must be protected"
        );
    }

    #[test]
    fn replaces_explicit_users_write_on_a_protected_child() {
        let dir = ProgramDataDir::new("rustinel-acl-explicit-test");
        if !running_elevated(&dir.0) {
            eprintln!("skipping: test directory is not owned by Administrators");
            return;
        }
        let child_dir = dir.0.join("rules");
        fs::create_dir(&child_dir).expect("create child directory");
        let child_file = child_dir.join("rule.yml");
        fs::write(&child_file, "title: test\n").expect("write child file");

        let status = Command::new("icacls")
            .arg(&child_dir)
            .args(["/inheritance:d", "/grant", "*S-1-5-32-545:(OI)(CI)M"])
            .status()
            .expect("set explicit Users write access");
        assert!(status.success(), "set explicit Users write access");
        assert!(dacl_sddl(&child_dir).starts_with("D:P"));
        let before = child_dir.join("before-probe.txt");
        write_as_limited_user(&before).expect("limited user must be able to write before repair");
        fs::remove_file(before).expect("remove probe");

        secure_directory(&dir.0, ManagedAccess::UsersRead, &[]).expect("secure directory");

        for path in [&child_dir, &child_file] {
            let sddl = dacl_sddl(path);
            let users = users_aces(&sddl);
            assert!(
                !users.is_empty() && users.iter().all(|ace| ace.contains(";0x1200a9;;;BU)")),
                "Users must be read/execute only on {}: {sddl}",
                path.display()
            );
        }
        let after = child_dir.join("after-probe.txt");
        assert_eq!(
            write_as_limited_user(&after)
                .expect_err("limited user must be denied")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn admin_only_removes_users_entirely() {
        let dir = ProgramDataDir::new("rustinel-acl-logs-test");
        if !running_elevated(&dir.0) {
            eprintln!("skipping: test directory is not owned by Administrators");
            return;
        }
        fs::write(dir.0.join("alerts.json"), "{}\n").expect("write log file");

        secure_directory(&dir.0, ManagedAccess::AdminOnly, &[]).expect("secure directory");

        for path in [dir.0.clone(), dir.0.join("alerts.json")] {
            let sddl = dacl_sddl(&path);
            assert!(users_aces(&sddl).is_empty(), "{}: {sddl}", path.display());
        }
    }

    #[test]
    fn parent_repair_keeps_logs_admin_only() {
        let dir = ProgramDataDir::new("rustinel-acl-log-parent-test");
        if !running_elevated(&dir.0) {
            eprintln!("skipping: test directory is not owned by Administrators");
            return;
        }
        let logs = dir.0.join("logs");
        fs::create_dir(&logs).expect("create logs directory");
        let log = logs.join("alerts.json");
        fs::write(&log, "{}\n").expect("write log file");

        secure_directory(&logs, ManagedAccess::AdminOnly, &[]).expect("secure logs");
        secure_directory(&dir.0, ManagedAccess::UsersRead, &[logs.clone()]).expect("secure parent");

        for path in [&logs, &log] {
            let sddl = dacl_sddl(path);
            assert!(users_aces(&sddl).is_empty(), "{}: {sddl}", path.display());
        }
    }

    #[test]
    fn refuses_a_junction_inside_the_tree() {
        let dir = ProgramDataDir::new("rustinel-acl-junction-test");
        if !running_elevated(&dir.0) {
            eprintln!("skipping: test directory is not owned by Administrators");
            return;
        }
        let target = dir.0.join("elsewhere");
        fs::create_dir(&target).expect("create junction target");
        let junction = dir.0.join("rules");
        let status = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .status()
            .expect("run mklink");
        assert!(status.success(), "create junction");

        let err = secure_directory(&dir.0, ManagedAccess::UsersRead, &[])
            .expect_err("junction must be refused");
        assert!(
            err.to_string().contains("reparse point"),
            "unexpected error: {err:#}"
        );
    }
}
