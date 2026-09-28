//! Trust checks for configuration and detection inputs.
//!
//! The agent runs privileged and acts on what it loads: a Sigma filter
//! suppresses detections, IOC and YARA files decide what alerts, and the
//! configuration drives active response. An input that another local account
//! can write is therefore a way to blind or steer the agent. Every load, at
//! startup and on hot reload, checks the whole input before reading it and
//! rejects all of it when any part fails, so a reload keeps the previous
//! generation.
//!
//! Two policies apply, chosen by where the input lives:
//!
//! - **Managed**, under the install layout that `rustinel setup` creates:
//!   every entry must be owned by root, SYSTEM, Administrators, or the agent's
//!   own account, and links inside the tree are refused.
//! - **Portable**, anywhere else: any owner is accepted, because
//!   `sudo ./rustinel run` from an extracted folder is the documented
//!   quickstart, but links are followed and checked like the rest.
//!
//! Under both, no other account may be able to write an entry. On Unix that
//! also covers the parent directories, since whoever can write a parent can
//! swap the input. A world-writable parent is accepted only with the sticky
//! bit, as on `/tmp`. Windows parents are not checked: `C:\ProgramData`
//! grants Users create rights by design, and creating an entry there does not
//! allow replacing an existing one.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::config::InstallLayout;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Managed,
    Portable,
}

impl Policy {
    fn for_path(path: &Path) -> Self {
        let layout = InstallLayout::managed_current();
        let roots = [
            layout.config_file.parent(),
            Some(layout.rules_dir.as_path()),
        ];
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        if roots
            .into_iter()
            .flatten()
            .any(|root| path_starts_with(&absolute, root))
        {
            Self::Managed
        } else {
            Self::Portable
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Portable => "portable",
        }
    }
}

#[cfg(windows)]
fn path_starts_with(path: &Path, root: &Path) -> bool {
    let lower = |path: &Path| PathBuf::from(path.to_string_lossy().to_lowercase());
    lower(path).starts_with(lower(root))
}

#[cfg(not(windows))]
fn path_starts_with(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// Verify that no untrusted account can change the input at `path`, which may
/// be a file or a directory tree. A missing path is accepted; the loader
/// reports it.
pub fn verify_input(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(());
    }
    let policy = Policy::for_path(path);
    let mut visited = HashSet::new();
    verify_root(path, policy, &mut visited).with_context(|| {
        format!(
            "refusing untrusted {} input {}",
            policy.label(),
            path.display()
        )
    })
}

fn verify_root(path: &Path, policy: Policy, visited: &mut HashSet<PathBuf>) -> Result<()> {
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))?;
    if !visited.insert(canonical.clone()) {
        return Ok(());
    }
    imp::verify_parents(path, policy)?;
    if canonical != path {
        imp::verify_parents(&canonical, policy)?;
    }
    verify_tree(&canonical, policy, visited)
}

fn verify_tree(path: &Path, policy: Policy, visited: &mut HashSet<PathBuf>) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if imp::is_link(&metadata) {
        if policy == Policy::Managed {
            bail!(
                "{} is a link; managed inputs must not contain links",
                path.display()
            );
        }
        return verify_root(path, policy, visited);
    }
    imp::verify_entry(path, &metadata, policy)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
            verify_tree(&entry.path(), policy, visited)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
mod imp {
    use std::collections::HashMap;
    use std::fs::{self, Metadata};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::sync::Mutex;

    use anyhow::{bail, Context, Result};

    use super::Policy;

    const STICKY: u32 = 0o1000;

    pub(super) fn is_link(metadata: &Metadata) -> bool {
        metadata.file_type().is_symlink()
    }

    pub(super) fn verify_parents(path: &Path, policy: Policy) -> Result<()> {
        let mut current = path.parent();
        while let Some(dir) = current {
            if dir.as_os_str().is_empty() {
                break;
            }
            let metadata =
                fs::metadata(dir).with_context(|| format!("inspect {}", dir.display()))?;
            verify(dir, &metadata, policy, true)?;
            current = dir.parent();
        }
        Ok(())
    }

    pub(super) fn verify_entry(path: &Path, metadata: &Metadata, policy: Policy) -> Result<()> {
        verify(path, metadata, policy, false)
    }

    fn verify(path: &Path, metadata: &Metadata, policy: Policy, parent: bool) -> Result<()> {
        let mode = metadata.mode();
        let group_write = mode & 0o020 != 0
            && metadata.gid() != 0
            && !is_private_group(metadata.gid(), metadata.uid());
        let other_write = mode & 0o002 != 0;
        let sticky_parent = parent && metadata.is_dir() && mode & STICKY != 0;
        if (group_write || other_write) && !sticky_parent {
            bail!(
                "{} is writable by other accounts (mode {:o}); remove group and other write access",
                path.display(),
                mode & 0o7777
            );
        }
        if policy == Policy::Managed {
            let uid = metadata.uid();
            let euid = unsafe { libc::geteuid() };
            if uid != 0 && uid != euid {
                bail!(
                    "{} is owned by uid {uid}; managed inputs must be owned by root",
                    path.display()
                );
            }
        }
        Ok(())
    }

    /// Whether `gid` is the user-private group of `uid`: that account's
    /// primary group with no other members. Debian, Ubuntu, and Fedora give
    /// every account one and default to umask 002, so group write on such a
    /// group grants nobody else anything.
    pub(super) fn is_private_group(gid: u32, uid: u32) -> bool {
        static CACHE: Mutex<Option<HashMap<(u32, u32), bool>>> = Mutex::new(None);
        let mut cache = CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *cache
            .get_or_insert_with(HashMap::new)
            .entry((gid, uid))
            .or_insert_with(|| primary_gid(uid) == Some(gid) && group_has_no_members(gid))
    }

    fn primary_gid(uid: u32) -> Option<u32> {
        let mut buffer = vec![0 as libc::c_char; 16 * 1024];
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut passwd,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        (status == 0 && !result.is_null()).then_some(passwd.pw_gid as u32)
    }

    fn group_has_no_members(gid: u32) -> bool {
        let mut buffer = vec![0 as libc::c_char; 64 * 1024];
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getgrgid_r(
                gid as libc::gid_t,
                &mut group,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        status == 0
            && !result.is_null()
            && (group.gr_mem.is_null() || unsafe { (*group.gr_mem).is_null() })
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::Metadata;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;
    use std::sync::OnceLock;

    use anyhow::{bail, Result};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
        WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::Policy;

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    // FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY,
    // FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL,
    // GENERIC_WRITE: any of them lets the holder change what the agent loads.
    const WRITE_MASK: u32 =
        0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;

    pub(super) fn is_link(metadata: &Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    }

    pub(super) fn verify_parents(_path: &Path, _policy: Policy) -> Result<()> {
        Ok(())
    }

    pub(super) fn verify_entry(path: &Path, _metadata: &Metadata, policy: Policy) -> Result<()> {
        let name: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
        };
        if status.0 != 0 {
            bail!(
                "read security of {}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(status.0 as i32)
            );
        }
        let result = unsafe { verify_security(path, owner, dacl, policy) };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        result
    }

    /// # Safety
    /// `owner` and `dacl` must point into a live security descriptor.
    unsafe fn verify_security(
        path: &Path,
        owner: PSID,
        dacl: *mut ACL,
        policy: Policy,
    ) -> Result<()> {
        let owner_is_admin = is_admin_or_self(owner);
        if policy == Policy::Managed && !owner_is_admin {
            bail!(
                "{} is owned by {}; managed inputs must be owned by SYSTEM or Administrators",
                path.display(),
                sid_label(owner)
            );
        }
        if dacl.is_null() {
            bail!(
                "{} has no DACL, so every account can write it",
                path.display()
            );
        }

        let mut info = ACL_SIZE_INFORMATION::default();
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )?;
        for index in 0..info.AceCount {
            let mut ace = std::ptr::null_mut();
            GetAce(dacl, index, &mut ace)?;
            let header = &*(ace as *const ACE_HEADER);
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                || u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0
            {
                continue;
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            if allowed.Mask & WRITE_MASK == 0 {
                continue;
            }
            let sid = PSID((&allowed.SidStart as *const u32).cast_mut().cast());
            // The owner already controls the entry, and OWNER RIGHTS means the
            // owner. A managed owner was checked above.
            let trusted = is_admin_or_self(sid)
                || IsWellKnownSid(sid, WinCreatorOwnerRightsSid).as_bool()
                || EqualSid(sid, owner).is_ok();
            if !trusted {
                bail!(
                    "{} grants write access to {}; remove it so only SYSTEM, Administrators, and the owner can write",
                    path.display(),
                    sid_label(sid)
                );
            }
        }
        Ok(())
    }

    unsafe fn is_admin_or_self(sid: PSID) -> bool {
        IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
            || current_user_sid()
                .is_some_and(|user| EqualSid(sid, PSID(user.as_ptr().cast_mut().cast())).is_ok())
    }

    fn sid_label(sid: PSID) -> String {
        let mut text = PWSTR::null();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) }.is_err() {
            return "an unknown SID".to_string();
        }
        let string = unsafe { text.to_string() }.unwrap_or_default();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        match crate::utils::lookup_account_sid(&string) {
            Ok(name) => format!("{name} ({string})"),
            Err(_) => string,
        }
    }

    /// The agent's own account, as a SID buffer.
    fn current_user_sid() -> Option<&'static [u8]> {
        static SID: OnceLock<Option<Vec<u8>>> = OnceLock::new();
        SID.get_or_init(|| unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
            let mut buffer = vec![0u8; needed as usize];
            let queried = GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            );
            let _ = CloseHandle(token);
            queried.ok()?;
            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = user.User.Sid;
            let length = windows::Win32::Security::GetLengthSid(sid) as usize;
            Some(std::slice::from_raw_parts(sid.0 as *const u8, length).to_vec())
        })
        .as_deref()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn accepts_a_private_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("sigma")).expect("mkdir");
        fs::write(dir.path().join("sigma").join("rule.yml"), "title: x\n").expect("write");
        verify_input(dir.path()).expect("private tree is trusted");
    }

    #[test]
    fn accepts_a_missing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        verify_input(&dir.path().join("absent")).expect("missing input is left to the loader");
    }

    #[test]
    fn rejects_a_world_writable_file_anywhere_in_the_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("sigma").join("nested");
        fs::create_dir_all(&nested).expect("mkdir");
        let rule = nested.join("filter.yml");
        fs::write(&rule, "title: x\n").expect("write");
        fs::set_permissions(&rule, fs::Permissions::from_mode(0o666)).expect("chmod");

        let err = verify_input(dir.path()).expect_err("world-writable rule must be refused");
        assert!(
            format!("{err:#}").contains("writable by other accounts"),
            "{err:#}"
        );
    }

    #[test]
    fn rejects_a_group_writable_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sigma = dir.path().join("sigma");
        fs::create_dir(&sigma).expect("mkdir");
        fs::set_permissions(&sigma, fs::Permissions::from_mode(0o775)).expect("chmod");
        // Group write only matters for a shared group, not root's own or the
        // owner's private group.
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&sigma).expect("stat");
        if metadata.gid() == 0 || imp::is_private_group(metadata.gid(), metadata.uid()) {
            eprintln!("skipping: the test directory's group is not shared");
            return;
        }

        let err = verify_input(&sigma).expect_err("group-writable tree must be refused");
        assert!(
            format!("{err:#}").contains("writable by other accounts"),
            "{err:#}"
        );
    }

    #[test]
    fn accepts_group_write_for_a_private_group() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let metadata = fs::metadata(dir.path()).expect("stat");
        if !imp::is_private_group(metadata.gid(), metadata.uid()) {
            eprintln!("skipping: this account has no user-private group");
            return;
        }
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o775)).expect("chmod");
        verify_input(dir.path()).expect("a private group grants nobody else write");
    }

    #[test]
    fn rejects_a_writable_parent_without_the_sticky_bit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).expect("mkdir");
        let config = shared.join("config.toml");
        fs::write(&config, "").expect("write");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("chmod");

        let err = verify_input(&config).expect_err("a replaceable config must be refused");
        assert!(
            format!("{err:#}").contains("writable by other accounts"),
            "{err:#}"
        );

        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).expect("chmod");
        verify_input(&config).expect("a sticky parent cannot be used to swap the file");
    }

    #[test]
    fn follows_links_in_portable_inputs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).expect("mkdir");
        let target = outside.join("rule.yml");
        fs::write(&target, "title: x\n").expect("write");
        let tree = dir.path().join("sigma");
        fs::create_dir(&tree).expect("mkdir");
        std::os::unix::fs::symlink(&target, tree.join("rule.yml")).expect("symlink");

        verify_input(&tree).expect("a private link target is trusted");

        fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).expect("chmod");
        let err = verify_input(&tree).expect_err("a writable link target must be refused");
        assert!(
            format!("{err:#}").contains("writable by other accounts"),
            "{err:#}"
        );
    }

    #[test]
    fn managed_layout_paths_use_the_managed_policy() {
        let layout = InstallLayout::managed_current();
        assert_eq!(Policy::for_path(&layout.sigma_rules_dir), Policy::Managed);
        assert_eq!(
            Policy::for_path(layout.config_file.as_path()),
            Policy::Managed
        );
        assert_eq!(
            Policy::for_path(Path::new("/opt/rustinel/rules/current/sigma")),
            Policy::Portable
        );
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::process::Command;

    fn grant_users_modify(path: &Path) {
        // S-1-5-32-545 is BUILTIN\Users, spelled as a SID so the test does
        // not depend on the display language.
        let status = Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"])
            .status()
            .expect("run icacls");
        assert!(status.success(), "grant Users modify");
    }

    #[test]
    fn accepts_a_private_temp_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("sigma")).expect("mkdir");
        fs::write(dir.path().join("sigma").join("rule.yml"), "title: x\n").expect("write");
        verify_input(dir.path()).expect("private tree is trusted");
    }

    #[test]
    fn rejects_a_tree_that_users_can_modify() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sigma = dir.path().join("sigma");
        fs::create_dir(&sigma).expect("mkdir");
        fs::write(sigma.join("rule.yml"), "title: x\n").expect("write");
        grant_users_modify(&sigma);

        let err = verify_input(dir.path()).expect_err("a Users-writable tree must be refused");
        assert!(
            format!("{err:#}").contains("grants write access"),
            "{err:#}"
        );
    }

    #[test]
    fn managed_layout_paths_use_the_managed_policy() {
        assert_eq!(
            Policy::for_path(Path::new(r"c:\programdata\rustinel\rules\current\sigma")),
            Policy::Managed
        );
        assert_eq!(
            Policy::for_path(Path::new(r"C:\Tools\rustinel\rules\sigma")),
            Policy::Portable
        );
    }
}
