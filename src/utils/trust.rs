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

/// The account an integration runs as: a Unix group ID, or a Windows SID.
#[cfg(unix)]
pub(crate) type Principal = u32;
#[cfg(windows)]
pub(crate) type Principal = imp::Sid;

/// A single administrator-designated tree where an integration may update rules.
#[derive(Clone, Debug)]
pub struct RuleTrust {
    root: PathBuf,
    principal: Principal,
}

impl RuleTrust {
    pub(crate) fn new(root: &Path, principal: &Principal) -> Result<Self> {
        anyhow::ensure!(
            root.is_absolute(),
            "integration rules directory must be absolute"
        );
        anyhow::ensure!(
            !root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
            "integration rules directory must not contain parent traversal"
        );
        let trust = Self {
            root: root.to_path_buf(),
            principal: principal.to_owned(),
        };
        trust.verify_root()?;
        Ok(trust)
    }

    #[cfg(unix)]
    fn verify_root(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&self.root)?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.gid() == self.principal
                && metadata.mode() & 0o007 == 0 && metadata.mode() & 0o2000 != 0,
            "integration rules directory must be root-owned, setgid, assigned to the integration group, and inaccessible to others"
        );
        verify_root_controlled_parents(&self.root, self.principal)
    }

    #[cfg(windows)]
    fn verify_root(&self) -> Result<()> {
        anyhow::ensure!(
            fs::symlink_metadata(&self.root)?.is_dir(),
            "integration rules directory must be a directory"
        );
        imp::verify_integration_entry(&self.root, &self.principal, false)?;
        imp::verify_controlled_parents(&self.root)
    }
}

#[cfg(windows)]
pub(crate) use imp::{resolve_principal, verify_controlled_parents, verify_integration_entry};

/// Configuration, rule-tree anchors and shared log directories must not be
/// replaceable by the integration account. Root-owned sticky ancestors are safe,
/// and so is group write for another group, such as Ubuntu's `root:syslog`
/// `/var/log`.
#[cfg(unix)]
pub(crate) fn verify_root_controlled_parents(path: &Path, gid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let controlled = |metadata: &fs::Metadata| {
        let mode = metadata.mode();
        metadata.uid() == 0
            && (mode & 0o1000 != 0
                || (mode & 0o002 == 0 && (mode & 0o020 == 0 || metadata.gid() != gid)))
    };
    let absolute = std::path::absolute(path)?;
    for parent in absolute.ancestors().skip(1) {
        let metadata = fs::metadata(parent)?;
        let entry = fs::symlink_metadata(parent)?;
        anyhow::ensure!(
            metadata.is_dir() && entry.uid() == 0 && controlled(&metadata),
            "{} must be a root-controlled parent directory",
            parent.display()
        );
    }
    // Check the resolved ancestry too, so a root-owned link cannot hide a
    // directory owned by the integration account.
    let canonical = fs::canonicalize(path)?;
    if canonical != absolute {
        for parent in canonical.ancestors().skip(1) {
            anyhow::ensure!(
                controlled(&fs::metadata(parent)?),
                "{} must be a root-controlled parent directory",
                parent.display()
            );
        }
    }
    Ok(())
}

/// Rule loaders alone may use the explicitly delegated tree. Other inputs keep
/// the normal trust policy, including inputs outside that tree.
pub fn verify_rule_input(path: &Path, trust: Option<&RuleTrust>) -> Result<()> {
    let Some(trust) = trust else {
        return verify_input(path);
    };
    let absolute = std::path::absolute(path)?;
    let Ok(relative) = absolute.strip_prefix(&trust.root) else {
        return verify_input(path);
    };
    trust.verify_root()?;
    let mut current = trust.root.clone();
    for component in relative.components() {
        anyhow::ensure!(
            matches!(component, std::path::Component::Normal(_)),
            "invalid integration rule path"
        );
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => verify_shared_entry(&current, &metadata, &trust.principal)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    }
    fn walk(path: &Path, principal: &Principal) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        verify_shared_entry(path, &metadata, principal)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                walk(&entry?.path(), principal)?;
            }
        }
        Ok(())
    }
    walk(&absolute, &trust.principal)
}

#[cfg(unix)]
fn verify_shared_entry(path: &Path, metadata: &fs::Metadata, gid: &u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(
        (metadata.is_dir() || metadata.is_file())
            && (metadata.gid() == *gid || (metadata.uid() == 0 && metadata.mode() & 0o022 == 0))
            && metadata.mode() & 0o002 == 0
            && (!metadata.is_file() || metadata.nlink() == 1),
        "{} is not a regular integration rule input with the expected group",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn verify_shared_entry(path: &Path, metadata: &fs::Metadata, sid: &imp::Sid) -> Result<()> {
    anyhow::ensure!(
        !imp::is_link(metadata) && (metadata.is_dir() || metadata.is_file()),
        "{} is not a regular integration rule input",
        path.display()
    );
    imp::verify_integration_entry(path, sid, true)
}

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
    use std::fs::{self, Metadata};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;
    use std::sync::OnceLock;

    use anyhow::{bail, Context, Result};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsWellKnownSid, LookupAccountNameW, TokenUser, WinAnonymousSid, WinAuthenticatedUserSid,
        WinBuiltinAdministratorsSid, WinBuiltinGuestsSid, WinBuiltinUsersSid,
        WinCreatorOwnerRightsSid, WinInteractiveSid, WinLocalServiceSid, WinLocalSid,
        WinLocalSystemSid, WinNetworkServiceSid, WinNetworkSid, WinServiceSid, WinWorldSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
        TOKEN_QUERY, TOKEN_USER,
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

    /// A SID buffer, as resolved from an account name.
    #[derive(Clone, Debug)]
    pub(crate) struct Sid(Vec<u8>);

    impl Sid {
        fn as_psid(&self) -> PSID {
            PSID(self.0.as_ptr().cast_mut().cast())
        }
    }

    /// Owner and DACL of a file or folder, freed on drop.
    struct Security {
        owner: PSID,
        dacl: *mut ACL,
        descriptor: PSECURITY_DESCRIPTOR,
    }

    impl Drop for Security {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
            }
        }
    }

    impl Security {
        fn read(path: &Path) -> Result<Self> {
            let name: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut security = Self {
                owner: PSID::default(),
                dacl: std::ptr::null_mut(),
                descriptor: PSECURITY_DESCRIPTOR::default(),
            };
            let status = unsafe {
                GetNamedSecurityInfoW(
                    PCWSTR(name.as_ptr()),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    Some(&mut security.owner),
                    None,
                    Some(&mut security.dacl),
                    None,
                    &mut security.descriptor,
                )
            };
            if status.0 != 0 {
                bail!(
                    "read security of {}: {}",
                    path.display(),
                    std::io::Error::from_raw_os_error(status.0 as i32)
                );
            }
            if security.dacl.is_null() {
                bail!(
                    "{} has no DACL, so every account can write it",
                    path.display()
                );
            }
            Ok(security)
        }

        /// The SID and access mask of each allow entry that applies to this
        /// object. The SIDs point into the descriptor.
        fn allowed(&self) -> Result<Vec<(PSID, u32)>> {
            let mut info = ACL_SIZE_INFORMATION::default();
            let mut entries = Vec::new();
            unsafe {
                GetAclInformation(
                    self.dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )?;
                for index in 0..info.AceCount {
                    let mut ace = std::ptr::null_mut();
                    GetAce(self.dacl, index, &mut ace)?;
                    let header = &*(ace as *const ACE_HEADER);
                    if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                        || u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0
                    {
                        continue;
                    }
                    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                    let sid = PSID((&allowed.SidStart as *const u32).cast_mut().cast());
                    entries.push((sid, allowed.Mask));
                }
            }
            Ok(entries)
        }
    }

    pub(super) fn verify_entry(path: &Path, _metadata: &Metadata, policy: Policy) -> Result<()> {
        let security = Security::read(path)?;
        let owner = security.owner;
        if policy == Policy::Managed && !is_system_account(owner) {
            bail!(
                "{} is owned by {}; managed inputs must be owned by SYSTEM or Administrators",
                path.display(),
                sid_label(owner)
            );
        }
        for (sid, mask) in security.allowed()? {
            if mask & WRITE_MASK == 0 {
                continue;
            }
            // The owner already controls the entry, and OWNER RIGHTS means the
            // owner. A managed owner was checked above. Folders created under
            // Program Files inherit full control for TrustedInstaller.
            let trusted = is_system_account(sid)
                || unsafe {
                    IsWellKnownSid(sid, WinCreatorOwnerRightsSid).as_bool()
                        || EqualSid(sid, owner).is_ok()
                };
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

    const TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    // FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER, GENERIC_ALL: any of them on a
    // folder lets the holder replace what it contains.
    const REPLACE_MASK: u32 = 0x40 | 0x4_0000 | 0x8_0000 | 0x1000_0000;

    /// SYSTEM, Administrators, TrustedInstaller, or the agent's own account.
    fn is_system_account(sid: PSID) -> bool {
        let admin = unsafe { is_admin_or_self(sid) };
        admin || sid_string(sid).as_deref() == Some(TRUSTED_INSTALLER)
    }

    /// Resolve the configured integration account or group to a SID, refusing
    /// accounts that many principals share.
    pub(crate) fn resolve_principal(name: &str) -> Result<Sid> {
        anyhow::ensure!(!name.is_empty(), "integration group must not be empty");
        let wide: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let (mut sid_len, mut domain_len) = (0u32, 0u32);
        let mut kind = SID_NAME_USE(0);
        unsafe {
            let _ = LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(wide.as_ptr()),
                None,
                &mut sid_len,
                None,
                &mut domain_len,
                &mut kind,
            );
        }
        anyhow::ensure!(
            sid_len > 0,
            "integration group {name:?} does not exist or could not be resolved"
        );
        let mut sid = Sid(vec![0u8; sid_len as usize]);
        let mut domain = vec![0u16; domain_len as usize];
        unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(wide.as_ptr()),
                Some(PSID(sid.0.as_mut_ptr().cast())),
                &mut sid_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut kind,
            )
        }
        .with_context(|| format!("resolve integration group {name:?}"))?;
        let psid = sid.as_psid();
        let shared = [
            WinWorldSid,
            WinAuthenticatedUserSid,
            WinBuiltinUsersSid,
            WinBuiltinGuestsSid,
            WinInteractiveSid,
            WinAnonymousSid,
            WinLocalSid,
            WinNetworkSid,
            WinServiceSid,
            WinLocalServiceSid,
            WinNetworkServiceSid,
        ];
        let shared = shared
            .into_iter()
            .any(|kind| unsafe { IsWellKnownSid(psid, kind) }.as_bool());
        anyhow::ensure!(
            !shared && !is_system_account(psid),
            "integration group must be a dedicated account or group, not {}",
            sid_label(psid)
        );
        Ok(sid)
    }

    /// A file or folder the integration may write: owned by a system account
    /// (or, inside a delegated rules tree, by the integration), and writable
    /// only by system accounts, its owner, and the integration.
    pub(crate) fn verify_integration_entry(
        path: &Path,
        principal: &Sid,
        integration_owner: bool,
    ) -> Result<()> {
        let security = Security::read(path)?;
        let owner = security.owner;
        let principal = principal.as_psid();
        let owner_is_integration = unsafe { EqualSid(owner, principal) }.is_ok();
        anyhow::ensure!(
            is_system_account(owner) || (integration_owner && owner_is_integration),
            "{} is owned by {}; it must be owned by SYSTEM, Administrators, or TrustedInstaller",
            path.display(),
            sid_label(owner)
        );
        for (sid, mask) in security.allowed()? {
            if mask & WRITE_MASK == 0 {
                continue;
            }
            let trusted = is_system_account(sid)
                || unsafe {
                    IsWellKnownSid(sid, WinCreatorOwnerRightsSid).as_bool()
                        || EqualSid(sid, owner).is_ok()
                        || EqualSid(sid, principal).is_ok()
                };
            anyhow::ensure!(
                trusted,
                "{} grants write access to {}; only SYSTEM, Administrators, and the integration group may write",
                path.display(),
                sid_label(sid)
            );
        }
        Ok(())
    }

    /// Folders above an integration input must be real folders owned by a
    /// system account, and must not let anyone else replace their contents.
    pub(crate) fn verify_controlled_parents(path: &Path) -> Result<()> {
        let absolute = std::path::absolute(path)?;
        for parent in absolute.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(parent)
                .with_context(|| format!("inspect {}", parent.display()))?;
            anyhow::ensure!(
                metadata.is_dir() && !is_link(&metadata),
                "{} must be a folder, not a link",
                parent.display()
            );
            let security = Security::read(parent)?;
            anyhow::ensure!(
                is_system_account(security.owner),
                "{} is owned by {}; parent folders must be owned by SYSTEM, Administrators, or TrustedInstaller",
                parent.display(),
                sid_label(security.owner)
            );
            for (sid, mask) in security.allowed()? {
                anyhow::ensure!(
                    mask & REPLACE_MASK == 0
                        || is_system_account(sid)
                        || unsafe { IsWellKnownSid(sid, WinCreatorOwnerRightsSid) }.as_bool(),
                    "{} grants {} full control or delete-child access; parent folders must not let other accounts replace their contents",
                    parent.display(),
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

    fn sid_string(sid: PSID) -> Option<String> {
        let mut text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid, &mut text) }.ok()?;
        let string = unsafe { text.to_string() }.ok();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        string
    }

    fn sid_label(sid: PSID) -> String {
        let Some(string) = sid_string(sid) else {
            return "an unknown SID".to_string();
        };
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
    fn trusts_trusted_installer_like_administrators() {
        // Every folder created under Program Files inherits this grant.
        let dir = tempfile::tempdir().expect("tempdir");
        let status = Command::new("icacls")
            .arg(dir.path())
            .args([
                "/grant",
                "*S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464:(OI)(CI)F",
            ])
            .status()
            .expect("run icacls");
        assert!(status.success(), "grant TrustedInstaller");
        verify_input(dir.path()).expect("TrustedInstaller is a system account");
    }

    #[test]
    fn integration_rules_tree_accepts_the_integration_principal_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rules = dir.path().join("rules");
        fs::create_dir(&rules).expect("mkdir");
        let icacls = |path: &Path, args: &[&str]| {
            Command::new("icacls")
                .arg(path)
                .args(args)
                .status()
                .expect("run icacls")
                .success()
        };
        assert!(icacls(
            &rules,
            &["/grant", "NT SERVICE\\EventLog:(OI)(CI)M"]
        ));
        let file = rules.join("rule.yml");
        fs::write(&file, "title: x\n").expect("write");
        let sid = resolve_principal("NT SERVICE\\EventLog").expect("service SID");
        let trust = RuleTrust::new(&rules, &sid).expect("delegated root");

        assert!(verify_input(&rules).is_err(), "default policy refuses it");
        verify_rule_input(&rules, Some(&trust)).expect("delegated tree loads");
        // Files the integration creates are owned by it. Taking ownership for
        // another account needs an elevated shell.
        if icacls(&file, &["/setowner", "NT SERVICE\\EventLog"]) {
            verify_rule_input(&rules, Some(&trust)).expect("integration-owned file loads");
        }
        let other = resolve_principal("NT SERVICE\\Schedule").expect("service SID");
        assert!(RuleTrust::new(&rules, &other).is_err());
        assert!(icacls(&file, &["/grant", "*S-1-5-32-545:(W)"]));
        assert!(verify_rule_input(&rules, Some(&trust)).is_err());
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
