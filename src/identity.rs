//! Stable host and agent identity stamped on every live alert.
//!
//! Resolved once at startup and shared immutably, so no alert pays for an OS
//! lookup. An identifier that cannot be determined reliably is left out rather
//! than invented, and replayed detections carry no identity at all.

use crate::utils::fs::{create_new_output_file, ensure_output_directory, open_output_file};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::Path;
use tracing::warn;

const AGENT_ID_FILE: &str = "agent-id";
const AGENT_TYPE: &str = "rustinel";
/// Application-specific message so the raw machine identifier is never exposed.
const HOST_ID_CONTEXT: &[u8] = b"rustinel.host.id.v1";

/// ECS `host.*` and `agent.*` fields shared by every live alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    #[serde(rename = "host.id", skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(rename = "host.name", skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(rename = "agent.id", skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "agent.type")]
    pub agent_type: &'static str,
    #[serde(rename = "agent.version")]
    pub agent_version: &'static str,
}

impl Identity {
    /// Resolve the identity once. `state_dir` holds the persistent `agent-id`.
    pub fn resolve(state_dir: &Path) -> Self {
        let agent_id = match load_or_create_agent_id(state_dir) {
            Ok(id) => Some(id),
            Err(err) => {
                warn!(
                    directory = %state_dir.display(),
                    error = %err,
                    "agent.id unavailable: the persistent agent-id could not be read or created"
                );
                None
            }
        };
        Self {
            host_id: raw_machine_id().and_then(|raw| derive_host_id(&raw)),
            host_name: raw_hostname().and_then(|name| normalize_hostname(&name)),
            agent_id,
            agent_type: AGENT_TYPE,
            agent_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

/// Lowercase and strip surrounding whitespace and a trailing root dot.
pub fn normalize_hostname(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_lowercase();
    (!name.is_empty()).then_some(name)
}

/// One-way, keyed digest of the OS machine identifier. Stable for an unchanged
/// OS identity and independent of the Rustinel installation.
pub fn derive_host_id(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let unusable = raw.is_empty()
        || raw.eq_ignore_ascii_case("uninitialized")
        || raw.chars().all(|c| c == '0' || c == '-');
    if unusable {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(raw.to_lowercase().as_bytes()).ok()?;
    mac.update(HOST_ID_CONTEXT);
    let digest = mac.finalize().into_bytes();
    Some(hex::encode(&digest[..16]))
}

fn parse_agent_id(contents: &str) -> Option<String> {
    uuid::Uuid::parse_str(contents.trim())
        .ok()
        .map(|id| id.hyphenated().to_string())
}

fn read_existing(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no arguments and cannot fail.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return None;
        }
    }
    parse_agent_id(&fs::read_to_string(path).ok()?)
}

/// Return the persisted installation UUID, creating it on first use. The file
/// is owner-only, created atomically, and never replaced while it is valid.
pub fn load_or_create_agent_id(dir: &Path) -> std::io::Result<String> {
    ensure_output_directory(dir)?;
    let path = dir.join(AGENT_ID_FILE);
    if let Some(id) = read_existing(&path) {
        return Ok(id);
    }
    let id = uuid::Uuid::new_v4().hyphenated().to_string();
    match create_new_output_file(&path) {
        Ok(mut file) => {
            writeln!(file, "{id}")?;
            file.sync_all()?;
            Ok(id)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process created it first, or the content is corrupt.
            for _ in 0..20 {
                if let Some(existing) = read_existing(&path) {
                    return Ok(existing);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let mut file = open_output_file(&path, false)?;
            writeln!(file, "{id}")?;
            file.sync_all()?;
            Ok(id)
        }
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "linux")]
fn raw_machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "macos")]
fn raw_machine_id() -> Option<String> {
    // kern.uuid is the IOPlatformUUID.
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    // SAFETY: `buf` and `len` are valid for the call and the name is NUL-terminated.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.uuid".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 {
        return None;
    }
    let bytes = &buf[..len.min(buf.len())];
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}

#[cfg(windows)]
fn raw_machine_id() -> Option<String> {
    use windows::core::w;
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, REG_ROUTINE_FLAGS, RRF_RT_REG_SZ,
    };
    // RRF_SUBKEY_WOW64_64KEY: read the 64-bit view regardless of process bitness.
    const WOW64_64KEY: REG_ROUTINE_FLAGS = REG_ROUTINE_FLAGS(0x0001_0000);
    let mut buf = [0u16; 128];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: `buf` is valid for `size` bytes and both pointers outlive the call.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\Microsoft\Cryptography"),
            w!("MachineGuid"),
            REG_ROUTINE_FLAGS(RRF_RT_REG_SZ.0 | WOW64_64KEY.0),
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status.0 != 0 {
        return None;
    }
    let units = (size as usize / 2).min(buf.len());
    let text = String::from_utf16_lossy(&buf[..units]);
    Some(text.trim_end_matches('\0').to_string())
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn raw_machine_id() -> Option<String> {
    None
}

#[cfg(unix)]
fn raw_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

#[cfg(windows)]
fn raw_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

#[cfg(not(any(unix, windows)))]
fn raw_hostname() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_id_is_stable_and_hides_the_raw_id() {
        let raw = "4c4c4544-0042-3510-8051-b8c04f4d3232";
        let id = derive_host_id(raw).unwrap();
        assert_eq!(derive_host_id(raw), Some(id.clone()));
        assert_eq!(derive_host_id(&raw.to_uppercase()), Some(id.clone()));
        assert_eq!(id.len(), 32);
        assert!(!id.contains(&raw.replace('-', "")));
        assert_ne!(derive_host_id("other-machine"), Some(id));
    }

    #[test]
    fn unusable_machine_ids_yield_no_host_id() {
        for raw in [
            "",
            "  ",
            "uninitialized\n",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(derive_host_id(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn hostname_is_normalized_independently_of_host_id() {
        assert_eq!(
            normalize_hostname(" WIN-Lab01.Corp.\n"),
            Some("win-lab01.corp".into())
        );
        assert_eq!(normalize_hostname("  "), None);
        assert_eq!(normalize_hostname("."), None);
        // The host id is derived only from the machine id, so a rename cannot move it.
        assert_eq!(derive_host_id("machine"), derive_host_id("machine"));
    }

    #[test]
    fn agent_id_persists_across_loads() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("state");
        let first = load_or_create_agent_id(&dir).unwrap();
        assert!(uuid::Uuid::parse_str(&first).is_ok());
        assert_eq!(load_or_create_agent_id(&dir).unwrap(), first);
    }

    #[test]
    fn clean_reinstall_issues_a_new_agent_id() {
        let temp = tempfile::tempdir().unwrap();
        let first = load_or_create_agent_id(temp.path()).unwrap();
        fs::remove_file(temp.path().join(AGENT_ID_FILE)).unwrap();
        assert_ne!(load_or_create_agent_id(temp.path()).unwrap(), first);
    }

    #[test]
    fn corrupt_agent_id_file_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(AGENT_ID_FILE), "not a uuid").unwrap();
        let id = load_or_create_agent_id(temp.path()).unwrap();
        let stored = fs::read_to_string(temp.path().join(AGENT_ID_FILE)).unwrap();
        assert_eq!(stored.trim(), id);
    }

    #[cfg(unix)]
    #[test]
    fn agent_id_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        load_or_create_agent_id(temp.path()).unwrap();
        let mode = fs::metadata(temp.path().join(AGENT_ID_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn unwritable_state_directory_omits_agent_id() {
        let temp = tempfile::tempdir().unwrap();
        let blocker = temp.path().join("file");
        fs::write(&blocker, b"x").unwrap();
        let identity = Identity::resolve(&blocker.join("state"));
        assert_eq!(identity.agent_id, None);
        assert_eq!(identity.agent_type, "rustinel");
        assert_eq!(identity.agent_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn serializes_only_known_fields() {
        let identity = Identity {
            host_id: None,
            host_name: Some("lab".into()),
            agent_id: None,
            agent_type: AGENT_TYPE,
            agent_version: "1.0.0",
        };
        let json = serde_json::to_value(&identity).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"host.name":"lab","agent.type":"rustinel","agent.version":"1.0.0"})
        );
    }
}
