//! Account resolution helpers.

use anyhow::{anyhow, Result};

#[cfg(target_os = "linux")]
use std::ffi::CStr;

#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{LocalFree, HLOCAL};
#[cfg(windows)]
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
#[cfg(windows)]
use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn free_sid(sid: PSID) {
    if !sid.0.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid.0)));
        }
    }
}

/// Resolve a string SID (e.g., "S-1-5-18") into "DOMAIN\\User".
#[cfg(windows)]
pub fn lookup_account_sid(sid_str: &str) -> Result<String> {
    if sid_str.is_empty() {
        return Err(anyhow!("SID is empty"));
    }

    let wide_sid = to_wide(sid_str);
    let mut sid = PSID::default();

    unsafe {
        ConvertStringSidToSidW(PCWSTR(wide_sid.as_ptr()), &mut sid)
            .map_err(|e| anyhow!("ConvertStringSidToSidW failed: {}", e))?;
    }

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_use = SID_NAME_USE(0);

    unsafe {
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR::null()),
            &mut name_len,
            Some(PWSTR::null()),
            &mut domain_len,
            &mut sid_use,
        );
    }

    if name_len == 0 {
        free_sid(sid);
        return Err(anyhow!("LookupAccountSidW returned empty name length"));
    }

    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len as usize];

    let lookup_result = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut sid_use,
        )
        .map_err(|e| anyhow!("LookupAccountSidW failed: {}", e))
    };

    free_sid(sid);
    lookup_result?;

    let name = String::from_utf16_lossy(&name_buf)
        .trim_end_matches('\0')
        .to_string();
    let domain = String::from_utf16_lossy(&domain_buf)
        .trim_end_matches('\0')
        .to_string();

    if domain.is_empty() {
        Ok(name)
    } else {
        Ok(format!("{}\\{}", domain, name))
    }
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn lookup_account_sid(_sid_str: &str) -> Result<String> {
    Err(anyhow!("SID resolution is only supported on Windows"))
}

#[cfg(target_os = "linux")]
pub fn lookup_username_by_uid(uid: u32) -> Option<String> {
    let mut buf_len = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        value if value > 0 => value as usize,
        _ => 1024,
    };

    while buf_len <= 64 * 1024 {
        let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buf = vec![0u8; buf_len];

        let status = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };

        if status == 0 && !result.is_null() && !pwd.pw_name.is_null() {
            let name = unsafe { CStr::from_ptr(pwd.pw_name) };
            let value = name.to_string_lossy().trim().to_string();
            return (!value.is_empty()).then_some(value);
        }

        if status != libc::ERANGE {
            return None;
        }

        buf_len *= 2;
    }

    None
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn lookup_username_by_uid(_uid: u32) -> Option<String> {
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn lookup_current_effective_uid_returns_username() {
        let uid = unsafe { libc::geteuid() } as u32;
        let username = lookup_username_by_uid(uid).expect("current uid should resolve");
        assert!(!username.is_empty());
    }
}
