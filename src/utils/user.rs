//! SID to account name resolution helpers.

use anyhow::{anyhow, Result};

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
pub fn lookup_account_sid(_sid_str: &str) -> Result<String> {
    Err(anyhow!("SID resolution is only supported on Windows"))
}
