//! Process utilities.

use digest::Digest;
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub image: String,
    pub start_time: Option<u64>,
    pub command_line_hash: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessDetails {
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub parent_process_id: Option<u32>,
    pub parent_image: Option<String>,
    pub parent_command_line: Option<String>,
    pub current_directory: Option<String>,
    /// Linux `/proc/<pid>/stat` start time in clock ticks since boot.
    pub start_time: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct ProcStat {
    parent_process_id: Option<u32>,
    start_time: Option<u64>,
}

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

#[cfg(windows)]
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
#[cfg(windows)]
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut u8,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

/// Query a process command line from a process handle.
/// Returns None if the command line is unavailable or the process exits.
#[cfg(windows)]
pub fn query_process_command_line_from_handle(handle: HANDLE) -> Option<String> {
    unsafe {
        let mut return_length = 0u32;
        let status = NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH || return_length == 0 {
            return None;
        }

        let mut buffer = vec![0u8; return_length as usize];
        let status = NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buffer.as_mut_ptr(),
            return_length,
            &mut return_length,
        );
        if status != 0 {
            return None;
        }

        if buffer.len() < std::mem::size_of::<UNICODE_STRING>() {
            return None;
        }

        let unicode = &*(buffer.as_ptr() as *const UNICODE_STRING);
        if unicode.Length == 0 || unicode.Buffer.is_null() {
            return None;
        }

        let len = (unicode.Length / 2) as usize;
        let buffer_start = buffer.as_ptr() as usize;
        let buffer_end = buffer_start + buffer.len();
        let cmd_ptr = unicode.Buffer.0 as usize;
        let cmd_end = cmd_ptr.saturating_add(len.saturating_mul(2));
        if cmd_ptr < buffer_start || cmd_end > buffer_end {
            return None;
        }

        let slice = std::slice::from_raw_parts(unicode.Buffer.0, len);
        let cmd = String::from_utf16_lossy(slice)
            .trim_end_matches('\0')
            .to_string();
        if cmd.is_empty() {
            None
        } else {
            Some(cmd)
        }
    }
}

/// Query a process command line by PID (best-effort).
#[cfg(windows)]
pub fn query_process_command_line(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    if handle.is_invalid() {
        return None;
    }

    let cmd = query_process_command_line_from_handle(handle);
    let _ = unsafe { CloseHandle(handle) };
    cmd
}

#[cfg(target_os = "linux")]
pub fn query_process_command_line(pid: u32) -> Option<String> {
    read_proc_cmdline(pid)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn query_process_command_line(_pid: u32) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
pub fn query_process_details(pid: u32) -> Option<ProcessDetails> {
    if pid == 0 {
        return None;
    }

    let proc_stat = read_proc_stat(pid);
    let parent_process_id = proc_stat.as_ref().and_then(|stat| stat.parent_process_id);
    let details = ProcessDetails {
        image: read_proc_link(pid, "exe"),
        command_line: read_proc_cmdline(pid),
        parent_process_id,
        parent_image: parent_process_id.and_then(|ppid| read_proc_link(ppid, "exe")),
        parent_command_line: parent_process_id.and_then(read_proc_cmdline),
        current_directory: read_proc_link(pid, "cwd"),
        start_time: proc_stat.and_then(|stat| stat.start_time),
    };

    if details == ProcessDetails::default() {
        None
    } else {
        Some(details)
    }
}

#[cfg(target_os = "linux")]
pub fn query_process_identity(pid: u32) -> Option<ProcessIdentity> {
    let details = query_process_details(pid)?;
    Some(ProcessIdentity {
        pid,
        image: details.image?,
        start_time: details.start_time,
        command_line_hash: details.command_line.as_deref().map(hash_command_line),
    })
}

#[cfg(windows)]
pub fn query_process_identity(pid: u32) -> Option<ProcessIdentity> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return None;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    if handle.is_invalid() {
        return None;
    }

    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    let image = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }
    .ok()
    .and_then(|_| {
        let value = String::from_utf16_lossy(&buffer[..len as usize]);
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    });

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let start_time =
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }
            .ok()
            .map(|_| ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64);

    let command_line_hash = query_process_command_line_from_handle(handle)
        .as_deref()
        .map(hash_command_line);

    let _ = unsafe { CloseHandle(handle) };

    Some(ProcessIdentity {
        pid,
        image: image?,
        start_time,
        command_line_hash,
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn query_process_identity(_pid: u32) -> Option<ProcessIdentity> {
    None
}

pub fn hash_command_line(command_line: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(command_line.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(target_os = "linux")]
fn read_proc_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .map(|segment| String::from_utf8_lossy(segment).into_owned())
        .collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

#[cfg(target_os = "linux")]
fn read_proc_link(pid: u32, name: &str) -> Option<String> {
    let path = fs::read_link(format!("/proc/{pid}/{name}")).ok()?;
    Some(path.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn read_proc_stat(pid: u32) -> Option<ProcStat> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    let rest = stat.get(end + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() <= 19 {
        return None;
    }

    Some(ProcStat {
        parent_process_id: fields.get(1).and_then(|value| value.parse::<u32>().ok()),
        start_time: fields.get(19).and_then(|value| value.parse::<u64>().ok()),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn query_current_process_details_returns_linux_proc_metadata() {
        let pid = std::process::id();
        let details = query_process_details(pid).expect("current process details should exist");

        assert!(details.image.is_some());
        assert!(details.command_line.is_some());
        assert!(details.parent_process_id.is_some());
        assert!(details.current_directory.is_some());
        assert!(details.start_time.is_some());
    }

    #[test]
    fn query_current_process_command_line_returns_non_empty_string() {
        let pid = std::process::id();
        let command_line =
            query_process_command_line(pid).expect("current process command line should exist");
        assert!(!command_line.is_empty());
    }
}
