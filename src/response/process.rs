//! Keep the validated process reference alive until termination.

use crate::utils::ProcessIdentity;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

pub(super) struct ProcessTarget {
    pub(super) identity: ProcessIdentity,
    #[cfg(target_os = "linux")]
    pidfd: OwnedFd,
    #[cfg(windows)]
    handle: OwnedHandle,
}

impl ProcessTarget {
    /// Open a process reference and validate identity before returning it.
    pub(super) fn open(expected: &ProcessIdentity) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        let pidfd = {
            let pid = libc::pid_t::try_from(expected.pid).map_err(|_| "invalid process PID")?;
            // SAFETY: pidfd_open takes a PID and flags, with no pointer arguments.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
            if fd < 0 {
                return Err(format!(
                    "pidfd_open failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: the successful syscall returned a new descriptor owned here.
            unsafe { OwnedFd::from_raw_fd(fd as i32) }
        };

        #[cfg(windows)]
        let handle = {
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
            };
            // SAFETY: opening a process does not dereference caller-provided pointers.
            let handle = unsafe {
                OpenProcess(
                    PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    expected.pid,
                )
            }
            .map_err(|err| format!("OpenProcess failed: {err}"))?;
            // SAFETY: OpenProcess returned a new handle owned here.
            unsafe { OwnedHandle::from_raw_handle(handle.0) }
        };

        #[cfg(windows)]
        let current = crate::utils::process::query_process_identity_from_handle(
            expected.pid,
            windows::Win32::Foundation::HANDLE(handle.as_raw_handle()),
        );
        #[cfg(not(windows))]
        let current = crate::utils::query_process_identity(expected.pid);
        let current = current.ok_or_else(|| {
            "process no longer exists or identity could not be queried".to_string()
        })?;

        #[cfg(any(target_os = "linux", windows))]
        if current.start_time.is_none() {
            return Err("process start time could not be queried".to_string());
        }

        let target = Self {
            identity: current,
            #[cfg(target_os = "linux")]
            pidfd,
            #[cfg(windows)]
            handle,
        };
        // Linux identity queries use /proc/<pid>. Confirm the pinned process is
        // still live AFTER those reads, so a recycled PID cannot supply them.
        #[cfg(target_os = "linux")]
        target.ensure_live()?;
        expected.matches(&target.identity)?;
        Ok(target)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn ensure_live(&self) -> Result<(), String> {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized pollfd for the duration of poll.
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result < 0 {
            return Err(format!(
                "pidfd poll failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if result != 0 {
            return Err("process exited during identity validation".to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn terminate(&self) -> Result<(), String> {
        // SAFETY: the descriptor stays owned and open, and null siginfo requests
        // the default SIGKILL information. No bare-PID fallback is safe here.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(format!(
                "pidfd_send_signal failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(windows)]
    pub(super) fn terminate(&self) -> Result<(), String> {
        use windows::Win32::{Foundation::HANDLE, System::Threading::TerminateProcess};
        // SAFETY: this is the same owned handle used to query the identity.
        unsafe { TerminateProcess(HANDLE(self.handle.as_raw_handle()), 1) }
            .map_err(|err| format!("TerminateProcess failed: {err}"))
    }

    #[cfg(target_os = "macos")]
    pub(super) fn terminate(&self) -> Result<(), String> {
        let pid = libc::pid_t::try_from(self.identity.pid).map_err(|_| "invalid process PID")?;
        // macOS has no pidfd equivalent. PID reuse can still race this kill.
        let result = unsafe { libc::kill(pid, libc::SIGKILL) };
        if result == 0 {
            Ok(())
        } else {
            Err(format!(
                "kill({pid}, SIGKILL) failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    pub(super) fn terminate(&self) -> Result<(), String> {
        Err("Active response termination is not supported on this platform".to_string())
    }
}
