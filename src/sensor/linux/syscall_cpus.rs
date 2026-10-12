//! Keep user-memory syscall tracepoints firing on every CPU.
//!
//! Some stable kernels (Ubuntu 7.0.0-38, 7.1.6 and later 7.1.y) carry a
//! backport of "tracing: perf: Fix stale head for perf syscall tracing" that
//! returns from `perf_syscall_enter` when the current CPU has no perf event,
//! before the attached BPF programs are consulted. Aya, like libbpf, attaches
//! a tracepoint program through one perf event on CPU 0, so on those kernels
//! the program only runs for syscalls made on CPU 0.
//!
//! Only the `sys_enter_*` events that copy user memory take that path. For each
//! of them a counting perf event is opened on every online CPU. The event
//! samples nothing and does not run the program a second time; it only keeps
//! that CPU's event list non-empty. On an unaffected kernel it is redundant
//! and costs one counter update per traced syscall.

use std::os::fd::{FromRawFd, OwnedFd};

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

use super::tracepoint_format::{reads_user_memory, tracepoint_id};

/// Counting perf events held for the lifetime of the attached programs.
#[derive(Default)]
pub(super) struct SyscallCpuEvents {
    /// Attached `(program, tracepoint)` pairs still waiting for coverage.
    pending: Vec<(String, String)>,
    events: Vec<OwnedFd>,
}

impl SyscallCpuEvents {
    /// Remember an attached tracepoint if it takes the path that needs a
    /// per-CPU event. Coverage waits for [`Self::cover_pending`], so these
    /// descriptors never take the place of a program's own.
    pub fn queue(&mut self, program: &str, category: &str, name: &str) {
        if category == "syscalls"
            && name.starts_with("sys_enter_")
            && reads_user_memory(category, name)
        {
            self.pending.push((program.to_owned(), name.to_owned()));
        }
    }

    /// Cover every queued tracepoint, returning the program and the reason
    /// for each one left partly uncovered.
    pub fn cover_pending(&mut self) -> Vec<(String, anyhow::Error)> {
        let pending = std::mem::take(&mut self.pending);
        let mut failures = Vec::new();
        for (program, name) in pending {
            if let Err(error) = self.cover(&name) {
                failures.push((program, error));
            }
        }
        failures
    }

    /// Open a counting event for `syscalls/name` on every online CPU.
    ///
    /// CPUs that fail are named in the error; the others stay covered.
    fn cover(&mut self, name: &str) -> Result<()> {
        let id = tracepoint_id("syscalls", name)?;
        let cpus = aya::util::online_cpus()
            .map_err(|(_, error)| error)
            .context("cannot list online CPUs")?;
        let mut failed = Vec::new();
        let mut first_error = None;
        for cpu in cpus {
            match open_counting_event(id, cpu) {
                Ok(fd) => self.events.push(fd),
                Err(error) => {
                    failed.push(cpu.to_string());
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            None => Ok(()),
            Some(error) => Err(anyhow!(error).context(format!(
                "cannot activate syscalls/{name} on CPUs {}",
                failed.join(",")
            ))),
        }
    }
}

/// Raise the soft open-file limit to the hard limit.
///
/// Each covered tracepoint holds one descriptor per CPU, which passes the
/// usual soft limit of 1024 on large hosts.
pub(super) fn raise_open_file_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        warn!(error = %std::io::Error::last_os_error(), "cannot read the open-file limit");
        return;
    }
    if limit.rlim_cur >= limit.rlim_max {
        return;
    }
    let previous = limit.rlim_cur;
    limit.rlim_cur = limit.rlim_max;
    // SAFETY: `limit` is a valid rlimit; raising the soft limit up to the
    // hard limit needs no privilege.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        warn!(error = %std::io::Error::last_os_error(), "cannot raise the open-file limit");
        return;
    }
    info!(
        previous,
        current = limit.rlim_cur,
        "raised the open-file limit"
    );
}

/// The original 64-byte `perf_event_attr` (`PERF_ATTR_SIZE_VER0`). Later
/// fields are optional and a counting tracepoint needs none of them.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    event_type: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

const _: () = assert!(std::mem::size_of::<PerfEventAttr>() == 64);

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;

fn open_counting_event(id: u64, cpu: u32) -> std::io::Result<OwnedFd> {
    let attr = PerfEventAttr {
        event_type: PERF_TYPE_TRACEPOINT,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: id,
        ..Default::default()
    };
    // SAFETY: `attr` follows the stable perf_event_attr ABI and outlives the
    // call, which retains no pointer. pid -1 with a CPU counts every task on
    // that CPU; the descriptor is close-on-exec.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            -1 as libc::pid_t,
            cpu as libc::c_int,
            -1 as libc::c_int,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful perf_event_open returns a new descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}
