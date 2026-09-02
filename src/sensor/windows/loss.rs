//! Windows ETW kernel-buffer loss accounting.
//!
//! Queue telemetry starts at the provider callback, so it cannot see events
//! discarded by ETW before that callback runs. `EventsLost` is cumulative for
//! each trace session and is read both periodically and when the session is
//! stopped.

use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
};

use crate::utils::LogRateLimiter;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const LOSS_LOG_WINDOW: Duration = Duration::from_secs(10);
const TRACE_NAME_BYTES: usize = 2 * 1024;

#[repr(C)]
struct PropertiesBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    names: [u8; 2 * TRACE_NAME_BYTES],
}

impl PropertiesBuffer {
    fn new() -> Box<Self> {
        Box::new(Self {
            properties: EVENT_TRACE_PROPERTIES::default(),
            names: [0; 2 * TRACE_NAME_BYTES],
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Session {
    Main,
    Process,
}

#[derive(Debug)]
pub(super) struct LossCounters {
    main: AtomicU64,
    process: AtomicU64,
    warnings: Mutex<LogRateLimiter>,
}

impl LossCounters {
    pub(super) fn new() -> Self {
        Self {
            main: AtomicU64::new(0),
            process: AtomicU64::new(0),
            warnings: Mutex::new(LogRateLimiter::new(LOSS_LOG_WINDOW)),
        }
    }

    pub(super) fn total(&self) -> u64 {
        self.main
            .load(Ordering::Relaxed)
            .saturating_add(self.process.load(Ordering::Relaxed))
    }

    pub(super) fn reset(&self) {
        self.main.store(0, Ordering::Relaxed);
        self.process.store(0, Ordering::Relaxed);
        match self.warnings.lock() {
            Ok(mut limiter) => *limiter = LogRateLimiter::new(LOSS_LOG_WINDOW),
            Err(poisoned) => {
                *poisoned.into_inner() = LogRateLimiter::new(LOSS_LOG_WINDOW);
            }
        }
    }

    fn record(&self, session: Session, session_name: &str, events_lost: u64) {
        let counter = match session {
            Session::Main => &self.main,
            Session::Process => &self.process,
        };
        let previous = counter.fetch_max(events_lost, Ordering::Relaxed);
        if events_lost <= previous {
            return;
        }

        let decision = match self.warnings.lock() {
            Ok(mut limiter) => limiter.should_emit("etw_events_lost"),
            Err(poisoned) => poisoned.into_inner().should_emit("etw_events_lost"),
        };
        if decision.should_emit {
            warn!(
                session = session_name,
                session_lost = events_lost,
                lost_total = self.total(),
                suppressed_warnings = decision.suppressed_since_last_emit,
                "ETW discarded events because its kernel buffer pool was exhausted"
            );
        }
    }
}

pub(super) fn spawn(
    sessions: [(&'static str, Session); 2],
    shutdown: Arc<AtomicBool>,
    counters: Arc<LossCounters>,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("etw-loss".into())
        .spawn(move || {
            let mut query_warned = [false; 2];
            while !shutdown.load(Ordering::Relaxed) {
                thread::sleep(POLL_INTERVAL);
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                for (index, (name, session)) in sessions.iter().copied().enumerate() {
                    match query(name, EVENT_TRACE_CONTROL_QUERY) {
                        Ok(events_lost) => counters.record(session, name, events_lost),
                        Err(err) if !query_warned[index] => {
                            query_warned[index] = true;
                            warn!(
                                session = name,
                                "Could not query ETW kernel loss; retrying: {err:#}"
                            );
                        }
                        Err(_) => {}
                    }
                }
            }
            info!(lost_total = counters.total(), "ETW loss monitor stopped");
        })
        .context("failed to spawn ETW loss monitor")
}

/// Stop a session and retain the final `EventsLost` value returned by ETW.
pub(super) fn stop_and_record(
    session_name: &str,
    session: Session,
    counters: &LossCounters,
) -> Result<()> {
    let events_lost = query(session_name, EVENT_TRACE_CONTROL_STOP)?;
    counters.record(session, session_name, events_lost);
    Ok(())
}

fn query(session_name: &str, control: EVENT_TRACE_CONTROL) -> Result<u64> {
    let name: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let total = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * TRACE_NAME_BYTES;
    let mut buffer = PropertiesBuffer::new();
    let properties = &mut buffer.properties as *mut EVENT_TRACE_PROPERTIES;

    // SAFETY: `properties` points to the aligned header of an allocation large
    // enough for both name buffers, and the offsets point into that storage.
    let status = unsafe {
        (*properties).Wnode.BufferSize = total as u32;
        (*properties).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*properties).LogFileNameOffset =
            (size_of::<EVENT_TRACE_PROPERTIES>() + TRACE_NAME_BYTES) as u32;
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            properties,
            control,
        )
    };
    if status.is_err() {
        bail!("ControlTraceW failed for session '{session_name}': {status:?}");
    }

    // ETW exposes a 32-bit per-session counter. Widen before combining the two
    // sessions so their cumulative total cannot overflow at the addition site.
    Ok(unsafe { (*properties).EventsLost as u64 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_are_monotonic_and_sum_both_sessions() {
        let counters = LossCounters::new();
        counters.record(Session::Main, "main", 3);
        counters.record(Session::Process, "process", 5);
        counters.record(Session::Main, "main", 2);

        assert_eq!(counters.total(), 8);
    }
}
