//! Periodic handoff of partially filled ETW buffers.
//!
//! ETW flushes a real-time session when a buffer fills or the session's
//! one-second `FlushTimer` expires. A lone event can therefore wait almost one
//! second before the consumer sees it. `ControlTraceW(EVENT_TRACE_CONTROL_FLUSH)`
//! requests the same handoff without changing the session buffer sizing.
//!
//! The main session pauses forced flushing while Rustinel's sensor queue is at
//! least half full. The process session keeps flushing because delaying its
//! callback also delays the live-process `CommandLine` lookup, and short-lived
//! processes may exit before that lookup runs.
//!
//! The two sessions are flushed at different rates, because they are flushed
//! for different reasons. The main session is flushed to bound *alert* latency,
//! which the 20 ms default covers. The Kernel-Process session is flushed to win
//! a race against process exit: `CommandLine` is read out of the live process,
//! and on this lab VM a `cmd /c echo` is gone often enough that a 20 ms handoff
//! captured only 60% of them, against 99.9% at 5 ms. That rate is only
//! affordable because the process session is small - flushing the 256 KB
//! burst-absorbing session 200 times a second would hand over mostly empty
//! buffers and give back what #312 bought.
//!
//! The two intervals are separate configuration options. `0` on the main
//! session is a latency-for-syscalls trade an operator may reasonably want;
//! `0` on the process session drops short-lived command-line capture to 16.6%,
//! since that session then falls back to the one-second timer, and has to be
//! asked for on its own.

use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_PROPERTIES,
};

use super::registry_value_data::session_handle;
use crate::sensor::SensorEvent;

pub(super) const DEFAULT_INTERVAL_MS: u64 = 20;
const MIN_INTERVAL: Duration = Duration::from_millis(20);

/// Default handoff interval for the dedicated Kernel-Process session, in
/// milliseconds.
///
/// Barely a tuning knob: it is set by how long a short-lived process lives, not
/// by a latency preference. Measured on the Windows 11 lab VM over 2,000
/// `cmd /c echo` runs - 20 ms captured 61.5% of their command lines, 10 ms
/// 99.9%, 5 ms 99.85%, 1 ms 99.8%, against 100% for the pre-#312 session. 5 ms
/// is chosen over 10 ms for margin on a faster host: the sweep shows the cost
/// is flat below 10 ms, with the agent's CPU indistinguishable across the whole
/// range.
pub(super) const DEFAULT_PROCESS_INTERVAL_MS: u64 = 5;

/// Floor for the process session, so a misconfigured interval cannot turn the
/// flush thread into a spin on the syscall.
const PROCESS_MIN_INTERVAL: Duration = Duration::from_millis(1);

const MAX_QUEUE_PERCENT_FOR_FLUSH: usize = 50;
const TRACE_NAME_BYTES: usize = 2 * 1024;

/// An explicitly aligned header followed by the name storage `ControlTraceW`
/// expects. The header gives the allocation the API's required alignment.
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

/// Handoff interval for the main session, from `windows.etw_flush_interval_ms`.
///
/// `0` disables forced flushing altogether; anything else is raised to
/// [`MIN_INTERVAL`], below which the syscall cost is not worth paying for
/// providers with no deadline of their own.
pub(super) fn main_interval(interval_ms: u64) -> Option<Duration> {
    if interval_ms == 0 {
        return None;
    }
    Some(Duration::from_millis(interval_ms).max(MIN_INTERVAL))
}

/// Handoff interval for the Kernel-Process session, from
/// `windows.etw_process_flush_interval_ms`.
///
/// Read from its own option rather than from the main session's, because
/// `etw_flush_interval_ms = 0` is a reasonable thing for an operator to want -
/// it trades alert latency for one less periodic syscall - and it must not
/// silently take `CommandLine` collection down with it. Zero here disables the
/// process handoff explicitly, and measures 16.6% short-lived command-line
/// capture against 99.9% at the 5 ms default.
pub(super) fn process_interval(interval_ms: u64) -> Option<Duration> {
    if interval_ms == 0 {
        return None;
    }
    Some(Duration::from_millis(interval_ms).max(PROCESS_MIN_INTERVAL))
}

pub(super) fn spawn(
    session_name: &str,
    interval: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    sensor_tx: Sender<SensorEvent>,
    pause_on_backpressure: bool,
) -> Result<Option<JoinHandle<()>>> {
    let Some(interval) = interval else {
        return Ok(None);
    };

    let handle = session_handle(session_name).with_context(|| {
        format!("could not resolve forced ETW flush handle for session '{session_name}'")
    })?;

    if pause_on_backpressure {
        info!(
            "Forced ETW flush enabled: every {} ms while the sensor queue is below {}% (session '{}')",
            interval.as_millis(),
            MAX_QUEUE_PERCENT_FOR_FLUSH,
            session_name
        );
    } else {
        info!(
            "Forced ETW flush enabled: every {} ms without queue pausing (session '{}')",
            interval.as_millis(),
            session_name
        );
    }

    let name = session_name.to_string();
    let worker = thread::Builder::new()
        .name("etw-flush".into())
        .spawn(move || {
            run(
                handle,
                interval,
                shutdown,
                sensor_tx,
                pause_on_backpressure,
                &name,
            )
        })
        .with_context(|| {
            format!("failed to spawn ETW flush thread for session '{session_name}'")
        })?;
    Ok(Some(worker))
}

fn queue_is_backed_up<T>(sensor_tx: &Sender<T>) -> bool {
    let capacity = sensor_tx.max_capacity();
    let depth = capacity.saturating_sub(sensor_tx.capacity());
    depth.saturating_mul(100) >= capacity.saturating_mul(MAX_QUEUE_PERCENT_FOR_FLUSH)
}

fn should_pause_flush<T>(sensor_tx: &Sender<T>, pause_on_backpressure: bool) -> bool {
    pause_on_backpressure && queue_is_backed_up(sensor_tx)
}

fn run(
    handle: CONTROLTRACE_HANDLE,
    interval: Duration,
    shutdown: Arc<AtomicBool>,
    sensor_tx: Sender<SensorEvent>,
    pause_on_backpressure: bool,
    name: &str,
) {
    let mut warned = false;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(interval);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if should_pause_flush(&sensor_tx, pause_on_backpressure) {
            continue;
        }

        let mut buffer = PropertiesBuffer::new();
        let properties = &mut buffer.properties as *mut EVENT_TRACE_PROPERTIES;
        let total = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * TRACE_NAME_BYTES;

        // SAFETY: `properties` points to the aligned header in `buffer`, the
        // allocation is at least `total` bytes, and both name offsets point
        // into its trailing storage. The API may write throughout that block.
        let status = unsafe {
            (*properties).Wnode.BufferSize = total as u32;
            (*properties).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*properties).LogFileNameOffset =
                (size_of::<EVENT_TRACE_PROPERTIES>() + TRACE_NAME_BYTES) as u32;
            ControlTraceW(
                handle,
                PCWSTR::null(),
                properties,
                EVENT_TRACE_CONTROL_FLUSH,
            )
        };

        if status.is_err() && !warned {
            warned = true;
            warn!("Forced ETW flush failed for session '{name}': {status:?}; buffers still flush on the session timer");
        }
    }

    info!("ETW flush thread stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_disables_forced_flushing() {
        assert!(main_interval(0).is_none());
        assert!(process_interval(0).is_none());
    }

    #[test]
    fn interval_is_clamped_to_twenty_milliseconds() {
        assert_eq!(DEFAULT_INTERVAL_MS, 20);
        assert_eq!(main_interval(1), Some(MIN_INTERVAL));
        assert_eq!(
            main_interval(DEFAULT_INTERVAL_MS),
            Some(Duration::from_millis(DEFAULT_INTERVAL_MS))
        );
    }

    #[test]
    fn process_session_is_flushed_faster_than_the_main_one() {
        // The measured cliff: at the main session's 20 ms interval the
        // command-line back-fill captured 61.5% of `cmd /c echo` runs, and
        // 99.85% at 5 ms. A process default that tracked the main one would
        // reintroduce #349.
        const { assert!(DEFAULT_PROCESS_INTERVAL_MS < DEFAULT_INTERVAL_MS) };
        assert!(
            process_interval(DEFAULT_PROCESS_INTERVAL_MS) < main_interval(DEFAULT_INTERVAL_MS),
            "the process session must be handed its buffers sooner than the main one"
        );
        assert_eq!(
            process_interval(DEFAULT_PROCESS_INTERVAL_MS),
            Some(Duration::from_millis(DEFAULT_PROCESS_INTERVAL_MS))
        );
    }

    #[test]
    fn the_two_intervals_are_configured_independently() {
        // `etw_flush_interval_ms = 0` is a reasonable operator choice, and it
        // must not take `CommandLine` collection down with it: the process
        // session reads its own option, so nothing here consults the main one.
        assert_eq!(
            process_interval(DEFAULT_PROCESS_INTERVAL_MS),
            Some(Duration::from_millis(5)),
            "the process interval must not depend on the main session's"
        );
        // Only the main session is clamped to 20 ms; clamping the process
        // session there is exactly the bug.
        assert_eq!(main_interval(5), Some(MIN_INTERVAL));
        assert_eq!(process_interval(5), Some(Duration::from_millis(5)));
    }

    #[test]
    fn the_process_interval_is_floored_but_not_capped() {
        assert_eq!(process_interval(1), Some(PROCESS_MIN_INTERVAL));
        assert_eq!(process_interval(2), Some(Duration::from_millis(2)));
        assert_eq!(process_interval(50), Some(Duration::from_millis(50)));
    }

    #[test]
    fn queue_guard_activates_at_half_capacity() {
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        assert!(!queue_is_backed_up(&tx));
        tx.try_send(()).expect("first event fits");
        assert!(!queue_is_backed_up(&tx));
        tx.try_send(()).expect("second event fits");
        assert!(queue_is_backed_up(&tx));
        assert!(should_pause_flush(&tx, true));
        assert!(!should_pause_flush(&tx, false));
    }
}
