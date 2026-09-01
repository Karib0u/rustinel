//! Periodic handoff of partially filled ETW buffers.
//!
//! ETW flushes a real-time session when a buffer fills or the session's
//! one-second `FlushTimer` expires. A lone event can therefore wait almost one
//! second before the consumer sees it. `ControlTraceW(EVENT_TRACE_CONTROL_FLUSH)`
//! requests the same handoff without changing the session buffer sizing.
//!
//! Forced flushing pauses while Rustinel's sensor queue is at least half full.
//! At that point buffers already fill quickly and downstream queueing, rather
//! than ETW's timer, controls alert latency.
//!
//! The two sessions are flushed at different rates, because they are flushed
//! for different reasons. The main session is flushed to bound *alert* latency,
//! which the 20 ms default covers. The Kernel-Process session is flushed to win
//! a race against process exit: `CommandLine` is read out of the live process,
//! and on this lab VM a `cmd /c echo` is gone often enough that a 20 ms handoff
//! captured only 60% of them, against 99.9% at 5 ms. That rate is only
//! affordable because the process session is small — flushing the 256 KB
//! burst-absorbing session 200 times a second would hand over mostly empty
//! buffers and give back what #312 bought.

use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

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

/// Handoff interval for the dedicated Kernel-Process session.
///
/// Not a tuning knob: it is set by how long a short-lived process lives, not by
/// a latency preference. Measured on the Windows 11 lab VM over 2,000
/// `cmd /c echo` runs — 20 ms captured 61.5% of their command lines, 10 ms
/// 99.9%, 5 ms 99.85%, 1 ms 99.8%, against 100% for the pre-#312 session. 5 ms
/// is chosen over 10 ms for margin on a faster host: the sweep shows the cost
/// is flat below 10 ms, with the agent's CPU indistinguishable across the whole
/// range.
const PROCESS_INTERVAL: Duration = Duration::from_millis(5);

/// Floor for the process session, for an operator who configures a shorter
/// interval than [`PROCESS_INTERVAL`] for the main one.
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

/// Handoff interval for the Kernel-Process session.
///
/// Fixed at [`PROCESS_INTERVAL`] rather than configured, because it is the
/// back-fill race that sets it. The one thing the configuration still decides
/// is whether forced flushing happens at all, and an operator who asks for a
/// *faster* main session gets at least that on the process session too.
pub(super) fn process_interval(interval_ms: u64) -> Option<Duration> {
    if interval_ms == 0 {
        return None;
    }
    Some(
        Duration::from_millis(interval_ms)
            .min(PROCESS_INTERVAL)
            .max(PROCESS_MIN_INTERVAL),
    )
}

pub(super) fn spawn(
    session_name: &str,
    interval: Option<Duration>,
    shutdown: Arc<AtomicBool>,
    sensor_tx: Sender<SensorEvent>,
) -> Option<JoinHandle<()>> {
    let interval = interval?;

    let handle = match session_handle(session_name) {
        Ok(handle) => handle,
        Err(err) => {
            warn!(
                "Forced ETW flush disabled: could not resolve control handle for '{session_name}': {err:#}"
            );
            return None;
        }
    };

    info!(
        "Forced ETW flush enabled: every {} ms while the sensor queue is below {}% (session '{}')",
        interval.as_millis(),
        MAX_QUEUE_PERCENT_FOR_FLUSH,
        session_name
    );

    let name = session_name.to_string();
    thread::Builder::new()
        .name("etw-flush".into())
        .spawn(move || run(handle, interval, shutdown, sensor_tx, &name))
        .map_err(|err| warn!("Failed to spawn ETW flush thread: {err}"))
        .ok()
}

fn queue_is_backed_up<T>(sensor_tx: &Sender<T>) -> bool {
    let capacity = sensor_tx.max_capacity();
    let depth = capacity.saturating_sub(sensor_tx.capacity());
    depth.saturating_mul(100) >= capacity.saturating_mul(MAX_QUEUE_PERCENT_FOR_FLUSH)
}

fn run(
    handle: CONTROLTRACE_HANDLE,
    interval: Duration,
    shutdown: Arc<AtomicBool>,
    sensor_tx: Sender<SensorEvent>,
    name: &str,
) {
    let mut warned = false;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(interval);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if queue_is_backed_up(&sensor_tx) {
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
        // 99.85% at 5 ms. A process interval that tracked the main one would
        // reintroduce #349.
        assert!(PROCESS_INTERVAL < MIN_INTERVAL);
        assert_eq!(
            process_interval(DEFAULT_INTERVAL_MS),
            Some(PROCESS_INTERVAL),
            "the default configuration must not slow the process session down"
        );
        assert_eq!(
            process_interval(10_000),
            Some(PROCESS_INTERVAL),
            "a relaxed main interval must not relax the back-fill race"
        );
    }

    #[test]
    fn a_faster_main_interval_is_honoured_by_the_process_session() {
        assert_eq!(process_interval(2), Some(Duration::from_millis(2)));
        // Still floored, so a misconfiguration cannot spin on the syscall.
        assert_eq!(process_interval(1), Some(PROCESS_MIN_INTERVAL));
    }

    #[test]
    fn queue_guard_activates_at_half_capacity() {
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        assert!(!queue_is_backed_up(&tx));
        tx.try_send(()).expect("first event fits");
        assert!(!queue_is_backed_up(&tx));
        tx.try_send(()).expect("second event fits");
        assert!(queue_is_backed_up(&tx));
    }
}
