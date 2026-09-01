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

fn configured_interval(interval_ms: u64) -> Option<Duration> {
    if interval_ms == 0 {
        return None;
    }
    Some(Duration::from_millis(interval_ms).max(MIN_INTERVAL))
}

pub(super) fn spawn(
    session_name: &str,
    interval_ms: u64,
    shutdown: Arc<AtomicBool>,
    sensor_tx: Sender<SensorEvent>,
) -> Option<JoinHandle<()>> {
    let interval = configured_interval(interval_ms)?;

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
        assert!(configured_interval(0).is_none());
    }

    #[test]
    fn interval_is_clamped_to_twenty_milliseconds() {
        assert_eq!(DEFAULT_INTERVAL_MS, 20);
        assert_eq!(configured_interval(1), Some(MIN_INTERVAL));
        assert_eq!(
            configured_interval(DEFAULT_INTERVAL_MS),
            Some(Duration::from_millis(DEFAULT_INTERVAL_MS))
        );
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
