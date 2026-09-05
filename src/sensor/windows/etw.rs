//! Windows ETW sensor lifecycle and public interface.

mod decode;
mod parser;
mod providers;
mod routing;
mod session;
mod state;

use super::event_log::EventLogSubscriptions;
use crate::sensor::{Sensor, SensorEvent};
use anyhow::Result;
use ferrisetw::trace::stop_trace_by_name;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

/// Fixed trace session name for stopping the trace on shutdown.
pub(super) const TRACE_SESSION_NAME: &str = "rustinel-etw-trace";

/// Session name for the dedicated `Microsoft-Windows-Kernel-Process` trace.
///
/// Process events are collected in their own session because they are the only
/// ones with a *latency* requirement: `CommandLine` is not carried by any
/// Kernel-Process event version, so it is read back out of the PEB in
/// [`decode::decode_process`], and that read only succeeds while the process is still
/// alive. `cmd /c echo` lives 10-30 ms. Every other provider needs the
/// opposite - the wide buffer pool of [`session::session_properties`], which is what
/// makes a buffer take a long time to fill and be handed over. One session
/// cannot satisfy both; two can. See [`session::process_session_properties`] and
/// [`super::flush`], which flushes this session four times as often.
pub(super) const PROCESS_TRACE_SESSION_NAME: &str = "rustinel-etw-process";

/// Windows ETW sensor implementation.
pub struct EtwSensor {
    shutdown: Arc<AtomicBool>,
    loss_counters: Arc<super::loss::LossCounters>,
    flush_interval_ms: u64,
    process_flush_interval_ms: u64,
}

impl EtwSensor {
    pub fn new() -> Self {
        Self::with_flush_intervals(
            super::flush::DEFAULT_INTERVAL_MS,
            super::flush::DEFAULT_PROCESS_INTERVAL_MS,
        )
    }

    /// The two sessions are configured separately on purpose; see
    /// [`super::flush::process_interval`].
    pub fn with_flush_intervals(flush_interval_ms: u64, process_flush_interval_ms: u64) -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            loss_counters: Arc::new(super::loss::LossCounters::new()),
            flush_interval_ms,
            process_flush_interval_ms,
        }
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Cumulative kernel-buffer loss across both ETW sessions.
    pub fn events_lost(&self) -> u64 {
        self.loss_counters.total()
    }
}

impl Default for EtwSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for EtwSensor {
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        info!("Starting ETW sensor...");

        self.shutdown.store(false, Ordering::Relaxed);
        self.loss_counters.reset();
        let event_logs = EventLogSubscriptions::start(tx.clone(), Arc::clone(&self.shutdown))?;

        // A session left running by a previous process keeps its old buffer
        // sizing and its old providers, and `start` would then bind to it.
        let _ = stop_trace_by_name(TRACE_SESSION_NAME);
        let _ = stop_trace_by_name(PROCESS_TRACE_SESSION_NAME);

        let trace_result = self.run_sessions(&tx);

        self.shutdown.store(true, Ordering::Relaxed);
        event_logs.join().and(trace_result)
    }

    fn shutdown(&self) {
        info!("Initiating graceful shutdown of ETW sensor...");
        self.shutdown.store(true, Ordering::Relaxed);

        for session in [TRACE_SESSION_NAME, PROCESS_TRACE_SESSION_NAME] {
            info!("Stopping ETW trace session '{session}'...");
            let kind = if session == TRACE_SESSION_NAME {
                super::loss::Session::Main
            } else {
                super::loss::Session::Process
            };
            if let Err(err) = super::loss::stop_and_record(session, kind, &self.loss_counters) {
                warn!("Failed to stop trace session '{session}': {err:?}");
            }
        }
    }
}
