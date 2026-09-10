//! Owned classic system logger, reusable for additional kernel providers.

use super::{session::process_session_properties, state::EtwState};
use crate::sensor::SensorEvent;
use crate::telemetry::WINDOWS_PROCESS_CORRELATION as METRICS;
use anyhow::{Context, Result};
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::trace::{
    stop_trace_by_name, KernelTrace, TraceBuilder, TraceProperties, TraceTrait,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

pub(super) const SESSION_NAME: &str = "rustinel-etw-classic";

pub(super) fn build_session(
    name: &str,
    properties: TraceProperties,
    providers: impl IntoIterator<Item = Provider>,
) -> TraceBuilder<KernelTrace> {
    let mut builder = KernelTrace::new()
        .named(name.to_string())
        .set_trace_properties(properties);
    for provider in providers {
        builder = builder.enable(provider);
    }
    builder
}

pub(super) struct ClassicSession {
    trace: Option<KernelTrace>,
    worker: Option<JoinHandle<()>>,
    expiry: Option<JoinHandle<()>>,
    flusher: Option<JoinHandle<()>>,
    stopped: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    loss: Arc<super::super::loss::LossCounters>,
}

impl ClassicSession {
    pub(super) fn start(
        state: Arc<EtwState>,
        tx: Sender<SensorEvent>,
        loss: Arc<super::super::loss::LossCounters>,
        flush_interval_ms: u64,
    ) -> Result<Self> {
        let mut session = Self {
            trace: None,
            worker: None,
            expiry: None,
            flusher: None,
            stopped: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
            loss,
        };
        let stopped = Arc::clone(&session.stopped);
        let expiry_state = Arc::clone(&state);
        let expiry_tx = tx.clone();
        // Expiry is independent of incoming traffic and remains active if the
        // classic session fails, so fallback creations can never get stranded.
        session.expiry = Some(
            thread::Builder::new()
                .name("etw-process-correlation".into())
                .spawn(move || loop {
                    let all = stopped.load(Ordering::Acquire);
                    let mut correlation = expiry_state
                        .process_correlation
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let events = correlation.expire(Instant::now(), all);
                    send(&expiry_state, &expiry_tx, events);
                    drop(correlation);
                    if all {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                })
                .context("Failed to start process correlation expiry worker")?,
        );
        let flush_tx = tx.clone();
        let failure_tx = tx.clone();
        let callback_state = Arc::clone(&state);
        let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
            .add_callback(move |record, locator| {
                let mut correlation = callback_state
                    .process_correlation
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let events = correlation.classic(record, locator);
                send(&callback_state, &tx, events);
            })
            .build();
        let _ = stop_trace_by_name(SESSION_NAME);
        match build_session(SESSION_NAME, process_session_properties(), [provider]).start() {
            Ok((trace, handle)) => {
                session.trace = Some(trace);
                session.flusher = super::super::flush::spawn(
                    SESSION_NAME, super::super::flush::process_interval(flush_interval_ms),
                    Arc::clone(&session.stopping), flush_tx, false,
                ).unwrap_or_else(|error| {
                    tracing::warn!(%error, "Classic process forced flush unavailable; using native timer");
                    None
                });
                let stopped = Arc::clone(&session.stopping);
                let failure_state = Arc::clone(&state);
                let worker_tx = failure_tx.clone();
                match thread::Builder::new()
                    .name("etw-classic-trace".into())
                    .spawn(move || {
                        let result = KernelTrace::process_from_handle(handle);
                        if !stopped.load(Ordering::Acquire) {
                            METRICS.session_failures.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                ?result,
                                "Classic process collection ended; retaining manifest fallback"
                            );
                            let mut correlation = failure_state
                                .process_correlation
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            send(&failure_state, &worker_tx, correlation.disable());
                        }
                    }) {
                    Ok(worker) => session.worker = Some(worker),
                    Err(error) => {
                        METRICS.session_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%error, "Classic process consumer unavailable; retaining manifest fallback");
                        session.trace.take();
                    }
                }
            }
            Err(error) => {
                METRICS.session_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    ?error,
                    "Classic process session unavailable; retaining manifest fallback"
                );
            }
        }
        if session.trace.is_none() {
            let mut correlation = state
                .process_correlation
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            send(&state, &failure_tx, correlation.disable());
        }
        Ok(session)
    }
}

pub(super) fn send(state: &EtwState, tx: &Sender<SensorEvent>, events: Vec<SensorEvent>) {
    for mut event in events {
        state.attribute_process_identity(&mut event);
        let _ = crate::telemetry::try_send_sensor_event(tx, event);
    }
}

impl Drop for ClassicSession {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if self.trace.is_some() {
            let _ = super::super::loss::stop_and_record(
                SESSION_NAME,
                super::super::loss::Session::Classic,
                &self.loss,
            );
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.trace.take();
        if let Some(flusher) = self.flusher.take() {
            let _ = flusher.join();
        }
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.expiry.take() {
            let _ = worker.join();
        }
    }
}
