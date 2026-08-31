//! Windows Event Log subscription infrastructure.
//!
//! Each source supplies a channel, an XPath query, and an XML decoder. The
//! subscription lifecycle, native handles, shutdown, and sensor-channel
//! delivery stay shared across System, Security, and Application sources.

mod security;
mod service;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{error::TrySendError, Sender};
use tracing::{info, trace, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_ITEMS, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeToFutureEvents,
    EVT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

use crate::sensor::SensorEvent;

use super::etw::TRACE_SESSION_NAME;

const EVENT_LOG_WAIT: Duration = Duration::from_millis(250);

type EventDecoder = fn(&str) -> Result<SensorEvent>;

#[derive(Clone, Copy)]
struct EventLogSource {
    name: &'static str,
    channel: &'static str,
    query: &'static str,
    decoder: EventDecoder,
}

impl EventLogSource {
    const fn new(
        name: &'static str,
        channel: &'static str,
        query: &'static str,
        decoder: EventDecoder,
    ) -> Self {
        Self {
            name,
            channel,
            query,
            decoder,
        }
    }
}

pub(super) struct EventLogSubscriptions {
    workers: Vec<EventLogSubscription>,
}

impl EventLogSubscriptions {
    pub(super) fn start(tx: Sender<SensorEvent>, shutdown: Arc<AtomicBool>) -> Result<Self> {
        let sources = [service::source(), security::source()];
        let mut workers = Vec::with_capacity(sources.len());

        for source in sources {
            match EventLogSubscription::start(source, tx.clone(), Arc::clone(&shutdown)) {
                Ok(worker) => workers.push(worker),
                Err(err) => {
                    shutdown.store(true, Ordering::Relaxed);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(err);
                }
            }
        }

        Ok(Self { workers })
    }

    pub(super) fn join(self) -> Result<()> {
        let mut first_error = None;
        for worker in self.workers {
            if let Err(err) = worker.join() {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

struct EventLogSubscription {
    worker: JoinHandle<Result<()>>,
}

impl EventLogSubscription {
    fn start(
        source: EventLogSource,
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(format!("event-log-{}", source.name))
            .spawn(move || run_subscription(source, tx, shutdown, startup_tx))
            .with_context(|| format!("failed to spawn {} event log worker", source.name))?;

        match startup_rx.recv() {
            Ok(Ok(())) => Ok(Self { worker }),
            Ok(Err(err)) => {
                let _ = worker.join();
                Err(anyhow!(err))
            }
            Err(_) => {
                let result = worker.join().map_err(|_| {
                    anyhow!("{} event log worker panicked during startup", source.name)
                })?;
                result?;
                Err(anyhow!(
                    "{} event log worker stopped during startup",
                    source.name
                ))
            }
        }
    }

    fn join(self) -> Result<()> {
        self.worker
            .join()
            .map_err(|_| anyhow!("event log worker panicked"))?
    }
}

fn run_subscription(
    source: EventLogSource,
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
    startup_tx: mpsc::SyncSender<std::result::Result<(), String>>,
) -> Result<()> {
    let result = run_subscription_inner(source, tx, Arc::clone(&shutdown), &startup_tx);

    if result.is_err() && !shutdown.swap(true, Ordering::Relaxed) {
        // ETW processing is blocking. Stop it so an event log failure reaches
        // the sensor caller instead of silently removing telemetry.
        let _ = ferrisetw::trace::stop_trace_by_name(TRACE_SESSION_NAME);
    }

    result
}

fn run_subscription_inner(
    source: EventLogSource,
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
    startup_tx: &mpsc::SyncSender<std::result::Result<(), String>>,
) -> Result<()> {
    // Pull subscriptions use a manual-reset event. It starts signaled so the
    // first EvtNext establishes the result-set state, matching Microsoft's
    // reference consumer.
    let signal = match unsafe { CreateEventW(None, true, true, None) } {
        Ok(handle) => OwnedKernelHandle(handle),
        Err(err) => {
            let message = format!("failed to create {} event log signal: {err}", source.name);
            let _ = startup_tx.send(Err(message.clone()));
            return Err(anyhow!(message));
        }
    };

    let channel = wide_string(source.channel);
    let query = wide_string(source.query);
    let subscription = match unsafe {
        EvtSubscribe(
            None,
            Some(signal.0),
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            None,
            None,
            None,
            EvtSubscribeToFutureEvents.0,
        )
    } {
        Ok(handle) => OwnedEvtHandle(handle),
        Err(err) => {
            let message = format!(
                "failed to subscribe to {} events in {}: {err}",
                source.name, source.channel
            );
            let _ = startup_tx.send(Err(message.clone()));
            return Err(anyhow!(message));
        }
    };

    let _ = startup_tx.send(Ok(()));
    info!(
        source = source.name,
        channel = source.channel,
        "Event log subscription started"
    );

    while !shutdown.load(Ordering::Relaxed) {
        let wait = unsafe { WaitForSingleObject(signal.0, EVENT_LOG_WAIT.as_millis() as u32) };
        if wait == WAIT_TIMEOUT {
            continue;
        }
        if wait != WAIT_OBJECT_0 {
            return Err(anyhow!(
                "{} event log wait failed with status {wait:?}",
                source.name
            ));
        }

        drain_events(source, subscription.0, &tx)?;
        unsafe { ResetEvent(signal.0) }
            .map_err(|err| anyhow!("failed to reset {} event log signal: {err}", source.name))?;
    }

    info!(
        source = source.name,
        channel = source.channel,
        "Event log subscription stopped"
    );
    Ok(())
}

fn drain_events(
    source: EventLogSource,
    subscription: EVT_HANDLE,
    tx: &Sender<SensorEvent>,
) -> Result<()> {
    loop {
        let mut raw_events = [0isize; 16];
        let mut returned = 0u32;
        let next = unsafe { EvtNext(subscription, &mut raw_events, 0, 0, &mut returned) };

        match next {
            Ok(()) => {}
            Err(err) if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() => return Ok(()),
            Err(err) => {
                return Err(anyhow!(
                    "failed to read {} event log subscription: {err}",
                    source.name
                ))
            }
        }

        for raw_event in raw_events.into_iter().take(returned as usize) {
            let event_handle = EVT_HANDLE(raw_event);
            let decoded = render_event_xml(event_handle).and_then(|xml| (source.decoder)(&xml));
            unsafe {
                let _ = EvtClose(event_handle);
            }

            match decoded {
                Ok(event) => {
                    if let Err(TrySendError::Closed(_)) = crate::telemetry::try_send(
                        crate::telemetry::ChannelId::SensorEvents,
                        tx,
                        event,
                    ) {
                        trace!(
                            source = source.name,
                            "Sensor event channel closed; dropping event"
                        );
                    }
                }
                Err(err) => warn!(
                    source = source.name,
                    error = %err,
                    "Failed to decode event log record"
                ),
            }
        }
    }
}

fn render_event_xml(event: EVT_HANDLE) -> Result<String> {
    let mut bytes_needed = 0u32;
    let mut property_count = 0u32;
    let _ = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut bytes_needed,
            &mut property_count,
        )
    };
    if bytes_needed < 2 {
        return Err(anyhow!("event XML render returned an empty buffer"));
    }

    let mut buffer = vec![0u16; bytes_needed.div_ceil(2) as usize];
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            bytes_needed,
            Some(buffer.as_mut_ptr().cast()),
            &mut bytes_needed,
            &mut property_count,
        )
    }
    .map_err(|err| anyhow!("failed to render event XML: {err}"))?;

    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).context("event XML was not valid UTF-16")
}

fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct OwnedEvtHandle(EVT_HANDLE);

impl Drop for OwnedEvtHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

struct OwnedKernelHandle(HANDLE);

impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
