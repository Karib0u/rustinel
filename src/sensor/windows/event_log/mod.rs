//! Windows Event Log subscription infrastructure.
//!
//! Each source supplies a channel, an XPath query, and an XML decoder. The
//! subscription lifecycle, native handles, shutdown, and sensor-channel
//! delivery stay shared across System, Security, and Application sources.

mod security;
mod service;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::telemetry::event_log::update;
use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{error::TrySendError, Sender};
use tracing::{info, trace, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    ERROR_EVT_QUERY_RESULT_STALE, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS,
};
use windows::Win32::System::EventLog::*;

use crate::sensor::SensorEvent;

use super::etw::{PROCESS_TRACE_SESSION_NAME, TRACE_SESSION_NAME};

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
    pub(super) fn start(
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
        directory: &Path,
    ) -> Result<Self> {
        let sources = [service::source(), security::source()];
        let mut workers = Vec::with_capacity(sources.len());

        for source in sources {
            match EventLogSubscription::start(
                source,
                tx.clone(),
                Arc::clone(&shutdown),
                directory.join(format!("{}.xml", source.channel)),
            ) {
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
        checkpoint: PathBuf,
    ) -> Result<Self> {
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(format!("event-log-{}", source.name))
            .spawn(move || run_subscription(source, tx, shutdown, startup_tx, checkpoint))
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
    checkpoint: PathBuf,
) -> Result<()> {
    let result =
        run_subscription_inner(source, tx, Arc::clone(&shutdown), &startup_tx, &checkpoint);
    update(source.channel, |health| {
        health.active = false;
        if let Err(err) = &result {
            health.last_error = Some(err.to_string());
        }
    });
    if let Err(err) = &result {
        let _ = startup_tx.try_send(Err(err.to_string()));
    }

    if result.is_err() && !shutdown.swap(true, Ordering::Relaxed) {
        // ETW processing is blocking. Stop it so an event log failure reaches
        // the sensor caller instead of silently removing telemetry. Both
        // sessions are stopped: each has a thread parked in `process()`, and
        // leaving either running holds the sensor open.
        for session in [TRACE_SESSION_NAME, PROCESS_TRACE_SESSION_NAME] {
            let _ = ferrisetw::trace::stop_trace_by_name(session);
        }
    }

    result
}

// The box remains alive until EvtClose has waited for outstanding callbacks.
struct CallbackContext {
    source: EventLogSource,
    tx: Sender<SensorEvent>,
    state: Mutex<CallbackState>,
}

struct CallbackState {
    bookmark: OwnedEvtHandle,
    pending: Option<String>,
    failure: Option<String>,
}

fn run_subscription_inner(
    source: EventLogSource,
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
    startup_tx: &mpsc::SyncSender<std::result::Result<(), String>>,
    checkpoint: &Path,
) -> Result<()> {
    update(source.channel, |health| health.active = false);
    let saved = match std::fs::read_to_string(checkpoint) {
        Ok(xml) => Some(xml),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            update(source.channel, |health| health.checkpoint_errors += 1);
            return Err(err).context("failed to read Event Log checkpoint");
        }
    };
    let saved_wide = saved.as_deref().map(wide_string);
    let bookmark = unsafe {
        EvtCreateBookmark(
            saved_wide
                .as_ref()
                .map_or(PCWSTR::null(), |xml| PCWSTR(xml.as_ptr())),
        )
    }
    .map(OwnedEvtHandle)
    .map_err(|err| {
        update(source.channel, |health| health.checkpoint_errors += 1);
        anyhow!("invalid {} Event Log bookmark: {err}", source.channel)
    })?;
    let mut saved_record_id = None;
    if let Some(xml) = &saved {
        let record_id = bookmark_record_id(xml, source.channel).inspect_err(|_| {
            update(source.channel, |health| health.checkpoint_errors += 1);
        })?;
        saved_record_id = Some(record_id);
        let oldest = oldest_record(source.channel).inspect_err(|_| {
            update(source.channel, |health| health.subscription_errors += 1);
        })?;
        if retention_wrapped(record_id, oldest) {
            update(source.channel, |health| health.retention_wraps += 1);
            warn!(
                channel = source.channel,
                record_id,
                oldest,
                "Event Log downtime retention loss; matching record count unknown"
            );
        }
    }
    // Establish a baseline even when no matching record has been delivered yet.
    // Reading the newest unfiltered record does not infer loss from record gaps.
    let resume = if let Some(record_id) = saved_record_id {
        record_id != 0
    } else {
        seed_bookmark(source.channel, bookmark.0, checkpoint).inspect_err(|_| {
            update(source.channel, |health| health.checkpoint_errors += 1);
        })?
    };
    let context = Box::new(CallbackContext {
        source,
        tx,
        state: Mutex::new(CallbackState {
            bookmark,
            pending: None,
            failure: None,
        }),
    });
    let channel = wide_string(source.channel);
    let query = wide_string(source.query);
    let bookmark_handle = context
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .bookmark
        .0;
    let subscribe = |origin: u32| unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            (origin == EvtSubscribeStartAfterBookmark.0).then_some(bookmark_handle),
            Some((&*context as *const CallbackContext).cast()),
            Some(subscription_callback),
            origin | EvtSubscribeStrict.0,
        )
    };
    let origin = if resume {
        EvtSubscribeStartAfterBookmark.0
    } else {
        EvtSubscribeStartAtOldestRecord.0
    };
    let subscription = match subscribe(origin) {
        Ok(handle) => OwnedEvtHandle(handle),
        Err(err)
            if resume
                && (err.code() == ERROR_NOT_FOUND.to_hresult()
                    || err.code() == ERROR_EVT_QUERY_RESULT_STALE.to_hresult()) =>
        {
            update(source.channel, |health| {
                health.resume_failures += 1;
                health.last_error = Some(format!("strict bookmark resume failed: {err}"));
            });
            warn!(channel = source.channel, error = %err, "Event Log bookmark missing; resuming at oldest available record");
            subscribe(EvtSubscribeStartAtOldestRecord.0)
                .map(OwnedEvtHandle)
                .map_err(|err| subscription_error(source, err))?
        }
        Err(err) => return Err(subscription_error(source, err)),
    };
    {
        let state = context.state.lock().unwrap_or_else(|e| e.into_inner());
        update(source.channel, |health| {
            health.active = state.failure.is_none()
        });
    }
    let _ = startup_tx.send(Ok(()));
    info!(channel = source.channel, "Event log subscription started");
    let result = (|| {
        while !shutdown.load(Ordering::Relaxed) {
            persist_pending(&context, checkpoint)?;
            if let Some(error) = &context
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .failure
            {
                return Err(anyhow!(error.clone()));
            }
            thread::sleep(EVENT_LOG_WAIT);
        }
        Ok(())
    })();
    // Close before the final checkpoint: no callback may change it afterward.
    drop(subscription);
    let final_write = persist_pending(&context, checkpoint);
    result.and(final_write)
}

fn subscription_error(source: EventLogSource, err: windows::core::Error) -> anyhow::Error {
    update(source.channel, |health| health.subscription_errors += 1);
    anyhow!("{} Event Log subscription failed: {err}", source.channel)
}

unsafe extern "system" fn subscription_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user_context: *const core::ffi::c_void,
    event: EVT_HANDLE,
) -> u32 {
    let context = &*(user_context as *const CallbackContext);
    // Never unwind through the Windows callback ABI.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = context.state.lock().unwrap_or_else(|e| e.into_inner());
        if action == EvtSubscribeActionError {
            let code = event.0 as u32;
            let message = if code == ERROR_EVT_QUERY_RESULT_STALE.0 {
                format!("ERROR_EVT_QUERY_RESULT_STALE ({code}): subscribed records are missing")
            } else {
                format!("Event Log subscription error {code}")
            };
            update(context.source.channel, |health| {
                health.subscription_errors += 1;
                if code == ERROR_EVT_QUERY_RESULT_STALE.0 {
                    health.live_stale += 1;
                }
                health.active = false;
                health.last_error = Some(message.clone());
            });
            warn!(
                channel = context.source.channel,
                code, "Event Log subscription error"
            );
            state.failure = Some(message);
            return;
        }
        if action != EvtSubscribeActionDeliver || state.failure.is_some() {
            return;
        }
        let decoded = render_event_xml(event).and_then(|xml| (context.source.decoder)(&xml));
        match decoded {
            Ok(decoded) => {
                update(context.source.channel, |health| {
                    health.delivered += 1;
                    // XPath excludes records. Differences are never counted as loss.
                    health.last_record_id = decoded.source_seq;
                });
                if let Err(TrySendError::Closed(_)) =
                    crate::telemetry::try_send_sensor_event(&context.tx, decoded)
                {
                    trace!(channel = context.source.channel, "Sensor channel closed");
                    return;
                }
            }
            Err(err) => {
                update(context.source.channel, |health| health.decode_errors += 1);
                warn!(channel = context.source.channel, error = %err, "Failed to decode event log record");
            }
        }
        // Checkpoint records handled here, including explicitly accounted queue shedding.
        // Native callback event handles belong to Windows and must not be closed.
        let checkpoint = EvtUpdateBookmark(state.bookmark.0, event)
            .map_err(anyhow::Error::from)
            .and_then(|()| render_xml(state.bookmark.0, EvtRenderBookmark.0));
        match checkpoint {
            Ok(xml) => state.pending = Some(xml),
            Err(err) => {
                update(context.source.channel, |health| {
                    health.checkpoint_errors += 1
                });
                state.failure = Some(format!("Event Log checkpoint update failed: {err}"));
            }
        }
    }));
    if outcome.is_err() {
        update(context.source.channel, |health| {
            health.subscription_errors += 1
        });
        context
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .failure = Some("Event Log callback panicked".into());
    }
    0
}

fn persist_pending(context: &CallbackContext, path: &Path) -> Result<()> {
    let pending = context
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pending
        .take();
    if let Some(xml) = pending {
        write_checkpoint(path, &xml).inspect_err(|_| {
            update(context.source.channel, |health| {
                health.checkpoint_errors += 1
            });
        })?;
    }
    Ok(())
}

fn write_checkpoint(path: &Path, xml: &str) -> Result<()> {
    let directory = path
        .parent()
        .context("checkpoint needs a parent directory")?;
    std::fs::create_dir_all(directory)?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(xml.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|err| err.error)?;
    Ok(())
}

fn seed_bookmark(channel: &str, bookmark: EVT_HANDLE, path: &Path) -> Result<bool> {
    let channel_name = channel;
    let channel = wide_string(channel);
    let query = wide_string("*");
    let result = OwnedEvtHandle(unsafe {
        EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    }?);
    let mut events = [0isize; 1];
    let mut returned = 0;
    match unsafe { EvtNext(result.0, &mut events, 0, 0, &mut returned) } {
        Err(err) if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() => {
            // Zero means the channel was empty, not a missing processed record.
            // Resume it from the oldest record so downtime events are replayed.
            let escaped = channel_name
                .replace('&', "&amp;")
                .replace('"', "&quot;")
                .replace('<', "&lt;");
            write_checkpoint(
                path,
                &format!(
                    r#"<BookmarkList><Bookmark Channel="{escaped}" RecordId="0" IsCurrent="true"/></BookmarkList>"#
                ),
            )?;
            return Ok(false);
        }
        other => other?,
    }
    let event = OwnedEvtHandle(EVT_HANDLE(events[0]));
    unsafe { EvtUpdateBookmark(bookmark, event.0) }?;
    write_checkpoint(path, &render_xml(bookmark, EvtRenderBookmark.0)?)?;
    Ok(true)
}

fn retention_wrapped(record_id: u64, oldest: u64) -> bool {
    // The bookmark itself was already processed. Only records after it matter.
    oldest > record_id.saturating_add(1)
}

fn bookmark_record_id(xml: &str, channel: &str) -> Result<u64> {
    let document = roxmltree::Document::parse(xml)?;
    document
        .descendants()
        .find(|node| node.has_tag_name("Bookmark") && node.attribute("Channel") == Some(channel))
        .and_then(|node| node.attribute("RecordId"))
        .context("bookmark has no channel record ID")?
        .parse()
        .context("invalid bookmark record ID")
}

fn oldest_record(channel: &str) -> Result<u64> {
    let channel = wide_string(channel);
    let log = OwnedEvtHandle(unsafe {
        EvtOpenLog(None, PCWSTR(channel.as_ptr()), EvtOpenChannelPath.0)
    }?);
    let mut value = EVT_VARIANT::default();
    let mut used = 0;
    unsafe {
        EvtGetLogInfo(
            log.0,
            EvtLogOldestRecordNumber,
            std::mem::size_of_val(&value) as u32,
            Some(&mut value),
            &mut used,
        )
    }?;
    if value.Type != EvtVarTypeUInt64.0 as u32 {
        return Err(anyhow!("unexpected oldest record number type"));
    }
    Ok(unsafe { value.Anonymous.UInt64Val })
}

fn render_event_xml(event: EVT_HANDLE) -> Result<String> {
    render_xml(event, EvtRenderEventXml.0)
}

fn render_xml(event: EVT_HANDLE, flags: u32) -> Result<String> {
    let mut bytes_needed = 0u32;
    let mut property_count = 0u32;
    let _ = unsafe {
        EvtRender(
            None,
            event,
            flags,
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
            flags,
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

#[cfg(test)]
mod tests;
