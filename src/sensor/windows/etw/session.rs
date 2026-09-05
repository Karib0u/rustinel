//! ETW session configuration, callbacks, and processing lifecycle.

use super::super::{registry_rundown, registry_value_data};
use super::decode::decode_record;
use super::providers::{EtwProvider, EtwProviders};
use super::state::EtwState;
use super::{EtwSensor, PROCESS_TRACE_SESSION_NAME, TRACE_SESSION_NAME};
use crate::sensor::SensorEvent;
use anyhow::Result;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::trace::{TraceBuilder, TraceProperties, TraceTrait, UserTrace};
use ferrisetw::GUID;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tracing::{info, trace, warn};

/// Size of one ETW session buffer, in KB.
///
/// `ferrisetw` defaults to 32 KB with the buffer counts left at 0, which lets
/// the kernel pick them - in practice 2 to 24 buffers, a 768 KB ceiling. That
/// ceiling cannot absorb a burst. On a Windows 11 lab VM (6 vCPU, 8 GB), a
/// 4,000-process fork tree lost 12-60% of process starts on the defaults across
/// four runs, and none at all on the values here; the workload and the full
/// table are in `docs/operations.md`.
///
/// The loss is kernel-side, so no per-field fix reaches it - it degrades
/// `CommandLine`, `ParentImage` and every other process field at once, and a
/// lost *parent* start costs `ParentImage` on all of that process's children.
/// Larger buffers are what helps: the cost of a burst is buffer *turnover*, and
/// 256 KB holds eight times the events per flush. See [`SESSION_MIN_BUFFERS`]
/// for the memory this commits.
pub(super) const SESSION_BUFFER_SIZE_KB: u32 = 256;

/// Buffers committed when the session starts.
///
/// ETW session buffers are non-paged pool, allocated up front for the minimum
/// and grown on demand to [`SESSION_MAX_BUFFERS`]. 64 x 256 KB is 16 MB
/// resident - deliberately paid at startup rather than during the burst,
/// because growing the pool is exactly the work that is too slow when a fork
/// tree is already filling buffers.
pub(super) const SESSION_MIN_BUFFERS: u32 = 64;

/// Upper bound on the buffer pool: 128 x 256 KB = 32 MB.
///
/// 42x the default ceiling. This is a fixed configuration on purpose - adaptive
/// sizing is not warranted until a single configuration is shown not to cover
/// realistic hosts.
pub(super) const SESSION_MAX_BUFFERS: u32 = 128;

/// How often partially filled buffers are flushed to the consumer.
///
/// One second is the ETW minimum. It bounds the delay on a *quiet* host, where
/// buffers would otherwise sit unfilled; under load buffers flush as soon as
/// they fill, so this does not affect burst behaviour either way.
pub(super) const SESSION_FLUSH_TIMER: Duration = Duration::from_secs(1);

/// Buffer configuration for the real-time session.
///
/// Everything else is inherited from `ferrisetw`'s defaults, in particular the
/// logging mode: `EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING` is kept on purpose.
/// Per-processor buffering would raise raw throughput, but it delivers events
/// per CPU rather than in timestamp order, and both [`FilePathCache`] and
/// [`RegistryPathCache`] resolve a path by pairing a naming event with a later
/// event on the same object - reordering those silently mis-attributes paths.
/// A wider buffer pool buys the same headroom without touching ordering.
pub(super) fn session_properties() -> TraceProperties {
    TraceProperties {
        buffer_size: SESSION_BUFFER_SIZE_KB,
        min_buffer: SESSION_MIN_BUFFERS,
        max_buffer: SESSION_MAX_BUFFERS,
        flush_timer: SESSION_FLUSH_TIMER,
        ..TraceProperties::default()
    }
}

/// Size of one buffer on the Kernel-Process session, in KB.
///
/// The small buffer is the point of the second session. A buffer is handed to
/// the consumer when it fills, and a 256 KB buffer carrying only process and
/// image-load events takes far longer to fill than a 32 KB one - on a quiet
/// host it never does, and delivery falls back on the flush timer. That is the
/// regression #349 describes: the back-fill race window went from ~8-16 ms to
/// ~100 ms-1 s when #312 widened the shared session, and a `cmd /c echo` exits
/// inside it. 32 KB is the value that measured 15/15 short-lived command lines
/// in 1.3.0.
pub(super) const PROCESS_SESSION_BUFFER_SIZE_KB: u32 = 32;

/// Buffers committed when the Kernel-Process session starts: 2 MB.
pub(super) const PROCESS_SESSION_MIN_BUFFERS: u32 = 64;

/// Upper bound on the Kernel-Process buffer pool: 512 x 32 KB = 16 MB.
///
/// The buffer counts are set explicitly for the same reason [`session_properties`]
/// sets them: left at `0` the kernel picks at most 24 buffers, a 768 KB ceiling
/// that lost 12-60% of process starts under a fork tree (#312). Small buffers
/// and a deep pool are not in tension - the first bounds latency, the second
/// bounds burst loss - so this session keeps 1.3.0's latency without giving up
/// #312's headroom for the events that matter most to it.
pub(super) const PROCESS_SESSION_MAX_BUFFERS: u32 = 512;

/// Buffer configuration for the dedicated Kernel-Process session.
///
/// Deliberately close to `ferrisetw`'s defaults, which is what Rustinel ran on
/// before #312: the same 32 KB buffer and the same one-second flush timer, with
/// only the pool depth raised. The logging mode is inherited for the same
/// reason as the main session - event order within a session is load-bearing -
/// though nothing on this session pairs events the way the path caches do.
pub(super) fn process_session_properties() -> TraceProperties {
    TraceProperties {
        buffer_size: PROCESS_SESSION_BUFFER_SIZE_KB,
        min_buffer: PROCESS_SESSION_MIN_BUFFERS,
        max_buffer: PROCESS_SESSION_MAX_BUFFERS,
        flush_timer: SESSION_FLUSH_TIMER,
        ..TraceProperties::default()
    }
}

/// Ask the registry provider to include value data, once the session exists.
///
/// This cannot be part of building the provider: `ferrisetw` has no way to
/// express the filter payload it needs, so the provider is re-enabled by hand
/// on the running session. A failure is logged and tolerated because the
/// mechanism is undocumented and may not hold on every Windows build.
pub(super) fn request_registry_value_data() {
    let provider = EtwProviders::kernel_registry();
    match registry_value_data::request_value_data(
        TRACE_SESSION_NAME,
        to_windows_guid(provider.guid),
        provider.level,
        provider.keywords,
        provider.event_ids,
    ) {
        Ok(()) => info!("Registry value data capture enabled"),
        Err(err) => warn!(
            "Could not enable registry value data capture ({err:#}); \
             registry Details will be unavailable"
        ),
    }
}

/// Seed the key-path index with the keys that were already open.
///
/// Deliberately after `trace.start()`: a key opened between the snapshot and
/// the session start would be in neither, whereas one opened between the
/// session start and the snapshot is in both, and the live index wins. Cost is
/// a one-shot ~32 ms sweep of the handle table; see [`registry_rundown`].
pub(super) fn seed_registry_paths(state: &EtwState) {
    let keys = registry_rundown::snapshot_open_keys();
    let count = keys.len();
    state.registry_paths().seed(keys);
    crate::telemetry::REGISTRY.set_snapshot_keys(count);

    if count == 0 {
        // Not fatal, but it means every write through a pre-session handle is
        // invisible again, so it must not be silent.
        warn!(
            "Registry key rundown found no open keys; writes through handles \
             older than the trace session will be dropped"
        );
    } else {
        info!("Registry key rundown seeded {count} pre-existing keys");
    }
}

/// `ferrisetw` is built against a different `windows` version than this crate,
/// so the two `GUID` types are distinct despite being the same four fields.
pub(super) fn to_windows_guid(guid: GUID) -> windows::core::GUID {
    windows::core::GUID {
        data1: guid.data1,
        data2: guid.data2,
        data3: guid.data3,
        data4: guid.data4,
    }
}

/// Attach `providers` to a named session and return the builder.
///
/// Every provider gets the same callback: routing is by provider GUID inside
/// [`decode_record`], not by which session delivered the record, so the split
/// is invisible below this point.
pub(super) fn build_session(
    session_name: &str,
    properties: TraceProperties,
    providers: Vec<EtwProvider>,
    state: &Arc<EtwState>,
    tx: &Sender<SensorEvent>,
) -> TraceBuilder<UserTrace> {
    info!(
        "ETW session '{}' buffers: {} KB x {}-{} ({} MB ceiling), flush {}s",
        session_name,
        properties.buffer_size,
        properties.min_buffer,
        properties.max_buffer,
        (properties.buffer_size as u64 * properties.max_buffer as u64) / 1024,
        properties.flush_timer.as_secs(),
    );

    let mut trace_builder = UserTrace::new()
        .named(session_name.to_string())
        .set_trace_properties(properties);

    for provider_def in providers {
        info!(
            "Enabling ETW provider: {} ({:?}) with level {} and keywords: 0x{:X} on session '{}'",
            provider_def.name,
            provider_def.guid,
            provider_def.level,
            provider_def.keywords,
            session_name
        );

        let state = Arc::clone(state);
        let tx = tx.clone();
        let mut provider_builder = Provider::by_guid(provider_def.guid)
            .level(provider_def.level)
            .any(provider_def.keywords)
            .add_callback(move |record, schema_locator| {
                let decoded = decode_record(record, schema_locator, &state);
                for event in decoded.replayed.into_iter().chain(decoded.primary) {
                    // Blocking inside an ETW callback stalls the trace
                    // session and loses events in the kernel buffer instead,
                    // so overflow is shed. The telemetry counters record both
                    // outcomes and emit the rate-limited cumulative warning.
                    if let Err(TrySendError::Closed(_)) =
                        crate::telemetry::try_send_sensor_event(&tx, event)
                    {
                        trace!("Sensor event channel closed; dropping ETW event");
                    }
                }
            });

        if !provider_def.event_ids.is_empty() {
            provider_builder = provider_builder
                .add_filter(EventFilter::ByEventIds(provider_def.event_ids.to_vec()));
        }

        trace_builder = trace_builder.enable(provider_builder.build());
    }

    trace_builder
}

/// Interpret the return of a blocking `process()` call.
///
/// Stopping a trace from `shutdown()` makes `process()` return an error by
/// design; only a failure while the sensor is supposed to keep running is a
/// real one, and it must reach the caller - logging alone buries the ETW error
/// code in the operational log (#256).
pub(super) fn interpret_process_result(
    session_name: &str,
    result: std::result::Result<(), ferrisetw::trace::TraceError>,
    shutting_down: bool,
) -> Result<()> {
    match result {
        Ok(()) => {
            info!("ETW trace session '{session_name}' stopped");
            Ok(())
        }
        Err(err) if shutting_down => {
            info!("ETW trace session '{session_name}' stopped with result: {err:?}");
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!(
            "ETW trace processing failed for session '{session_name}': {err:?}"
        )),
    }
}

impl EtwSensor {
    /// Start both sessions and block on the main one until shutdown.
    ///
    /// The two sessions are started before either is processed, so a failure to
    /// create the second one is reported as a startup error rather than as a
    /// sensor that silently runs without process events.
    pub(super) fn run_sessions(&self, tx: &Sender<SensorEvent>) -> Result<()> {
        let state = Arc::new(EtwState::new());

        let main_builder = build_session(
            TRACE_SESSION_NAME,
            session_properties(),
            EtwProviders::main_session(),
            &state,
            tx,
        );
        let process_builder = build_session(
            PROCESS_TRACE_SESSION_NAME,
            process_session_properties(),
            EtwProviders::process_session(),
            &state,
            tx,
        );

        let (mut main_trace, _main_handle) = main_builder
            .start()
            .map_err(|err| anyhow::anyhow!("Failed to start ETW trace: {err:?}"))?;
        info!("ETW trace session '{TRACE_SESSION_NAME}' started successfully");

        request_registry_value_data();
        seed_registry_paths(&state);

        // Dropping `main_trace` on this path stops the session it created, so
        // a half-started pair cannot be left behind for the next run to trip
        // over.
        let (process_trace, process_handle) = process_builder
            .start()
            .map_err(|err| anyhow::anyhow!("Failed to start ETW process trace: {err:?}"))?;
        info!("ETW trace session '{PROCESS_TRACE_SESSION_NAME}' started successfully");

        // Check the worker before blocking on the main session. Otherwise a
        // thread-creation failure would leave the sensor running forever with
        // no consumer for process events.
        let process_worker = self.spawn_process_trace_worker(process_handle)?;

        let loss_monitor = match super::super::loss::spawn(
            [
                (TRACE_SESSION_NAME, super::super::loss::Session::Main),
                (
                    PROCESS_TRACE_SESSION_NAME,
                    super::super::loss::Session::Process,
                ),
            ],
            Arc::clone(&self.shutdown),
            Arc::clone(&self.loss_counters),
        ) {
            Ok(worker) => worker,
            Err(err) => {
                self.shutdown.store(true, Ordering::Relaxed);
                let _ = super::super::loss::stop_and_record(
                    TRACE_SESSION_NAME,
                    super::super::loss::Session::Main,
                    &self.loss_counters,
                );
                let _ = super::super::loss::stop_and_record(
                    PROCESS_TRACE_SESSION_NAME,
                    super::super::loss::Session::Process,
                    &self.loss_counters,
                );
                let _ = process_worker.join();
                drop(process_trace);
                return Err(err);
            }
        };

        // The process flusher is required whenever its interval is enabled:
        // without it, short-lived command-line capture falls back to 16.6%.
        let process_flusher = match super::super::flush::spawn(
            PROCESS_TRACE_SESSION_NAME,
            super::super::flush::process_interval(self.process_flush_interval_ms),
            Arc::clone(&self.shutdown),
            tx.clone(),
            false,
        ) {
            Ok(flusher) => flusher,
            Err(err) => {
                self.shutdown.store(true, Ordering::Relaxed);
                let _ = super::super::loss::stop_and_record(
                    TRACE_SESSION_NAME,
                    super::super::loss::Session::Main,
                    &self.loss_counters,
                );
                let _ = super::super::loss::stop_and_record(
                    PROCESS_TRACE_SESSION_NAME,
                    super::super::loss::Session::Process,
                    &self.loss_counters,
                );
                let _ = process_worker.join();
                let _ = loss_monitor.join();
                drop(process_trace);
                return Err(err);
            }
        };

        // Failure of the main session's optional latency optimization keeps
        // the existing behavior: ETW's native timer still delivers events.
        let main_flusher = super::super::flush::spawn(
            TRACE_SESSION_NAME,
            super::super::flush::main_interval(self.flush_interval_ms),
            Arc::clone(&self.shutdown),
            tx.clone(),
            true,
        )
        .unwrap_or_else(|err| {
            warn!("Forced ETW flush disabled for main session: {err:#}");
            None
        });
        let flushers = [main_flusher, process_flusher];

        let main_result = interpret_process_result(
            TRACE_SESSION_NAME,
            main_trace.process(),
            self.shutdown.load(Ordering::Relaxed),
        );

        // Whatever ended the main session ends the sensor. The process session
        // is stopped by name so its blocking `process_from_handle` returns and
        // the worker can be joined; `process_trace` would do the same on drop,
        // but only after the join has already deadlocked.
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = super::super::loss::stop_and_record(
            TRACE_SESSION_NAME,
            super::super::loss::Session::Main,
            &self.loss_counters,
        );
        let _ = super::super::loss::stop_and_record(
            PROCESS_TRACE_SESSION_NAME,
            super::super::loss::Session::Process,
            &self.loss_counters,
        );

        let process_result = process_worker
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("ETW process trace thread panicked")));

        for flusher in flushers.into_iter().flatten() {
            let _ = flusher.join();
        }
        let _ = loss_monitor.join();

        drop(process_trace);
        main_result.and(process_result)
    }

    /// Run the Kernel-Process session on its own thread.
    ///
    /// A second `process()` cannot share the main thread - the call blocks
    /// until its session stops. The handle is processed rather than the trace
    /// itself so the `UserTrace` stays with the caller, which is what stops the
    /// session when this function's caller returns.
    pub(super) fn spawn_process_trace_worker(
        &self,
        handle: ferrisetw::native::TraceHandle,
    ) -> Result<std::thread::JoinHandle<Result<()>>> {
        let shutdown = Arc::clone(&self.shutdown);
        let loss_counters = Arc::clone(&self.loss_counters);
        std::thread::Builder::new()
            .name("etw-process-trace".into())
            .spawn(move || {
                let result = interpret_process_result(
                    PROCESS_TRACE_SESSION_NAME,
                    UserTrace::process_from_handle(handle),
                    shutdown.load(Ordering::Relaxed),
                );

                // The main session's `process()` is blocking, so a failure here
                // would otherwise sit unnoticed until the agent is stopped by
                // hand, with every process event missing in the meantime. Stop
                // the main session to make the failure reach the caller - the
                // same contract `run_subscription` uses for the event logs.
                if result.is_err() && !shutdown.swap(true, Ordering::Relaxed) {
                    let _ = super::super::loss::stop_and_record(
                        TRACE_SESSION_NAME,
                        super::super::loss::Session::Main,
                        &loss_counters,
                    );
                }

                result
            })
            .map_err(|err| anyhow::anyhow!("Failed to spawn ETW process trace thread: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::providers::EtwProviders;
    use super::super::PROCESS_TRACE_SESSION_NAME;
    use super::super::TRACE_SESSION_NAME;
    use super::*;
    use ferrisetw::trace::TraceProperties;
    use std::time::Duration;

    #[test]
    fn session_properties_are_set_explicitly() {
        // The bug this guards is silent: leaving the properties at their
        // defaults cost 12-60% of process starts under a fork tree, with no
        // error and no counter (#306). Assert the session is not running on
        // `ferrisetw`'s defaults, and that the pool it asks for is large
        // enough to matter.
        let props = session_properties();
        let defaults = TraceProperties::default();

        assert!(
            props.buffer_size > defaults.buffer_size,
            "buffer size must be raised above the {} KB default",
            defaults.buffer_size
        );
        assert!(
            props.min_buffer > 0 && props.max_buffer >= props.min_buffer,
            "buffer counts must be explicit and ordered, got {}-{}",
            props.min_buffer,
            props.max_buffer
        );

        // The default ceiling is 24 x 32 KB; anything close to it is not a fix.
        let ceiling_kb = props.buffer_size as u64 * props.max_buffer as u64;
        assert!(
            ceiling_kb >= 16 * 1024,
            "buffer pool ceiling is only {ceiling_kb} KB"
        );

        // Below one second ETW clamps silently, so the value would not be the
        // configured one.
        assert!(props.flush_timer >= Duration::from_secs(1));

        // Ordering is load-bearing for the path caches; inheriting the default
        // logging mode is what keeps it. See `session_properties`.
        assert_eq!(props.log_file_mode, defaults.log_file_mode);
    }

    #[test]
    fn process_session_trades_buffer_size_for_pool_depth() {
        // The two properties this session exists for, and they pull in
        // opposite directions if only one number is available to tune: a
        // *small* buffer so it fills and is handed over before a short-lived
        // process exits (#349), and a *deep* pool so a fork tree does not
        // overrun it the way `ferrisetw`'s defaults did (#312).
        let props = process_session_properties();
        let main = session_properties();
        let defaults = TraceProperties::default();

        assert!(
            props.buffer_size <= defaults.buffer_size,
            "process buffers must not be larger than the {} KB default that measured 15/15",
            defaults.buffer_size
        );
        assert!(
            props.buffer_size < main.buffer_size,
            "a process session sized like the main session is not a fix"
        );

        assert!(
            props.min_buffer > 0 && props.max_buffer >= props.min_buffer,
            "buffer counts must be explicit and ordered, got {}-{}",
            props.min_buffer,
            props.max_buffer
        );
        let ceiling_kb = props.buffer_size as u64 * props.max_buffer as u64;
        assert!(
            ceiling_kb >= 16 * 1024,
            "process buffer pool ceiling is only {ceiling_kb} KB"
        );

        assert!(props.flush_timer >= Duration::from_secs(1));
        assert_eq!(props.log_file_mode, defaults.log_file_mode);
    }

    #[test]
    fn sessions_partition_the_providers() {
        // A provider dropped from both lists is silent telemetry loss, and one
        // enabled on both is a duplicate of every event it carries.
        let mut split: Vec<&str> = EtwProviders::process_session()
            .iter()
            .chain(EtwProviders::main_session().iter())
            .map(|provider| provider.name)
            .collect();
        let mut all: Vec<&str> = EtwProviders::all()
            .iter()
            .map(|provider| provider.name)
            .collect();
        split.sort_unstable();
        all.sort_unstable();

        assert_eq!(split, all, "provider split does not cover every provider");
        let unique = {
            let mut names = split.clone();
            names.dedup();
            names
        };
        assert_eq!(unique, split, "a provider is enabled on both sessions");
    }

    #[test]
    fn only_kernel_process_is_split_off() {
        // Registry must stay on the main session: `RegistryPathCache` pairs a
        // write with the `OpenKey` that named its key, and that pairing only
        // holds within one session's ordering. Kernel-File has the same
        // constraint through `FilePathCache`.
        let names: Vec<&str> = EtwProviders::process_session()
            .iter()
            .map(|provider| provider.name)
            .collect();
        assert_eq!(names, vec!["Microsoft-Windows-Kernel-Process"]);
    }

    #[test]
    fn sessions_have_distinct_names() {
        assert_ne!(TRACE_SESSION_NAME, PROCESS_TRACE_SESSION_NAME);
    }

    #[test]
    fn shutdown_is_not_treated_as_a_processing_failure() {
        // `stop_trace_by_name` makes the blocking `process()` return an error;
        // reporting that as a sensor failure would make every clean stop look
        // like a crash, and swallowing it unconditionally would hide a real one
        // (#256).
        let err = || Err(ferrisetw::trace::TraceError::InvalidTraceName);

        assert!(interpret_process_result(TRACE_SESSION_NAME, err(), true).is_ok());
        assert!(interpret_process_result(TRACE_SESSION_NAME, err(), false).is_err());
        assert!(interpret_process_result(TRACE_SESSION_NAME, Ok(()), false).is_ok());
    }
}
