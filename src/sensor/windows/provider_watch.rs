//! Detects an ETW provider being switched off under a running session.
//!
//! A session that stops entirely already ends the sensor, which the shutdown
//! path reports. `logman update trace <session> --p <provider> 0 0 -ets`
//! leaves the session running and its heartbeats flowing while one telemetry
//! family goes silent, and nothing else notices.
//!
//! The agent records what it enabled on each session, then every
//! [`CHECK_INTERVAL`] asks the kernel what each session has enabled
//! (`EnumerateTraceGuidsEx(TraceGuidQueryInfo)`) and compares. A difference is
//! alerted once per change, not once per check.
//!
//! Scope: enablement, level and keywords. Event ID filters and the registry
//! `CapturedData` payload are part of what the agent asked for, but the
//! kernel does not report either back, so a re-enable that restores the same
//! level and keywords without them cannot be seen here.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, EnumerateTraceGuidsEx, TraceGuidQueryInfo, TraceQueryInformation,
    TraceSystemTraceEnableFlagsInfo, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_PROPERTIES,
};

use crate::models::ecs::{AgentTamper, EcsAlert};
use crate::state::AgentAlertWriter;
use crate::telemetry::EtwProviderWatchSnapshot;
use crate::vocab::Platform;

/// How often each session's providers are compared with the expected set.
pub(super) const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Granularity at which the worker notices shutdown while waiting.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

const TRACE_NAME_BYTES: usize = 2 * 1024;
const TAMPER_KIND: &str = "etw_provider_modified";
const CLASSIC_SESSION_PROVIDER: &str = "NT Kernel Logger (process)";

/// One provider the agent enabled on a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExpectedProvider {
    pub(super) session: &'static str,
    pub(super) name: &'static str,
    pub(super) guid: GUID,
    pub(super) level: u8,
    pub(super) keywords: u64,
    /// The registry provider is re-enabled with a `CapturedData` payload. It
    /// is recorded so an alert can name it, but it is not observable.
    pub(super) captured_data: bool,
}

/// What a session reports for one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Observed {
    NotEnabled,
    Enabled { level: u8, keywords: u64 },
}

/// The session-wide view the kernel gives of a running session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionInfo {
    pub(super) logger_id: u16,
    pub(super) enable_flags: u32,
}

/// One `TRACE_ENABLE_INFO` row of a provider query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EnableInfo {
    pub(super) is_enabled: bool,
    pub(super) level: u8,
    pub(super) logger_id: u16,
    pub(super) keywords: u64,
}

/// A difference between expected and observed, ready to alert on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Change {
    pub(super) kind: &'static str,
    pub(super) expected: String,
    pub(super) observed: String,
    pub(super) detail: String,
}

/// Compare one provider's expectation with what its session reports.
pub(super) fn compare(expected: &ExpectedProvider, observed: Observed) -> Option<Change> {
    let describe = |level: u8, keywords: u64| format!("level {level}, keywords 0x{keywords:X}");
    let want = describe(expected.level, expected.keywords);
    match observed {
        Observed::NotEnabled => Some(Change {
            kind: "provider_disabled",
            expected: want,
            observed: "not enabled".to_string(),
            detail: "the provider is no longer enabled on the session".to_string(),
        }),
        Observed::Enabled { level, keywords } => {
            // The keyword mask is the stronger signal, so it is named first
            // when both moved.
            let kind = if keywords != expected.keywords {
                "keywords_changed"
            } else if level != expected.level {
                "level_changed"
            } else {
                return None;
            };
            Some(Change {
                kind,
                expected: want,
                observed: describe(level, keywords),
                detail: if kind == "keywords_changed" {
                    "the keyword mask was changed".to_string()
                } else {
                    "the level was changed".to_string()
                },
            })
        }
    }
}

/// The classic kernel session carries flags rather than provider GUIDs.
fn compare_classic(session: &'static str, flags: u32) -> Option<Change> {
    let wanted = EVENT_TRACE_FLAG_PROCESS.0;
    if flags & wanted == wanted {
        return None;
    }
    Some(Change {
        kind: "kernel_flags_changed",
        expected: format!("flags 0x{wanted:X}"),
        observed: format!("flags 0x{flags:X}"),
        detail: format!("the process flag was removed from session {session}"),
    })
}

/// Pick this session's row out of a provider query.
pub(super) fn observe(rows: &[EnableInfo], logger_id: u16) -> Observed {
    rows.iter()
        .find(|row| row.logger_id == logger_id && row.is_enabled)
        .map(|row| Observed::Enabled {
            level: row.level,
            keywords: row.keywords,
        })
        .unwrap_or(Observed::NotEnabled)
}

/// Decode the buffer `EnumerateTraceGuidsEx(TraceGuidQueryInfo)` fills.
///
/// Layout: `TRACE_GUID_INFO { InstanceCount, Reserved }`, then per instance a
/// `TRACE_PROVIDER_INSTANCE_INFO { NextOffset, EnableCount, Pid, Flags }`
/// followed by `EnableCount` x `TRACE_ENABLE_INFO`. `NextOffset` is relative
/// to the instance and zero on the last one.
pub(super) fn parse_guid_info(buffer: &[u8]) -> Vec<EnableInfo> {
    const INSTANCE_HEADER: usize = 16;
    const ENABLE_INFO: usize = 32;

    let read_u32 = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(buffer.get(at..at + 4)?.try_into().ok()?))
    };
    let mut rows = Vec::new();
    let Some(instances) = read_u32(0) else {
        return rows;
    };
    let mut instance = 8usize;
    for _ in 0..instances {
        let (Some(next), Some(count)) = (read_u32(instance), read_u32(instance + 4)) else {
            break;
        };
        for index in 0..count as usize {
            let at = instance + INSTANCE_HEADER + index * ENABLE_INFO;
            let Some(row) = buffer.get(at..at + ENABLE_INFO) else {
                return rows;
            };
            rows.push(EnableInfo {
                is_enabled: u32::from_le_bytes(row[0..4].try_into().unwrap()) != 0,
                level: row[4],
                logger_id: u16::from_le_bytes(row[6..8].try_into().unwrap()),
                keywords: u64::from_le_bytes(row[16..24].try_into().unwrap()),
            });
        }
        if next == 0 {
            break;
        }
        instance += next as usize;
    }
    rows
}

#[repr(C)]
struct PropertiesBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    names: [u8; 2 * TRACE_NAME_BYTES],
}

/// Look up a running session by name.
pub(super) fn query_session(session_name: &str) -> Result<SessionInfo> {
    let name: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let total = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * TRACE_NAME_BYTES;
    let mut buffer = Box::new(PropertiesBuffer {
        properties: EVENT_TRACE_PROPERTIES::default(),
        names: [0; 2 * TRACE_NAME_BYTES],
    });
    let properties = &mut buffer.properties as *mut EVENT_TRACE_PROPERTIES;

    // SAFETY: `properties` points at the aligned header in `buffer`, which is
    // at least `total` bytes, and both name offsets point into its tail.
    let status = unsafe {
        (*properties).Wnode.BufferSize = total as u32;
        (*properties).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*properties).LogFileNameOffset =
            (size_of::<EVENT_TRACE_PROPERTIES>() + TRACE_NAME_BYTES) as u32;
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            properties,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if status.is_err() {
        bail!("ControlTraceW(QUERY) failed for session '{session_name}': {status:?}");
    }
    // SAFETY: the query succeeded, so the header is initialised.
    let (handle, enable_flags) = unsafe {
        (
            (*properties).Wnode.Anonymous1.HistoricalContext,
            (*properties).EnableFlags.0,
        )
    };
    // A system logger keeps its current flags in the group mask, which
    // `EnableFlags` does not follow once the session has been updated.
    let mut mask = [0u32; 8];
    let mut returned = 0u32;
    // SAFETY: `mask` outlives the call and its byte size is passed.
    let queried = unsafe {
        TraceQueryInformation(
            CONTROLTRACE_HANDLE { Value: handle },
            TraceSystemTraceEnableFlagsInfo,
            mask.as_mut_ptr() as *mut c_void,
            std::mem::size_of_val(&mask) as u32,
            Some(&mut returned),
        )
    };
    let enable_flags = if queried.is_ok() && returned >= 4 {
        mask[0]
    } else {
        enable_flags
    };
    // The logger ID is the low word of the session handle.
    Ok(SessionInfo {
        logger_id: (handle & 0xFFFF) as u16,
        enable_flags,
    })
}

/// Every session's enablement of `guid`.
pub(super) fn query_provider(guid: &GUID) -> Result<Vec<EnableInfo>> {
    // 8-byte alignment for the structures the kernel writes into the buffer.
    let mut storage = vec![0u64; 256];
    loop {
        let mut returned = 0u32;
        let bytes = storage.len() * size_of::<u64>();
        // SAFETY: `guid` and `storage` outlive the call, and `bytes` is the
        // real size of `storage`.
        let status = unsafe {
            EnumerateTraceGuidsEx(
                TraceGuidQueryInfo,
                Some(guid as *const GUID as *const c_void),
                size_of::<GUID>() as u32,
                Some(storage.as_mut_ptr() as *mut c_void),
                bytes as u32,
                &mut returned,
            )
        };
        if status == ERROR_INSUFFICIENT_BUFFER || status == ERROR_MORE_DATA {
            storage = vec![
                0u64;
                (returned as usize)
                    .div_ceil(size_of::<u64>())
                    .max(storage.len() * 2)
            ];
            continue;
        }
        if status.is_err() {
            bail!("EnumerateTraceGuidsEx failed for {guid:?}: {status:?}");
        }
        // SAFETY: `returned` bytes were initialised at the start of `storage`.
        let filled = unsafe { std::slice::from_raw_parts(storage.as_ptr() as *const u8, bytes) };
        return Ok(parse_guid_info(&filled[..(returned as usize).min(bytes)]));
    }
}

/// Counters behind the `etw_provider_watch` entry of `telemetry.json`.
#[derive(Debug, Default)]
pub(crate) struct ProviderWatchCounters {
    checks: AtomicU64,
    mismatches: AtomicU64,
    alerts: AtomicU64,
    query_errors: AtomicU64,
}

impl ProviderWatchCounters {
    pub(crate) fn snapshot(&self) -> Option<EtwProviderWatchSnapshot> {
        let checks = self.checks.load(Ordering::Relaxed);
        let query_errors = self.query_errors.load(Ordering::Relaxed);
        if checks == 0 && query_errors == 0 {
            return None;
        }
        Some(EtwProviderWatchSnapshot {
            checks,
            mismatches: self.mismatches.load(Ordering::Relaxed),
            alerts: self.alerts.load(Ordering::Relaxed),
            query_errors,
        })
    }
}

/// The classic kernel session, when the agent managed to start it.
pub(super) struct ClassicExpectation {
    pub(super) session: &'static str,
}

/// Reports changes and remembers what it already reported.
struct Reporter {
    sink: Option<AgentAlertWriter>,
    counters: Arc<ProviderWatchCounters>,
    reported: HashMap<(&'static str, String), Change>,
}

impl Reporter {
    /// `None` clears a previous report, so the same change alerts again if it
    /// recurs after the provider was restored.
    fn record(
        &mut self,
        session: &'static str,
        provider: &'static str,
        guid: String,
        change: Option<Change>,
        expected: &ExpectedProvider,
    ) {
        let key = (session, guid.clone());
        let Some(change) = change else {
            if self.reported.remove(&key).is_some() {
                info!(
                    session,
                    provider, "ETW provider matches its configuration again"
                );
            }
            return;
        };
        self.counters.mismatches.fetch_add(1, Ordering::Relaxed);
        if self.reported.get(&key) == Some(&change) {
            return;
        }
        warn!(
            session,
            provider,
            change = change.kind,
            expected = %change.expected,
            observed = %change.observed,
            "ETW provider was modified while the session kept running"
        );
        self.counters.alerts.fetch_add(1, Ordering::Relaxed);
        if let Some(write) = &self.sink {
            write(&EcsAlert::agent_tamper(
                Platform::Windows,
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                AgentTamper {
                    kind: TAMPER_KIND,
                    change: change.kind,
                    session,
                    provider,
                    provider_guid: format!("{:?}", expected.guid).to_lowercase(),
                    expected: change.expected.clone(),
                    observed: change.observed.clone(),
                    detail: change.detail.clone(),
                },
            ));
        }
        self.reported.insert(key, change);
    }
}

/// Run one comparison pass over every expected provider.
fn check_once(
    expected: &[ExpectedProvider],
    classic: Option<&ClassicExpectation>,
    reporter: &mut Reporter,
) {
    let counters = Arc::clone(&reporter.counters);
    let mut sessions: HashMap<&'static str, SessionInfo> = HashMap::new();
    let mut failed = false;

    for provider in expected {
        let info = match sessions.get(provider.session) {
            Some(info) => *info,
            None => match query_session(provider.session) {
                Ok(info) => {
                    sessions.insert(provider.session, info);
                    info
                }
                Err(err) => {
                    debug!("ETW provider check skipped: {err:#}");
                    counters.query_errors.fetch_add(1, Ordering::Relaxed);
                    failed = true;
                    continue;
                }
            },
        };
        let rows = match query_provider(&provider.guid) {
            Ok(rows) => rows,
            Err(err) => {
                debug!("ETW provider check skipped: {err:#}");
                counters.query_errors.fetch_add(1, Ordering::Relaxed);
                failed = true;
                continue;
            }
        };
        let change = compare(provider, observe(&rows, info.logger_id));
        reporter.record(
            provider.session,
            provider.name,
            format!("{:?}", provider.guid),
            change,
            provider,
        );
    }

    if let Some(classic) = classic {
        match query_session(classic.session) {
            Ok(info) => {
                let marker = ExpectedProvider {
                    session: classic.session,
                    name: CLASSIC_SESSION_PROVIDER,
                    guid: GUID::zeroed(),
                    level: 0,
                    keywords: 0,
                    captured_data: false,
                };
                let change = compare_classic(classic.session, info.enable_flags);
                reporter.record(
                    classic.session,
                    CLASSIC_SESSION_PROVIDER,
                    "classic-process".to_string(),
                    change,
                    &marker,
                );
            }
            Err(err) => {
                debug!("ETW provider check skipped: {err:#}");
                counters.query_errors.fetch_add(1, Ordering::Relaxed);
                failed = true;
            }
        }
    }

    if !failed {
        counters.checks.fetch_add(1, Ordering::Relaxed);
    }
}

/// Start the watcher thread. It runs until `shutdown` is set.
pub(super) fn spawn(
    expected: Vec<ExpectedProvider>,
    classic: Option<ClassicExpectation>,
    shutdown: Arc<AtomicBool>,
    sink: Option<AgentAlertWriter>,
    counters: Arc<ProviderWatchCounters>,
    interval: Duration,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("etw-provider-watch".into())
        .spawn(move || {
            let mut reporter = Reporter {
                sink,
                counters,
                reported: HashMap::new(),
            };
            loop {
                let mut waited = Duration::ZERO;
                while waited < interval {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(SHUTDOWN_POLL);
                    waited += SHUTDOWN_POLL;
                }
                check_once(&expected, classic.as_ref(), &mut reporter);
            }
        })
        .context("Failed to start ETW provider watch thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> ExpectedProvider {
        ExpectedProvider {
            session: "rustinel-etw-trace",
            name: "Microsoft-Windows-Kernel-Registry",
            guid: GUID::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd),
            level: 4,
            keywords: 0x7101,
            captured_data: true,
        }
    }

    fn buffer(rows: &[(u32, u8, u16, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(1u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((rows.len() as u32).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        for &(enabled, level, logger, keywords) in rows {
            out.extend(enabled.to_le_bytes());
            out.push(level);
            out.push(0);
            out.extend(logger.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend(keywords.to_le_bytes());
            out.extend(0u64.to_le_bytes());
        }
        out
    }

    #[test]
    fn parses_enable_rows_and_picks_the_session() {
        let rows = parse_guid_info(&buffer(&[(1, 4, 7, 0x7101), (1, 5, 9, 0x20)]));
        assert_eq!(rows.len(), 2);
        assert_eq!(
            observe(&rows, 7),
            Observed::Enabled {
                level: 4,
                keywords: 0x7101
            }
        );
        assert_eq!(observe(&rows, 3), Observed::NotEnabled);
    }

    #[test]
    fn a_disabled_row_is_not_enabled() {
        let rows = parse_guid_info(&buffer(&[(0, 4, 7, 0x7101)]));
        assert_eq!(observe(&rows, 7), Observed::NotEnabled);
    }

    #[test]
    fn truncated_buffers_do_not_panic() {
        let full = buffer(&[(1, 4, 7, 0x7101)]);
        for len in 0..full.len() {
            let _ = parse_guid_info(&full[..len]);
        }
    }

    #[test]
    fn matching_state_is_not_a_change() {
        let observed = Observed::Enabled {
            level: 4,
            keywords: 0x7101,
        };
        assert_eq!(compare(&expected(), observed), None);
    }

    #[test]
    fn every_kind_of_drift_is_named() {
        let disabled = compare(&expected(), Observed::NotEnabled).unwrap();
        assert_eq!(disabled.kind, "provider_disabled");
        let keywords = compare(
            &expected(),
            Observed::Enabled {
                level: 4,
                keywords: 0x1,
            },
        )
        .unwrap();
        assert_eq!(keywords.kind, "keywords_changed");
        assert_eq!(keywords.observed, "level 4, keywords 0x1");
        let level = compare(
            &expected(),
            Observed::Enabled {
                level: 2,
                keywords: 0x7101,
            },
        )
        .unwrap();
        assert_eq!(level.kind, "level_changed");
    }

    #[test]
    fn classic_session_must_keep_the_process_flag() {
        assert_eq!(compare_classic("s", EVENT_TRACE_FLAG_PROCESS.0), None);
        assert_eq!(compare_classic("s", EVENT_TRACE_FLAG_PROCESS.0 | 0x2), None);
        assert_eq!(
            compare_classic("s", 0).unwrap().kind,
            "kernel_flags_changed"
        );
    }

    #[test]
    fn an_unchanged_mismatch_alerts_once_and_a_restore_rearms_it() {
        let counters = Arc::new(ProviderWatchCounters::default());
        let mut reporter = Reporter {
            sink: None,
            counters: Arc::clone(&counters),
            reported: HashMap::new(),
        };
        let provider = expected();
        let record = |reporter: &mut Reporter, change| {
            reporter.record(
                provider.session,
                provider.name,
                "guid".to_string(),
                change,
                &provider,
            )
        };
        let off = compare(&provider, Observed::NotEnabled);

        record(&mut reporter, off.clone());
        record(&mut reporter, off.clone());
        assert_eq!(counters.alerts.load(Ordering::Relaxed), 1);
        assert_eq!(counters.mismatches.load(Ordering::Relaxed), 2);

        record(&mut reporter, None);
        record(&mut reporter, off);
        assert_eq!(counters.alerts.load(Ordering::Relaxed), 2);
    }
}
