//! Host-state boundary between native sensor facts and canonical events.
//!
//! Sensors finish decoding before this boundary.  Filesystem, process, account,
//! and registry-backed enrichment belongs here (or in the stateful normalizer
//! it owns), never in an ETW callback, Endpoint Security callback, or eBPF ring
//! drain.

use std::sync::Arc;

use crate::models::{CanonicalEvent, NormalizedEvent};
use crate::normalizer::Normalizer;
use crate::sensor::{RawEvent, RawPayload};

use super::{DnsCache, ProcessCache, SidCache};

/// Host-dependent enrichment and canonicalization state.
pub struct HostState {
    normalizer: Normalizer,
}

impl HostState {
    pub fn new(
        process_cache: Arc<ProcessCache>,
        sid_cache: Arc<SidCache>,
        dns_cache: Arc<DnsCache>,
    ) -> Self {
        Self {
            normalizer: Normalizer::new(process_cache, sid_cache, dns_cache),
        }
    }

    /// Enrich one raw event and create the semantic cross-platform boundary.
    pub fn canonicalize(&self, mut event: RawEvent) -> Option<CanonicalEvent> {
        self.enrich(&mut event);
        let normalized = self.normalizer.normalize(&event)?;
        let pid = match &event.payload {
            RawPayload::Process(process) => Some(process.process_id),
            _ => event.pid,
        };
        Some(CanonicalEvent::new(
            normalized,
            event.action,
            pid,
            event.process_start_key,
            event.parent_process_start_key,
        ))
    }

    /// Attach live-only process context after a detector has selected an alert.
    pub fn enrich_process_context(
        &self,
        event: &mut NormalizedEvent,
        process_start_key: Option<crate::sensor::ProcessStartKey>,
    ) {
        self.normalizer
            .enrich_process_context(event, process_start_key);
    }

    fn enrich(&self, event: &mut RawEvent) {
        #[cfg(windows)]
        {
            enrich_windows_process(event);
            crate::sensor::windows::enrich_event(event);
        }

        #[cfg(not(windows))]
        let _ = event;
    }
}

#[cfg(windows)]
fn enrich_windows_process(event: &mut RawEvent) {
    use crate::sensor::{RawPayload, SensorAction};

    if event.platform != crate::sensor::Platform::Windows {
        return;
    }
    let RawPayload::Process(process) = &mut event.payload else {
        return;
    };
    for value in [&mut process.image, &mut process.parent_image]
        .into_iter()
        .flatten()
    {
        *value = crate::utils::convert_nt_to_dos(value);
    }
    if event.action != SensorAction::Start {
        return;
    }
    let live = event.process_start_key.and_then(|key| {
        crate::utils::query_process_command_line_at_start(process.process_id, key.start_time)
    });
    enrich_windows_command_line(process, live);
}

#[cfg(any(windows, test))]
pub(crate) fn enrich_windows_command_line(
    process: &mut crate::sensor::RawProcessEvent,
    live: Option<String>,
) {
    let crate::sensor::RawProcessPlatform::Windows(source) = process.platform.as_mut() else {
        return;
    };
    let correlated = std::mem::take(&mut source.correlation_pending);
    let mut conflicting = false;
    if let Some(live) = live {
        match process.command_line.as_ref() {
            None => {
                process.command_line = Some(live);
                source.command_line_source = Some("live_query".into());
            }
            Some(captured)
                if source.command_line_may_be_truncated
                    && live.len() > captured.len()
                    && live.starts_with(captured) =>
            {
                source.classic_command_line = Some(captured.clone());
                process.command_line = Some(live);
                source.command_line_source = Some("live_query".into());
            }
            Some(captured) if captured != &live => {
                source.conflicting_live_command_line = Some(live);
                conflicting = true;
            }
            Some(_) => {}
        }
    }
    if correlated {
        let metrics = &crate::telemetry::WINDOWS_PROCESS_CORRELATION;
        let counter = if conflicting {
            tracing::warn!(
                pid = process.process_id,
                "Classic command line differs from live-query value"
            );
            &metrics.conflicting
        } else {
            &metrics.matched
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventFields;
    use crate::sensor::{
        Platform, RawLinuxProcess, RawLinuxProcessIdentity, RawPayload, RawProcessEvent,
        RawProcessPlatform, RawUserId, SensorAction, SensorNormalization,
    };
    use std::time::SystemTime;

    fn state() -> HostState {
        HostState::new(
            Arc::new(ProcessCache::new()),
            Arc::new(SidCache::new()),
            Arc::new(DnsCache::new()),
        )
    }

    #[test]
    fn windows_live_command_line_preserves_capture_and_recovers_only_truncated_prefixes() {
        for (captured, live, truncated, expected, conflict) in [
            ("captured", Some("changed"), false, "captured", true),
            ("captured", Some("captured"), false, "captured", false),
            ("captured", None, false, "captured", false),
            (
                "prefix",
                Some("prefix suffix"),
                true,
                "prefix suffix",
                false,
            ),
            ("prefix", Some("prefix suffix"), false, "prefix", true),
        ] {
            let mut process = RawProcessEvent::from_compatibility(
                serde_json::from_value(serde_json::json!({"ProcessId": "42"})).unwrap(),
                Platform::Windows,
                Some(42),
            );
            process.command_line = Some(captured.into());
            let source = process.windows_mut().unwrap();
            source.command_line_source = Some("classic".into());
            source.command_line_may_be_truncated = truncated;
            source.correlation_pending = true;
            enrich_windows_command_line(&mut process, live.map(String::from));
            assert_eq!(process.command_line.as_deref(), Some(expected));
            let source = process.windows_mut().unwrap();
            assert!(!source.correlation_pending);
            assert_eq!(source.conflicting_live_command_line.is_some(), conflict);
            assert_eq!(
                source.classic_command_line.as_deref(),
                (expected != captured).then_some(captured)
            );
        }
    }

    #[test]
    fn numeric_raw_process_facts_are_rendered_only_after_host_state() {
        let raw = RawEvent {
            platform: Platform::Linux,
            provider: "ebpf",
            action: SensorAction::Start,
            normalization: SensorNormalization {
                event_id: 1,
                action_code: 1,
            },
            pid: Some(42),
            timestamp: SystemTime::UNIX_EPOCH,
            source_seq: Some(7),
            process_start_key: None,
            parent_process_start_key: None,
            payload: RawPayload::Process(RawProcessEvent {
                process_id: 42,
                parent_process_id: Some(7),
                process_start_time: None,
                image: Some("/usr/bin/true".into()),
                command_line: Some("/usr/bin/true".into()),
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some(RawUserId::Unix(u32::MAX)),
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                platform: Box::new(RawProcessPlatform::Linux(RawLinuxProcess {
                    real_user_id: Some(u32::MAX),
                    identity: RawLinuxProcessIdentity {
                        real_group_id: Some(u32::MAX),
                        ..Default::default()
                    },
                    cgroup_id: Some(99),
                    image_source: Some("execve".into()),
                    image_truncated: None,
                    parent_process_id_derived: false,
                })),
            }),
        };

        let canonical = state().canonicalize(raw).expect("process canonicalizes");
        let EventFields::ProcessCreation(fields) = &canonical.normalized().fields else {
            panic!("expected process view")
        };
        assert_eq!(fields.process_id.as_deref(), Some("42"));
        assert_eq!(fields.parent_process_id.as_deref(), Some("7"));
        assert_eq!(fields.cgroup_id.as_deref(), Some("99"));
    }
}
