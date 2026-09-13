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
    use crate::sensor::{RawPayload, RawProcessPlatform, SensorAction};

    if event.action != SensorAction::Start || event.platform != crate::sensor::Platform::Windows {
        return;
    }
    let Some(start_time) = event.process_start_key.map(|key| key.start_time) else {
        return;
    };
    let RawPayload::Process(process) = &mut event.payload else {
        return;
    };
    let RawProcessPlatform::Windows(source) = process.platform.as_mut() else {
        return;
    };
    let Some(live) =
        crate::utils::query_process_command_line_at_start(process.process_id, start_time)
    else {
        return;
    };

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
        }
        Some(_) => {}
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
