//! Bounded correlation of classic creation facts and manifest process identity.

use super::parser::{filetime_to_system_time, try_get_uint_as_u64};
use crate::sensor::{SensorAction, SensorEvent, SensorPayload};
use crate::telemetry::WINDOWS_PROCESS_CORRELATION as METRICS;
use ferrisetw::{parser::Parser, schema_locator::SchemaLocator, EventRecord};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(2);
const CAPACITY: usize = 4096;
// These are adjacent notifications from the same creation, not an arbitrary
// PID lookup. Require creation time and near-identical source timestamps.
const PAIR_SKEW: Duration = Duration::from_millis(1);

pub(super) struct ClassicProcess {
    pid: u32,
    parent: u32,
    at: std::time::SystemTime,
    object: u64,
    stopped_at: Option<std::time::SystemTime>,
    rundown: bool,
    session_id: Option<u32>,
    command_line: Option<String>,
    sid: Option<String>,
}

struct Pending<T> {
    received: Instant,
    value: T,
}

#[derive(Default)]
pub(super) struct ProcessCorrelation {
    classic: HashMap<u32, VecDeque<Pending<ClassicProcess>>>,
    manifest: HashMap<u32, VecDeque<Pending<SensorEvent>>>,
    count: usize,
    unavailable: bool,
}

impl ProcessCorrelation {
    pub(super) fn classic(
        &mut self,
        record: &EventRecord,
        locator: &SchemaLocator,
    ) -> Vec<SensorEvent> {
        METRICS
            .classic_records
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !matches!(record.opcode(), 1..=3) {
            return Vec::new();
        }
        let Ok(schema) = locator.event_schema(record) else {
            METRICS
                .decode_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Vec::new();
        };
        let parser = Parser::create(record, &schema);
        let Some(pid) =
            try_get_uint_as_u64(&parser, "ProcessId").and_then(|pid| u32::try_from(pid).ok())
        else {
            METRICS
                .decode_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Vec::new();
        };
        // Stop and rundown are state observations only, never creations. End
        // records retire the exact kernel object, never a reused PID's entry.
        if record.opcode() == 2 {
            if let Some(object) = try_get_uint_as_u64(&parser, "UniqueProcessKey") {
                if let Some(entries) = self.classic.get_mut(&pid) {
                    let before = entries.len();
                    entries.retain(|entry| {
                        !(entry.value.rundown
                            && entry.value.object == object
                            && entry.value.at <= filetime_to_system_time(record.raw_timestamp()))
                    });
                    self.count -= before - entries.len();
                    for entry in entries.iter_mut().filter(|entry| {
                        entry.value.object == object
                            && entry.value.at <= filetime_to_system_time(record.raw_timestamp())
                    }) {
                        // Keep the start for late manifest delivery. Its source
                        // timestamp still binds the pair after process exit.
                        entry.value.stopped_at =
                            Some(filetime_to_system_time(record.raw_timestamp()));
                    }
                }
            }
            return Vec::new();
        }
        if record.opcode() == 3 {
            METRICS
                .rundown
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if !matches!(record.opcode(), 1 | 3) {
            return Vec::new();
        }
        let (Some(parent), Some(object)) = (
            try_get_uint_as_u64(&parser, "ParentId").and_then(|pid| u32::try_from(pid).ok()),
            try_get_uint_as_u64(&parser, "UniqueProcessKey"),
        ) else {
            METRICS
                .decode_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Vec::new();
        };
        let value = ClassicProcess {
            pid,
            parent,
            object,
            stopped_at: None,
            rundown: record.opcode() == 3,
            session_id: try_get_uint_as_u64(&parser, "SessionId")
                .and_then(|id| u32::try_from(id).ok()),
            at: filetime_to_system_time(record.raw_timestamp()),
            // Empty is a measured empty command line; do not convert it to a
            // missing field or trim user-supplied whitespace.
            command_line: parser.try_parse::<String>("CommandLine").ok(),
            sid: parser
                .try_parse::<Vec<u8>>("UserSID")
                .ok()
                .and_then(|bytes| decode_wbem_sid(&bytes, record.event_flags() & 0x20 != 0)),
        };
        self.insert_classic(value, Instant::now())
    }

    fn insert_classic(&mut self, value: ClassicProcess, now: Instant) -> Vec<SensorEvent> {
        let pid = value.pid;
        self.classic.entry(pid).or_default().push_back(Pending {
            received: now,
            value,
        });
        self.count += 1;
        let mut out = self.resolve(pid);
        if self.count > CAPACITY {
            out.extend(self.expire(Instant::now(), false));
        }
        out
    }

    pub(super) fn disable(&mut self) -> Vec<SensorEvent> {
        self.unavailable = true;
        self.expire(Instant::now(), true)
    }

    pub(super) fn manifest(&mut self, event: SensorEvent) -> Vec<SensorEvent> {
        if self.unavailable {
            if event.action == SensorAction::Start
                && matches!(event.payload, SensorPayload::Process(_))
            {
                METRICS
                    .unmatched
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return vec![event];
        }
        if !matches!(event.payload, SensorPayload::Process(_)) {
            return vec![event];
        }
        let Some(pid) = event.pid else {
            return vec![event];
        };
        if event.action != SensorAction::Start && !self.manifest.contains_key(&pid) {
            return vec![event];
        }
        self.manifest.entry(pid).or_default().push_back(Pending {
            received: Instant::now(),
            value: event,
        });
        self.count += 1;
        let mut out = self.resolve(pid);
        if self.count > CAPACITY {
            out.extend(self.expire(Instant::now(), false));
        }
        out
    }

    fn resolve(&mut self, pid: u32) -> Vec<SensorEvent> {
        let mut out = Vec::new();
        if let (Some(manifest), Some(classic)) =
            (self.manifest.get_mut(&pid), self.classic.get_mut(&pid))
        {
            let mut index = 0;
            while index < manifest.len() {
                if manifest[index].value.action != SensorAction::Start {
                    if index == 0 {
                        out.push(manifest.remove(index).unwrap().value);
                        self.count -= 1;
                        continue;
                    }
                    index += 1;
                    continue;
                }
                let candidates: Vec<_> = classic
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| same_creation(&manifest[index].value, &entry.value))
                    .map(|(i, _)| i)
                    .collect();
                if candidates.len() != 1 {
                    index += 1;
                    continue;
                }
                let classic_index = candidates[0];
                if manifest
                    .iter()
                    .filter(|entry| same_creation(&entry.value, &classic[classic_index].value))
                    .count()
                    != 1
                {
                    index += 1;
                    continue;
                }
                let mut event = manifest.remove(index).unwrap().value;
                let facts = classic.remove(classic_index).unwrap().value;
                self.count -= 2;
                if let SensorPayload::Process(fields) = &mut event.payload {
                    let conflict = fields
                        .command_line
                        .as_ref()
                        .zip(facts.command_line.as_ref())
                        .is_some_and(|(live, captured)| live != captured);
                    let evidence = fields.windows.get_or_insert_with(Default::default);
                    evidence.command_line_may_be_truncated = facts
                        .command_line
                        .as_ref()
                        .is_some_and(|line| line.encode_utf16().count() == 1024);
                    evidence.user_sid = facts.sid.clone();
                    evidence.session_id = facts.session_id;
                    if conflict {
                        evidence.conflicting_live_command_line = fields.command_line.clone();
                        METRICS
                            .conflicting
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::warn!(pid, "Classic command line differs from live-query value");
                    } else {
                        METRICS
                            .matched
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Some(command_line) = facts.command_line {
                        // Only recover a suffix at the observed source limit.
                        // The live value was captured through a lifetime-checked
                        // handle; different prefixes remain genuine conflicts.
                        let recover_suffix = evidence.command_line_may_be_truncated
                            && fields.command_line.as_ref().is_some_and(|live| {
                                live.len() > command_line.len() && live.starts_with(&command_line)
                            });
                        if recover_suffix {
                            evidence.classic_command_line = Some(command_line);
                            evidence.command_line_source = Some("live_query".into());
                        } else {
                            evidence.command_line_source = Some("classic".into());
                            fields.command_line = Some(command_line);
                            METRICS
                                .classic_command_line
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    if let Some(sid) = facts.sid {
                        fields.user = Some(sid);
                    }
                }
                out.push(event);
            }
        }
        if self
            .classic
            .get(&pid)
            .is_some_and(|entries| entries.is_empty())
        {
            self.classic.remove(&pid);
        }
        if self
            .manifest
            .get(&pid)
            .is_some_and(|entries| entries.is_empty())
        {
            self.manifest.remove(&pid);
        }
        out
    }

    pub(super) fn expire(&mut self, now: Instant, all: bool) -> Vec<SensorEvent> {
        let mut out = Vec::new();
        for entries in self.manifest.values_mut() {
            while entries.front().is_some_and(|entry| {
                all || self.count > CAPACITY || now.duration_since(entry.received) >= WINDOW
            }) {
                let event = entries.pop_front().unwrap().value;
                if event.action == SensorAction::Start {
                    METRICS
                        .unmatched
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                out.push(event);
                self.count -= 1;
            }
        }
        for entries in self.classic.values_mut() {
            while entries.front().is_some_and(|entry| {
                all || self.count > CAPACITY || now.duration_since(entry.received) >= WINDOW
            }) {
                let entry = entries.pop_front().unwrap();
                self.count -= 1;
                if !entry.value.rundown {
                    METRICS
                        .classic_unmatched
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        self.classic.retain(|_, entries| !entries.is_empty());
        self.manifest.retain(|_, entries| !entries.is_empty());
        out
    }
}

fn same_creation(event: &SensorEvent, classic: &ClassicProcess) -> bool {
    if classic.rundown || event.action != SensorAction::Start {
        return false;
    }
    let Some(key) = event.process_start_key else {
        return false;
    };
    let SensorPayload::Process(fields) = &event.payload else {
        return false;
    };
    let created = filetime_to_system_time(key.start_time as i64);
    let skew = event
        .timestamp
        .duration_since(classic.at)
        .or_else(|_| classic.at.duration_since(event.timestamp))
        .unwrap();
    key.pid == classic.pid
        && created <= classic.at
        && classic
            .stopped_at
            .is_none_or(|stopped| event.timestamp <= stopped)
        && skew <= PAIR_SKEW
        && fields
            .parent_process_id
            .as_deref()
            .and_then(|pid| pid.parse::<u32>().ok())
            == Some(classic.parent)
}

/// WBEM SID prefixes the SID with two pointer-sized TOKEN_USER fields.
/// Validate lengths before reading; account resolution can fail independently
/// without discarding this authoritative raw SID.
fn decode_wbem_sid(bytes: &[u8], is_32_bit: bool) -> Option<String> {
    let sid = bytes.get(if is_32_bit { 8 } else { 16 }..)?;
    if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 {
        return None;
    }
    let count = usize::from(sid[1]);
    if sid.len() < 8 + 4 * count {
        return None;
    }
    let authority = sid[2..8]
        .iter()
        .fold(0u64, |n, byte| (n << 8) | u64::from(*byte));
    let mut text = format!("S-1-{authority}");
    for part in sid[8..8 + 4 * count].as_chunks::<4>().0 {
        text.push_str(&format!("-{}", u32::from_le_bytes(*part)));
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProcessCreationFields;
    use crate::sensor::{Platform, ProcessStartKey, SensorNormalization};

    fn manifest(start: u64, at: u64) -> SensorEvent {
        let fields: ProcessCreationFields = serde_json::from_value(serde_json::json!({
            "ProcessId": "42", "ParentProcessId": "7", "Image": "C:\\Windows\\cmd.exe"
        }))
        .unwrap();
        SensorEvent {
            platform: Platform::Windows,
            provider: "etw",
            action: SensorAction::Start,
            normalization: SensorNormalization {
                event_id: 1,
                action_code: 1,
            },
            pid: Some(42),
            timestamp: filetime_to_system_time(at as i64),
            source_seq: None,
            process_start_key: Some(ProcessStartKey {
                pid: 42,
                start_time: start,
            }),
            parent_process_start_key: None,
            payload: SensorPayload::Process(fields),
        }
    }

    const BASE: u64 = 134_000_000_000_000_000;

    fn classic(at: u64, command: &str) -> ClassicProcess {
        ClassicProcess {
            pid: 42,
            parent: 7,
            at: filetime_to_system_time(at as i64),
            object: u64::MAX - 100,
            stopped_at: None,
            rundown: false,
            session_id: Some(1),
            command_line: Some(command.into()),
            sid: Some("S-1-5-18".into()),
        }
    }

    #[test]
    fn either_arrival_order_emits_one_creation_with_manifest_identity() {
        for reverse in [false, true] {
            let mut correlation = ProcessCorrelation::default();
            let command = "  cmd.exe /c echo été 🦀  ";
            let now = Instant::now();
            let out = if reverse {
                assert!(correlation.manifest(manifest(BASE, BASE + 100)).is_empty());
                correlation.insert_classic(classic(BASE + 150, command), now)
            } else {
                assert!(correlation
                    .insert_classic(classic(BASE + 150, command), now)
                    .is_empty());
                correlation.manifest(manifest(BASE, BASE + 100))
            };
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].process_start_key.unwrap().start_time, BASE);
            let SensorPayload::Process(fields) = &out[0].payload else {
                panic!()
            };
            assert_eq!(fields.command_line.as_deref(), Some(command));
            assert_eq!(fields.image.as_deref(), Some("C:\\Windows\\cmd.exe"));
            assert_eq!(
                fields
                    .windows
                    .as_ref()
                    .unwrap()
                    .command_line_source
                    .as_deref(),
                Some("classic")
            );
            assert!(correlation.expire(now + WINDOW, true).is_empty());
            assert_eq!(correlation.count, 0);
        }
    }

    #[test]
    fn old_pid_generation_and_parent_conflicts_do_not_join() {
        for parent in [7, 8] {
            let mut correlation = ProcessCorrelation::default();
            let mut old = classic(BASE + 150, "old");
            old.parent = parent;
            correlation.insert_classic(old, Instant::now());
            let event = if parent == 7 {
                manifest(BASE + 200, BASE + 250)
            } else {
                manifest(BASE, BASE + 100)
            };
            assert!(correlation.manifest(event).is_empty());
            let out = correlation.expire(Instant::now(), true);
            assert_eq!(out.len(), 1);
            let SensorPayload::Process(fields) = &out[0].payload else {
                panic!()
            };
            assert!(fields.command_line.is_none());
        }
    }

    #[test]
    fn terminated_before_consume_keeps_creation_and_stop_order() {
        let mut correlation = ProcessCorrelation::default();
        let start = manifest(BASE, BASE + 100);
        let mut stop = start.clone();
        stop.action = SensorAction::Stop;
        stop.timestamp = filetime_to_system_time((BASE + 1000) as i64);
        assert!(correlation.manifest(start).is_empty());
        assert!(correlation.manifest(stop).is_empty());
        let mut facts = classic(BASE + 150, "already exited");
        facts.stopped_at = Some(filetime_to_system_time((BASE + 1000) as i64));
        let out = correlation.insert_classic(facts, Instant::now());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].action, SensorAction::Start);
        assert_eq!(out[1].action, SensorAction::Stop);
    }

    #[test]
    fn ambiguous_pairs_and_excessive_source_skew_fall_back() {
        let now = Instant::now();
        let mut correlation = ProcessCorrelation::default();
        correlation.insert_classic(classic(BASE + 150, "one"), now);
        correlation.insert_classic(classic(BASE + 160, "two"), now);
        assert!(correlation.manifest(manifest(BASE, BASE + 100)).is_empty());
        assert_eq!(correlation.disable().len(), 1);
        let mut correlation = ProcessCorrelation::default();
        correlation.insert_classic(classic(BASE + 100_000, "late lifetime"), now);
        assert!(correlation.manifest(manifest(BASE, BASE + 100)).is_empty());
        assert_eq!(correlation.disable().len(), 1);
    }

    #[test]
    fn truncated_prefix_recovers_live_suffix_with_derived_provenance() {
        use crate::normalizer::Normalizer;
        use crate::state::{DnsCache, ProcessCache, SidCache};
        use std::sync::Arc;
        // Count UTF-16 units rather than UTF-8 bytes, including supplementary characters.
        let captured = "🦀".repeat(512);
        let live = format!("{captured} suspicious-suffix");
        for reverse in [false, true] {
            let mut correlation = ProcessCorrelation::default();
            let mut event = manifest(BASE, BASE + 100);
            if let SensorPayload::Process(fields) = &mut event.payload {
                fields.command_line = Some(live.clone());
            }
            let out = if reverse {
                correlation.manifest(event);
                correlation.insert_classic(classic(BASE + 150, &captured), Instant::now())
            } else {
                correlation.insert_classic(classic(BASE + 150, &captured), Instant::now());
                correlation.manifest(event)
            };
            let normalizer = Normalizer::new(
                Arc::new(ProcessCache::new()),
                Arc::new(SidCache::new()),
                Arc::new(DnsCache::new()),
            );
            let normalized = normalizer.normalize(&out[0]).unwrap();
            assert!(normalized
                .provenance
                .entries()
                .iter()
                .any(|entry| entry.field == "CommandLine"));
            let json = serde_json::to_value(&normalized).unwrap();
            assert_eq!(json["fields"]["CommandLine"], live);
            assert_eq!(
                json["fields"]["WindowsProcessMetadata"]["classic_command_line"],
                captured
            );
            assert_eq!(
                json["fields"]["WindowsProcessMetadata"]["command_line_source"],
                "live_query"
            );
        }
    }

    #[test]
    fn recovery_requires_boundary_exact_prefix_and_available_backup() {
        let captured = "x".repeat(1024);
        for (classic_value, live) in [
            (captured.clone(), None),
            (captured.clone(), Some(captured.clone())),
            (captured.clone(), Some(format!("different{captured}"))),
            ("short".into(), Some("short but changed".into())),
        ] {
            let mut correlation = ProcessCorrelation::default();
            let mut event = manifest(BASE, BASE + 100);
            if let SensorPayload::Process(fields) = &mut event.payload {
                fields.command_line = live;
            }
            correlation.manifest(event);
            let out =
                correlation.insert_classic(classic(BASE + 150, &classic_value), Instant::now());
            let SensorPayload::Process(fields) = &out[0].payload else {
                panic!()
            };
            assert_eq!(fields.command_line.as_ref(), Some(&classic_value));
            assert_eq!(
                fields
                    .windows
                    .as_ref()
                    .unwrap()
                    .command_line_source
                    .as_deref(),
                Some("classic")
            );
            assert!(fields
                .windows
                .as_ref()
                .unwrap()
                .classic_command_line
                .is_none());
        }
    }

    #[test]
    fn empty_long_unicode_and_conflicting_values_are_preserved() {
        for command in [String::new(), "été 🦀 ".repeat(4000)] {
            let mut correlation = ProcessCorrelation::default();
            let mut event = manifest(BASE, BASE + 100);
            if let SensorPayload::Process(fields) = &mut event.payload {
                fields.command_line = Some("modified PEB".into());
                fields
                    .windows
                    .get_or_insert_with(Default::default)
                    .command_line_source = Some("live_query".into());
            }
            correlation.manifest(event);
            let out = correlation.insert_classic(classic(BASE + 150, &command), Instant::now());
            let SensorPayload::Process(fields) = &out[0].payload else {
                panic!()
            };
            assert_eq!(fields.command_line.as_ref(), Some(&command));
            assert_eq!(
                fields
                    .windows
                    .as_ref()
                    .unwrap()
                    .conflicting_live_command_line
                    .as_deref(),
                Some("modified PEB")
            );
        }
    }

    #[test]
    fn expiry_and_capacity_keep_state_bounded_and_emit_fallback() {
        let mut correlation = ProcessCorrelation::default();
        let now = Instant::now();
        correlation.manifest(manifest(BASE, BASE + 100));
        assert!(correlation.expire(now, false).is_empty());
        assert_eq!(
            correlation
                .expire(now + WINDOW + Duration::from_secs(1), false)
                .len(),
            1
        );
        for pid in 0..CAPACITY + 1 {
            let mut facts = classic(BASE, "x");
            facts.pid = pid as u32;
            correlation.insert_classic(facts, now);
        }
        correlation.expire(now, false);
        assert!(correlation.count <= CAPACITY);
        correlation.expire(now + WINDOW, false);
        assert_eq!(correlation.count, 0);
    }

    #[test]
    fn rundown_seeds_bounded_object_state_without_creation_alerts() {
        let mut correlation = ProcessCorrelation::default();
        let mut facts = classic(BASE + 150, "existing");
        facts.rundown = true;
        assert!(correlation.insert_classic(facts, Instant::now()).is_empty());
        assert_eq!(correlation.count, 1);
        assert!(correlation.manifest(manifest(BASE, BASE + 100)).is_empty());
        let out = correlation.disable();
        assert_eq!(out.len(), 1);
        assert_eq!(correlation.count, 0);
        // Collection failure restores immediate manifest delivery.
        assert_eq!(correlation.manifest(manifest(BASE, BASE + 100)).len(), 1);
    }

    #[test]
    fn wbem_sid_validates_native_and_wow64_layouts() {
        for is_32_bit in [false, true] {
            let mut bytes = vec![0; if is_32_bit { 8 } else { 16 }];
            bytes.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
            assert_eq!(
                decode_wbem_sid(&bytes, is_32_bit).as_deref(),
                Some("S-1-5-18")
            );
            bytes.pop();
            assert!(decode_wbem_sid(&bytes, is_32_bit).is_none());
        }
        assert!(decode_wbem_sid(&[], false).is_none());
    }
}
