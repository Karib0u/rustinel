//! Payload decoding for Kernel-Audit-API-Calls event 5 (OpenProcess).

use crate::models::{ProcessAccessFields, ProcessAccessOutcome};
use crate::sensor::RawProcessAccess;

pub(super) const PROVIDER: &str = "Microsoft-Windows-Kernel-Audit-API-Calls";
pub(super) const OPEN_PROCESS_ID: u16 = 5;

/// The caller is the header's PID. The payload's PID is the attempted target.
/// A missing property indicates an unsupported layout. The invalid target
/// sentinel is a valid record and deliberately has no target identity.
pub(super) fn decode(
    source_pid: Option<u32>,
    property: impl Fn(&str) -> Option<u32>,
) -> Option<RawProcessAccess> {
    let target_pid = property("TargetProcessId")?;
    let desired_access = property("DesiredAccess")?;
    let return_code = property("ReturnCode")?;
    let access_outcome = if (return_code as i32) < 0 {
        ProcessAccessOutcome::Failure
    } else {
        ProcessAccessOutcome::Success
    };

    Some(RawProcessAccess {
        fields: ProcessAccessFields {
            source_process_id: source_pid.map(|pid| pid.to_string()),
            target_process_id: (target_pid != u32::MAX).then(|| target_pid.to_string()),
            desired_access: Some(format!("{desired_access:#x}")),
            return_code: Some(return_code.to_string()),
            access_outcome,
            ..Default::default()
        },
        target_start_key: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::models::{CanonicalEvent, FieldViewName, NormalizedEvent};
    use crate::sensor::{
        Platform, ProcessStartKey, RawEvent, RawPayload, SensorAction, SensorNormalization,
    };
    use crate::state::HostState;
    use std::time::UNIX_EPOCH;

    fn decode_properties(target_pid: u32, mask: u32, status: u32) -> RawProcessAccess {
        decode(Some(42), |property| match property {
            "TargetProcessId" => Some(target_pid),
            "DesiredAccess" => Some(mask),
            "ReturnCode" => Some(status),
            _ => None,
        })
        .unwrap()
    }

    fn access_event(access: RawProcessAccess) -> RawEvent {
        RawEvent {
            process_name: None,
            provenance: Default::default(),
            platform: Platform::Windows,
            provider: "etw",
            action: SensorAction::Access,
            normalization: SensorNormalization {
                event_id: OPEN_PROCESS_ID,
                action_code: 0,
            },
            pid: Some(42),
            timestamp: UNIX_EPOCH,
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
            payload: RawPayload::ProcessAccess(access),
        }
    }

    #[test]
    fn open_process_preserves_requested_rights_and_ntstatus() {
        for (target, mask, status, expected_mask, expected_outcome) in [
            (100, 4096, 0, "0x1000", "success"),
            (100, 0x0200_0000, 0, "0x2000000", "success"),
            (100, 0x1010, 0xc000_0022, "0x1010", "failure"),
            (u32::MAX, 0x1010, 0xc000_000b, "0x1010", "failure"),
            (100, 0, 0x4000_0000, "0x0", "success"),
        ] {
            let raw = access_event(decode_properties(target, mask, status));
            let event = HostState::default()
                .canonicalize(raw)
                .unwrap()
                .into_normalized();
            assert_eq!(event.get_field("EventID"), Some("5"));
            assert_eq!(event.get_field("SourceProcessId"), Some("42"));
            assert_eq!(
                event.get_field("TargetProcessId"),
                (target != u32::MAX).then_some("100")
            );
            assert_eq!(event.get_field("TargetImage"), None);
            assert_eq!(event.get_field("DesiredAccess"), Some(expected_mask));
            assert_eq!(event.get_field("GrantedAccess"), None);
            assert_eq!(
                event.get_field("ReturnCode"),
                Some(status.to_string().as_str())
            );
            assert_eq!(event.get_field("AccessOutcome"), Some(expected_outcome));
            let contract =
                crate::field_availability::event_contract(FieldViewName::SYSMON, &event).unwrap();
            assert_eq!(contract.source, PROVIDER);

            let serialized = serde_json::to_string(&event).unwrap();
            let replayed: NormalizedEvent = serde_json::from_str(&serialized).unwrap();
            assert_eq!(serde_json::to_string(&replayed).unwrap(), serialized);
            let replayed = CanonicalEvent::from_normalized(replayed);
            assert_eq!(replayed.action, SensorAction::Access);
            assert_eq!(replayed.pid, Some(42));
        }
    }

    #[test]
    fn open_process_requires_all_three_native_properties() {
        for missing in ["TargetProcessId", "DesiredAccess", "ReturnCode"] {
            assert!(decode(Some(42), |name| (name != missing).then_some(0)).is_none());
        }
    }

    #[test]
    fn process_access_uses_exact_cached_lifetimes_and_routes_to_sigma() {
        let host = HostState::default();
        for (pid, start, image) in [
            (42, 100, r"C:\Windows\caller.exe"),
            (100, 110, r"C:\Windows\notepad.exe"),
            (100, 200, r"C:\Windows\replacement.exe"),
            (u32::MAX, 90, r"C:\Windows\invalid.exe"),
        ] {
            host.processes.add(
                pid,
                start,
                image.to_string(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );
        }
        let mut access = decode_properties(100, 4096, 0xc000_0022);
        access.target_start_key = Some(ProcessStartKey {
            pid: 100,
            start_time: 110,
        });
        let mut raw = access_event(access);
        raw.process_start_key = Some(ProcessStartKey {
            pid: 42,
            start_time: 100,
        });
        let event = host.canonicalize(raw).unwrap().into_normalized();
        assert_eq!(
            event.get_field("SourceImage"),
            Some(r"C:\Windows\caller.exe")
        );
        assert_eq!(
            event.get_field("TargetImage"),
            Some(r"C:\Windows\notepad.exe")
        );

        for (target, status) in [(100, 0), (u32::MAX, 0xc000_000b)] {
            let raw = access_event(decode_properties(target, 4096, status));
            let unresolved = host.canonicalize(raw).unwrap().into_normalized();
            assert_eq!(unresolved.get_field("SourceImage"), None);
            assert_eq!(unresolved.get_field("TargetImage"), None);
        }

        let dir = tempfile::tempdir().unwrap();
        for (file, category, selection) in [
            ("attempt", "process_access", "    TargetImage|endswith: '\\notepad.exe'\n    DesiredAccess: '0x1000'\n    AccessOutcome: failure\n    ReturnCode: '3221225506'"),
            ("grant", "process_access", "    GrantedAccess: '0x1000'"),
            ("success", "process_access", "    AccessOutcome: success"),
            ("wrong-category", "process_creation", "    SourceImage|endswith: '\\caller.exe'"),
        ] {
            std::fs::write(dir.path().join(format!("{file}.yml")), format!("title: {file}\nlogsource:\n  product: windows\n  category: {category}\ndetection:\n  selection:\n{selection}\n  condition: selection\n")).unwrap();
        }
        let mut engine = Engine::new_for_platform_with_match_debug(
            Platform::Windows,
            crate::models::MatchDebugLevel::Off,
        );
        engine.load_rules(dir.path()).unwrap();
        let alerts = engine.check_event(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "attempt");
        let ecs = crate::models::ecs::EcsAlert::from(&alerts[0]);
        assert_eq!(ecs.event_outcome.as_deref(), Some("failure"));
        assert_eq!(ecs.process_pid, Some(42));
        assert_eq!(
            ecs.edr_process_access.unwrap().desired_access.as_deref(),
            Some("0x1000")
        );
    }
}
