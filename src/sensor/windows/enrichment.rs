//! Post-callback enrichment for Windows sensor events.
//!
//! ETW callbacks only decode data already carried by an event. Work that can
//! block, including opening and mapping PE images, belongs here after the
//! bounded sensor channel has accepted the event.

use crate::sensor::{SensorAction, SensorEvent, SensorPayload};
use crate::utils::{parse_metadata, pe};

/// Add PE version-resource fields to process-start and image-load events.
pub(crate) fn enrich_event(event: &mut SensorEvent) {
    match &mut event.payload {
        SensorPayload::Process(fields) if event.action == SensorAction::Start => {
            let metadata = fields.image.as_deref().and_then(parse_metadata);
            (
                fields.original_file_name,
                fields.product,
                fields.description,
                fields.company,
                fields.file_version,
            ) = pe::version_fields(metadata);
        }
        SensorPayload::ImageLoad(fields) => {
            let metadata = fields.image_loaded.as_deref().and_then(parse_metadata);
            (
                fields.original_file_name,
                fields.product,
                fields.description,
                fields.company,
                fields.file_version,
            ) = pe::version_fields(metadata);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use crate::models::{ImageLoadFields, ProcessCreationFields};
    use crate::sensor::{Platform, SensorNormalization};

    use super::*;

    fn event(action: SensorAction, payload: SensorPayload) -> SensorEvent {
        SensorEvent {
            platform: Platform::Windows,
            provider: "etw",
            action,
            normalization: SensorNormalization {
                event_id: 1,
                action_code: 1,
            },
            pid: Some(42),
            timestamp: UNIX_EPOCH,
            process_start_key: None,
            payload,
        }
    }

    fn process_fields(image: &str) -> ProcessCreationFields {
        ProcessCreationFields {
            image: Some(image.to_string()),
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: None,
            process_id: Some("42".to_string()),
            process_start_time: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
        }
    }

    fn image_load_fields(image: &str) -> ImageLoadFields {
        ImageLoadFields {
            image_loaded: Some(image.to_string()),
            process_id: Some("42".to_string()),
            image: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            signed: None,
            signature: None,
            user: None,
        }
    }

    #[test]
    fn process_start_is_enriched_after_decode() {
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(r"C:\Windows\System32\cmd.exe")),
        );

        enrich_event(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.original_file_name.is_some());
        assert!(fields.product.is_some());
        assert!(fields.description.is_some());
    }

    #[test]
    fn image_load_is_enriched_after_decode() {
        let mut event = event(
            SensorAction::Load,
            SensorPayload::ImageLoad(image_load_fields(r"C:\Windows\System32\cmd.exe")),
        );

        enrich_event(&mut event);

        let SensorPayload::ImageLoad(fields) = event.payload else {
            panic!("expected image-load payload");
        };
        assert!(fields.original_file_name.is_some());
        assert!(fields.product.is_some());
        assert!(fields.description.is_some());
    }

    #[test]
    fn process_stop_does_not_read_the_image() {
        let mut event = event(
            SensorAction::Stop,
            SensorPayload::Process(process_fields(r"C:\Windows\System32\cmd.exe")),
        );

        enrich_event(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.original_file_name.is_none());
        assert!(fields.product.is_none());
        assert!(fields.description.is_none());
    }
}
