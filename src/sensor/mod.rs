//! Shared sensor boundary types.
//!
//! Phase 1 introduces a platform-neutral raw event contract so Windows ETW and
//! Linux eBPF can feed the same downstream pipeline without leaking sensor-
//! specific record types into shared code.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

use std::time::SystemTime;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;

use crate::models::{
    DnsQueryFields, EventCategory, EventFields, FileEventFields, ImageLoadFields,
    NetworkConnectionFields, PowerShellScriptFields, ProcessCreationFields, RegistryEventFields,
    ServiceCreationFields, TaskCreationFields, WmiEventFields,
};

/// Cross-platform sensor interface.
///
/// Concrete sensors are responsible for decoding platform-specific telemetry
/// into [`SensorEvent`] values and emitting them through a bounded channel.
pub trait Sensor: Send + Sync {
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()>;
    fn shutdown(&self);
}

/// Shared event handler trait for the post-sensor pipeline.
pub trait SensorEventHandler: Send + Sync {
    fn handle_event(&self, event: &SensorEvent);
}

/// Platform that produced the raw sensor event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
}

/// High-level action emitted by a sensor event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorAction {
    Start,
    Stop,
    Create,
    Delete,
    Modify,
    Rename,
    Connect,
    Disconnect,
    Accept,
    Query,
    Set,
    Load,
    Execute,
    Register,
}

/// Stable process identity used to avoid PID reuse collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessStartKey {
    pub pid: u32,
    /// Platform-native process start timestamp paired with `pid`.
    pub start_time: u64,
}

/// Shared raw event emitted by any platform sensor.
#[derive(Debug, Clone)]
pub struct SensorEvent {
    pub platform: Platform,
    pub provider: &'static str,
    pub action: SensorAction,
    pub normalization: SensorNormalization,
    pub pid: Option<u32>,
    pub timestamp: SystemTime,
    pub process_start_key: Option<ProcessStartKey>,
    pub payload: SensorPayload,
}

impl SensorEvent {
    /// Return the event category, derived from the payload variant.
    ///
    /// This is the single source of truth — category is not stored separately
    /// to avoid the field and payload falling out of sync.
    pub fn category(&self) -> EventCategory {
        self.payload.category()
    }
}

/// Sensor-supplied compatibility metadata for the normalized event model.
///
/// Shared normalization copies this through without understanding any
/// platform-specific event numbering scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorNormalization {
    pub event_id: u16,
    pub action_code: u8,
}

/// Shared event router that dispatches decoded sensor events to downstream handlers.
pub struct SensorEventRouter {
    handlers: Vec<Box<dyn SensorEventHandler>>,
}

impl SensorEventRouter {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn register_handler(&mut self, handler: Box<dyn SensorEventHandler>) {
        self.handlers.push(handler);
    }

    pub fn route_event(&self, event: &SensorEvent) {
        for handler in &self.handlers {
            handler.handle_event(event);
        }
    }
}

impl Default for SensorEventRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed payload emitted by a sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensorPayload {
    Process(ProcessCreationFields),
    Network(NetworkConnectionFields),
    File(FileEventFields),
    Dns(DnsQueryFields),
    Registry(RegistryEventFields),
    ImageLoad(ImageLoadFields),
    Scripting(PowerShellScriptFields),
    Wmi(WmiEventFields),
    Service(ServiceCreationFields),
    Task(TaskCreationFields),
}

impl SensorPayload {
    /// Return the shared event category for this payload.
    pub fn category(&self) -> EventCategory {
        match self {
            Self::Process(_) => EventCategory::Process,
            Self::Network(_) => EventCategory::Network,
            Self::File(_) => EventCategory::File,
            Self::Dns(_) => EventCategory::Dns,
            Self::Registry(_) => EventCategory::Registry,
            Self::ImageLoad(_) => EventCategory::ImageLoad,
            Self::Scripting(_) => EventCategory::Scripting,
            Self::Wmi(_) => EventCategory::Wmi,
            Self::Service(_) => EventCategory::Service,
            Self::Task(_) => EventCategory::Task,
        }
    }

    #[cfg(test)]
    /// Convert the sensor payload back into the existing shared field enum.
    pub fn into_event_fields(self) -> EventFields {
        match self {
            Self::Process(fields) => EventFields::ProcessCreation(fields),
            Self::Network(fields) => EventFields::NetworkConnection(fields),
            Self::File(fields) => EventFields::FileEvent(fields),
            Self::Dns(fields) => EventFields::DnsQuery(fields),
            Self::Registry(fields) => EventFields::RegistryEvent(fields),
            Self::ImageLoad(fields) => EventFields::ImageLoad(fields),
            Self::Scripting(fields) => EventFields::PowerShellScript(fields),
            Self::Wmi(fields) => EventFields::WmiEvent(fields),
            Self::Service(fields) => EventFields::ServiceCreation(fields),
            Self::Task(fields) => EventFields::TaskCreation(fields),
        }
    }
}

impl TryFrom<EventFields> for SensorPayload {
    type Error = EventFields;

    fn try_from(fields: EventFields) -> std::result::Result<Self, Self::Error> {
        match fields {
            EventFields::ProcessCreation(fields) => Ok(Self::Process(fields)),
            EventFields::NetworkConnection(fields) => Ok(Self::Network(fields)),
            EventFields::FileEvent(fields) => Ok(Self::File(fields)),
            EventFields::DnsQuery(fields) => Ok(Self::Dns(fields)),
            EventFields::RegistryEvent(fields) => Ok(Self::Registry(fields)),
            EventFields::ImageLoad(fields) => Ok(Self::ImageLoad(fields)),
            EventFields::PowerShellScript(fields) => Ok(Self::Scripting(fields)),
            EventFields::WmiEvent(fields) => Ok(Self::Wmi(fields)),
            EventFields::ServiceCreation(fields) => Ok(Self::Service(fields)),
            EventFields::TaskCreation(fields) => Ok(Self::Task(fields)),
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn payload_category_matches_variant() {
        let payload = SensorPayload::Process(ProcessCreationFields {
            image: Some("/usr/bin/bash".to_string()),
            original_file_name: None,
            product: None,
            description: None,
            target_image: None,
            command_line: Some("/usr/bin/bash -c id".to_string()),
            process_id: Some("42".to_string()),
            process_start_time: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            logon_id: None,
            logon_guid: None,
        });

        assert_eq!(payload.category(), EventCategory::Process);
    }

    #[test]
    fn sensor_event_category_is_derived_from_payload() {
        let payload = SensorPayload::Network(NetworkConnectionFields {
            destination_ip: Some("198.51.100.10".to_string()),
            source_ip: Some("10.0.0.5".to_string()),
            destination_port: Some("443".to_string()),
            source_port: Some("51324".to_string()),
            process_id: Some("4242".to_string()),
            image: Some("/usr/bin/curl".to_string()),
            user: None,
            destination_hostname: None,
            protocol: Some("tcp".to_string()),
        });

        let event = SensorEvent {
            platform: Platform::Linux,
            provider: "ebpf",
            action: SensorAction::Connect,
            normalization: SensorNormalization {
                event_id: 3,
                action_code: 12,
            },
            pid: Some(4242),
            timestamp: SystemTime::UNIX_EPOCH,
            process_start_key: None,
            payload,
        };

        assert_eq!(event.category(), EventCategory::Network);
        assert_eq!(event.action, SensorAction::Connect);
        assert_eq!(event.pid, Some(4242));
    }

    #[test]
    fn payload_round_trips_through_event_fields() {
        let payload = SensorPayload::File(FileEventFields {
            source_filename: None,
            target_filename: Some("/tmp/example".to_string()),
            process_id: Some("77".to_string()),
            image: Some("/usr/bin/touch".to_string()),
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: None,
        });

        let fields = payload.into_event_fields();
        let payload = SensorPayload::try_from(fields).expect("file fields should map");

        assert_eq!(payload.category(), EventCategory::File);
    }

    #[test]
    fn try_from_rejects_untyped_event_fields() {
        let fields =
            EventFields::Generic(HashMap::from([("key".to_string(), "value".to_string())]));

        assert!(SensorPayload::try_from(fields).is_err());
    }
}
