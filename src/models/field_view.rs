//! Detection field views over Rustinel's canonical event data.
//!
//! Sensors populate the snake-case Rust fields in [`NormalizedEvent`].  The
//! names a rule sees live here instead: each static entry maps one view field
//! to a semantic Rustinel accessor.  Adding another rule vocabulary therefore
//! changes this module, routing, and its availability contract, not a sensor.

use super::{EventFields, NormalizedEvent};
use serde::Serialize;

/// A named rule-field vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct FieldViewName(&'static str);

impl FieldViewName {
    pub const SYSMON: Self = Self("sysmon");
    pub const DEFAULT: Self = Self::SYSMON;

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Rustinel's semantic field identifiers.
///
/// These names describe the data, independent of any external rule schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalField {
    AccountName,
    CdHash,
    Channel,
    CodeSigningFlags,
    CommandLine,
    Company,
    CgroupId,
    CgroupPath,
    ContainerId,
    ContainerRuntime,
    ContextInfo,
    ControllingTty,
    CreationTime,
    CurrentDirectory,
    Description,
    DestinationHostname,
    DestinationIp,
    DestinationPort,
    DnsQueryName,
    DnsQueryResults,
    DnsQueryStatus,
    DnsRecordType,
    EffectiveGroupId,
    EffectiveUserId,
    EventId,
    EventNamespace,
    EventType,
    FileVersion,
    Hashes,
    ImageLoaded,
    ImageSource,
    ImageTruncated,
    Imphash,
    Initiated,
    IntegrityLevel,
    IsPlatformBinary,
    KernelStartBoottime,
    MountNamespace,
    NetworkNamespace,
    NewName,
    Operation,
    OriginalFileName,
    ParentCommandLine,
    ParentImage,
    ParentProcessId,
    ParentUser,
    Path,
    PathTruncated,
    Payload,
    PidNamespace,
    PreExecImage,
    PreviousCreationTime,
    ProcessId,
    ProcessImage,
    ProcessStartTime,
    Product,
    Protocol,
    ProviderName,
    Query,
    RealGroupId,
    RealUserId,
    Script,
    ScriptBlockId,
    ScriptBlockText,
    ServiceFileName,
    ServiceName,
    ServiceType,
    SessionId,
    Signature,
    SignatureStatus,
    Signed,
    SigningId,
    SourceFilename,
    SourceIp,
    SourcePort,
    StartType,
    TargetFilename,
    TargetImage,
    TargetObject,
    TaskContent,
    TaskName,
    TeamId,
    Timestamp,
    User,
    UserName,
    Details,
}

/// A canonical value without imposing one external schema's representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalValue<'a> {
    String(&'a str),
    Bool(bool),
    U64(u64),
}

/// One compile-time field mapping in a named view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMapping {
    pub name: &'static str,
    pub canonical: CanonicalField,
    /// Whether the name is part of enumeration and keyword matching. Some
    /// compatibility aliases remain addressable without duplicating values.
    pub enumerate: bool,
}

const fn field(name: &'static str, canonical: CanonicalField) -> FieldMapping {
    FieldMapping {
        name,
        canonical,
        enumerate: true,
    }
}

const fn alias(name: &'static str, canonical: CanonicalField) -> FieldMapping {
    FieldMapping {
        name,
        canonical,
        enumerate: false,
    }
}

/// Sysmon-compatible rule names, sorted for allocation-free binary lookup.
///
/// This is the compatibility surface that `NormalizedEvent::get_field`
/// historically exposed. Keep aliases such as `ImagePath`, lowercase DNS
/// names, and Rustinel fidelity fields in this table.
pub const SYSMON_FIELDS: &[FieldMapping] = &[
    field("AccountName", CanonicalField::AccountName),
    field("CdHash", CanonicalField::CdHash),
    field("CgroupId", CanonicalField::CgroupId),
    field("CgroupPath", CanonicalField::CgroupPath),
    field("Channel", CanonicalField::Channel),
    field("CodeSigningFlags", CanonicalField::CodeSigningFlags),
    field("CommandLine", CanonicalField::CommandLine),
    field("Company", CanonicalField::Company),
    field("ContainerId", CanonicalField::ContainerId),
    field("ContainerRuntime", CanonicalField::ContainerRuntime),
    field("ContextInfo", CanonicalField::ContextInfo),
    field("ControllingTty", CanonicalField::ControllingTty),
    field("CreationUtcTime", CanonicalField::CreationTime),
    field("CurrentDirectory", CanonicalField::CurrentDirectory),
    field("Description", CanonicalField::Description),
    field("DestinationHostname", CanonicalField::DestinationHostname),
    field("DestinationIp", CanonicalField::DestinationIp),
    field("DestinationPort", CanonicalField::DestinationPort),
    field("Details", CanonicalField::Details),
    field("EffectiveGroupId", CanonicalField::EffectiveGroupId),
    field("EffectiveUserId", CanonicalField::EffectiveUserId),
    field("EventID", CanonicalField::EventId),
    field("EventNamespace", CanonicalField::EventNamespace),
    field("EventType", CanonicalField::EventType),
    field("FileVersion", CanonicalField::FileVersion),
    field("Hashes", CanonicalField::Hashes),
    field("Image", CanonicalField::ProcessImage),
    field("ImageLoaded", CanonicalField::ImageLoaded),
    alias("ImagePath", CanonicalField::ServiceFileName),
    field("ImageSource", CanonicalField::ImageSource),
    field("ImageTruncated", CanonicalField::ImageTruncated),
    field("Imphash", CanonicalField::Imphash),
    field("Initiated", CanonicalField::Initiated),
    field("IntegrityLevel", CanonicalField::IntegrityLevel),
    field("IsPlatformBinary", CanonicalField::IsPlatformBinary),
    field("KernelStartBoottime", CanonicalField::KernelStartBoottime),
    field("MountNamespace", CanonicalField::MountNamespace),
    field("NetworkNamespace", CanonicalField::NetworkNamespace),
    field("NewName", CanonicalField::NewName),
    field("Operation", CanonicalField::Operation),
    field("OriginalFileName", CanonicalField::OriginalFileName),
    field("ParentCommandLine", CanonicalField::ParentCommandLine),
    field("ParentImage", CanonicalField::ParentImage),
    field("ParentProcessId", CanonicalField::ParentProcessId),
    field("ParentUser", CanonicalField::ParentUser),
    field("Path", CanonicalField::Path),
    field("PathTruncated", CanonicalField::PathTruncated),
    field("Payload", CanonicalField::Payload),
    field("PidNamespace", CanonicalField::PidNamespace),
    field("PreExecImage", CanonicalField::PreExecImage),
    field(
        "PreviousCreationUtcTime",
        CanonicalField::PreviousCreationTime,
    ),
    field("ProcessId", CanonicalField::ProcessId),
    field("ProcessStartTime", CanonicalField::ProcessStartTime),
    field("Product", CanonicalField::Product),
    field("Protocol", CanonicalField::Protocol),
    field("Provider_Name", CanonicalField::ProviderName),
    field("Query", CanonicalField::Query),
    field("QueryName", CanonicalField::DnsQueryName),
    field("QueryResults", CanonicalField::DnsQueryResults),
    field("QueryStatus", CanonicalField::DnsQueryStatus),
    field("RealGroupId", CanonicalField::RealGroupId),
    field("RealUserId", CanonicalField::RealUserId),
    field("RecordType", CanonicalField::DnsRecordType),
    field("Script", CanonicalField::Script),
    field("ScriptBlockId", CanonicalField::ScriptBlockId),
    field("ScriptBlockText", CanonicalField::ScriptBlockText),
    field("ServiceFileName", CanonicalField::ServiceFileName),
    field("ServiceName", CanonicalField::ServiceName),
    field("ServiceType", CanonicalField::ServiceType),
    field("SessionId", CanonicalField::SessionId),
    field("Signature", CanonicalField::Signature),
    field("SignatureStatus", CanonicalField::SignatureStatus),
    field("Signed", CanonicalField::Signed),
    field("SigningId", CanonicalField::SigningId),
    field("SourceFilename", CanonicalField::SourceFilename),
    field("SourceIp", CanonicalField::SourceIp),
    field("SourcePort", CanonicalField::SourcePort),
    field("StartType", CanonicalField::StartType),
    field("TargetFilename", CanonicalField::TargetFilename),
    field("TargetImage", CanonicalField::TargetImage),
    field("TargetObject", CanonicalField::TargetObject),
    field("TaskContent", CanonicalField::TaskContent),
    field("TaskName", CanonicalField::TaskName),
    field("TeamId", CanonicalField::TeamId),
    field("User", CanonicalField::User),
    field("UserName", CanonicalField::UserName),
    alias("answer", CanonicalField::DnsQueryResults),
    alias("event_time", CanonicalField::Timestamp),
    alias("query", CanonicalField::DnsQueryName),
    alias("record_type", CanonicalField::DnsRecordType),
    field("timestamp", CanonicalField::Timestamp),
];

#[derive(Debug, Clone, Copy)]
pub struct FieldViewDefinition {
    pub name: FieldViewName,
    pub fields: &'static [FieldMapping],
}

/// Every detection view compiled into Rustinel.
pub const FIELD_VIEWS: &[FieldViewDefinition] = &[FieldViewDefinition {
    name: FieldViewName::SYSMON,
    fields: SYSMON_FIELDS,
}];

pub fn mappings(view: FieldViewName) -> &'static [FieldMapping] {
    FIELD_VIEWS
        .iter()
        .find(|definition| definition.name == view)
        .map(|definition| definition.fields)
        .unwrap_or(&[])
}

fn mapping(view: FieldViewName, name: &str) -> Option<&'static FieldMapping> {
    let mappings = mappings(view);
    mappings
        .binary_search_by_key(&name, |mapping| mapping.name)
        .ok()
        .map(|index| &mappings[index])
}

/// A borrowed rendering of one event in a selected field vocabulary.
#[derive(Debug, Clone, Copy)]
pub struct FieldView<'a> {
    event: &'a NormalizedEvent,
    name: FieldViewName,
}

impl<'a> FieldView<'a> {
    pub const fn new(event: &'a NormalizedEvent, name: FieldViewName) -> Self {
        Self { event, name }
    }

    pub const fn name(self) -> FieldViewName {
        self.name
    }

    pub fn get(self, name: &str) -> Option<CanonicalValue<'a>> {
        if matches!(
            crate::field_availability::availability_for_view(self.name, self.event, name),
            Some(crate::field_availability::Availability::Never(_))
        ) {
            return None;
        }

        self.get_unchecked(name)
    }

    /// Read through the mapping without applying the availability contract.
    /// Contract validation uses this to find contradictory producer state.
    pub(crate) fn get_unchecked(self, name: &str) -> Option<CanonicalValue<'a>> {
        if let Some(mapping) = mapping(self.name, name) {
            if let Some(value) = self.event.canonical_value(mapping.canonical, self.name) {
                return Some(value);
            }
        }

        // Native, allowlisted Security fields and test-only generic payloads
        // are already named for the default compatibility view. They stay
        // behind the view boundary rather than making the canonical model
        // string-addressable or leaking automatically into future views.
        if self.name != FieldViewName::SYSMON {
            return None;
        }
        match &self.event.fields {
            EventFields::SecurityAudit(fields) => fields.get(name).map(CanonicalValue::String),
            EventFields::Generic(fields) => fields
                .get(name)
                .map(String::as_str)
                .map(CanonicalValue::String),
            _ => None,
        }
    }

    pub fn mappings(self) -> &'static [FieldMapping] {
        mappings(self.name)
    }

    pub fn dynamic_fields(self) -> Box<dyn Iterator<Item = (&'a str, &'a str)> + 'a> {
        if self.name != FieldViewName::SYSMON {
            return Box::new(std::iter::empty());
        }
        match &self.event.fields {
            EventFields::SecurityAudit(fields) => Box::new(
                fields
                    .fields
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            ),
            EventFields::Generic(fields) => Box::new(
                fields
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            ),
            _ => Box::new(std::iter::empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_availability::{Availability, FIELD_AVAILABILITY};

    #[test]
    fn sysmon_table_is_sorted_and_unique() {
        for pair in SYSMON_FIELDS.windows(2) {
            assert!(pair[0].name < pair[1].name, "{:?} is not sorted", pair);
        }
    }

    #[test]
    fn rustinel_fidelity_fields_are_part_of_the_sysmon_view() {
        for name in ["ImageSource", "ImageTruncated", "PathTruncated"] {
            assert!(mapping(FieldViewName::SYSMON, name).is_some(), "{name}");
        }
    }

    #[test]
    fn every_typed_available_field_has_a_sysmon_mapping() {
        for contract in FIELD_AVAILABILITY
            .iter()
            .filter(|contract| contract.view == FieldViewName::SYSMON)
            .filter(|contract| contract.category != "security")
        {
            for field in contract
                .fields
                .iter()
                .filter(|field| !matches!(field.availability, Availability::Never(_)))
            {
                assert!(
                    mapping(FieldViewName::SYSMON, field.field).is_some(),
                    "missing {}/{}/{}",
                    contract.platform.as_str(),
                    contract.category,
                    field.field
                );
            }
        }
    }
}
