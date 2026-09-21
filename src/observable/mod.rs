//! Indicator-shaped values carried by a canonical event.
//!
//! This is the one place that knows which event fields hold a domain, an IP
//! address, a path, or a hash. Each event is walked once into a small list of
//! [`Observable`]s, and indicator matching reads only that list. Adding a field
//! here makes it matchable by every indicator of its kind, with no change to
//! the matcher.
//!
//! Extraction never rewrites the event. A relative command-line operand is
//! resolved against the process working directory into an absolute
//! [`Observable::Path`], while `CommandLine` itself stays exactly as the sensor
//! recorded it for Sigma and for alert output.

mod path;
mod text;

use crate::models::{EventFields, NormalizedEvent};
use crate::sensor::Platform;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use text::Text;

/// One indicator-shaped value found on an event.
///
/// Values borrow from the event wherever they appear in it verbatim. Only a
/// path assembled from a working directory, or normalized from `..` and
/// separator forms, is owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observable<'a> {
    /// A host name, trimmed of surrounding whitespace and trailing dots but
    /// otherwise as observed. Case is left to the consumer.
    Domain(&'a str),
    Ip(IpAddr),
    /// A file-system path. Absolute unless it came from a field the sensor
    /// reports as-is, such as `Image`.
    Path(Cow<'a, str>),
    Md5(&'a str),
    Sha1(&'a str),
    Sha256(&'a str),
}

impl fmt::Display for Observable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Observable::Domain(value) => write!(f, "domain:{value}"),
            Observable::Ip(value) => write!(f, "ip:{value}"),
            Observable::Path(value) => write!(f, "path:{value}"),
            Observable::Md5(value) => write!(f, "md5:{value}"),
            Observable::Sha1(value) => write!(f, "sha1:{value}"),
            Observable::Sha256(value) => write!(f, "sha256:{value}"),
        }
    }
}

/// The observables of one event, inline for the common case of a handful.
pub type Observables<'a> = SmallVec<[Observable<'a>; 8]>;

/// Walk `event` once and collect every observable it carries, in field order.
///
/// | Event | Observables |
/// | --- | --- |
/// | Process | `Image`, `ParentImage`, `TargetImage`; paths, hosts, and IPs in `CommandLine` operands |
/// | File | `TargetFilename`, `SourceFilename` |
/// | Registry | Absolute paths, hosts, and IPs in `Details` |
/// | Network | `DestinationIp`, `SourceIp`, `DestinationHostname` |
/// | DNS | `QueryName`; hosts and IPs in `QueryResults` |
/// | Image load | `ImageLoaded` |
/// | PowerShell script | `Path`; absolute paths, hosts, and IPs in `ScriptBlockText` |
/// | WMI | `DestinationHostname`; absolute paths, hosts, and IPs in `Query` |
/// | Service | `ServiceFileName`; hosts and IPs in it |
///
/// Hashes are not event fields: they are computed from the file behind an
/// event, and [`hashes`] turns them into observables.
pub fn extract(event: &NormalizedEvent) -> Observables<'_> {
    let windows = event.platform == Platform::Windows;
    let mut out = Observables::new();

    match &event.fields {
        EventFields::ProcessCreation(f) => {
            push_path(&mut out, f.image.as_deref());
            push_path(&mut out, f.parent_image.as_deref());
            push_path(&mut out, f.target_image.as_deref());
            if let Some(command_line) = f.command_line.as_deref() {
                let kind = Text::CommandLine {
                    cwd: f.current_directory.as_deref(),
                    has_image: f.image.as_deref().is_some_and(|image| !image.is_empty()),
                };
                text::scan(command_line, kind, windows, &mut out);
            }
        }
        EventFields::FileEvent(f) => {
            push_path(&mut out, f.target_filename.as_deref());
            push_path(&mut out, f.source_filename.as_deref());
        }
        EventFields::RegistryEvent(f) => {
            push_text(&mut out, f.details.as_deref(), Text::Prose, windows);
        }
        EventFields::NetworkConnection(f) => {
            push_ip(&mut out, f.destination_ip.as_deref());
            push_ip(&mut out, f.source_ip.as_deref());
            push_domain(&mut out, f.destination_hostname.as_deref());
        }
        EventFields::DnsQuery(f) => {
            push_domain(&mut out, f.query_name.as_deref());
            push_text(&mut out, f.query_results.as_deref(), Text::Network, windows);
        }
        EventFields::ImageLoad(f) => {
            push_path(&mut out, f.image_loaded.as_deref());
        }
        EventFields::PowerShellScript(f) => {
            push_path(&mut out, f.path.as_deref());
            push_text(
                &mut out,
                f.script_block_text.as_deref(),
                Text::Prose,
                windows,
            );
        }
        EventFields::PowerShellClassicStart(f) => {
            push_text(&mut out, f.data.as_deref(), Text::Prose, windows);
        }
        EventFields::WmiEvent(f) => {
            push_domain(&mut out, f.destination_hostname.as_deref());
            push_text(&mut out, f.query.as_deref(), Text::Prose, windows);
        }
        EventFields::ServiceCreation(f) => {
            // The whole value stays the path it always was, so an unquoted
            // `C:\Program Files\...` image path is still one observable.
            push_path(&mut out, f.service_file_name.as_deref());
            push_text(
                &mut out,
                f.service_file_name.as_deref(),
                Text::Network,
                windows,
            );
        }
        EventFields::PowerShellModule(_)
        | EventFields::TaskCreation(_)
        | EventFields::SecurityAudit(_)
        | EventFields::Generic(_) => {}
    }

    out
}

/// Observables for hashes computed from the file behind an event.
pub fn hashes<'a>(
    md5: Option<&'a str>,
    sha1: Option<&'a str>,
    sha256: Option<&'a str>,
) -> Observables<'a> {
    md5.map(Observable::Md5)
        .into_iter()
        .chain(sha1.map(Observable::Sha1))
        .chain(sha256.map(Observable::Sha256))
        .collect()
}

fn push_path<'a>(out: &mut Observables<'a>, value: Option<&'a str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        out.push(Observable::Path(Cow::Borrowed(value)));
    }
}

fn push_domain<'a>(out: &mut Observables<'a>, value: Option<&'a str>) {
    let Some(host) = value.map(|value| value.trim().trim_end_matches('.')) else {
        return;
    };
    if !host.is_empty() {
        out.push(Observable::Domain(host));
    }
}

fn push_ip(out: &mut Observables<'_>, value: Option<&str>) {
    if let Some(ip) = value.and_then(|value| value.parse::<IpAddr>().ok()) {
        out.push(Observable::Ip(ip));
    }
}

fn push_text<'a>(out: &mut Observables<'a>, value: Option<&'a str>, kind: Text<'_>, windows: bool) {
    if let Some(value) = value {
        text::scan(value, kind, windows, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DnsQueryFields, EventCategory, FileEventFields, ProcessCreationFields, RegistryEventFields,
        ServiceCreationFields,
    };

    fn event(platform: Platform, category: EventCategory, fields: EventFields) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            source_seq: None,
            ingest_seq: 0,
            platform,
            provider: "test".into(),
            category,
            event_id: 1,
            event_id_string: "1".into(),
            opcode: 1,
            fields,
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        }
    }

    fn rendered(event: &NormalizedEvent) -> Vec<String> {
        extract(event).iter().map(ToString::to_string).collect()
    }

    fn process_fields(image: &str, command_line: &str, cwd: Option<&str>) -> ProcessCreationFields {
        ProcessCreationFields {
            hashes: None,
            imphash: None,
            container: Default::default(),
            linux_identity: Default::default(),
            cgroup_id: None,
            exec: Default::default(),
            parent_process_id_derived: false,
            windows: Default::default(),
            image: Some(image.into()),
            image_source: None,
            image_truncated: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: Some(command_line.into()),
            process_id: Some("42".into()),
            process_start_time: None,
            parent_process_id: None,
            parent_image: Some("/usr/bin/bash".into()),
            parent_command_line: Some("bash ./ignored-parent-operand".into()),
            parent_user: None,
            current_directory: cwd.map(Into::into),
            integrity_level: None,
            user: None,
        }
    }

    #[test]
    fn process_events_offer_images_and_command_line_operands() {
        let event = event(
            Platform::Linux,
            EventCategory::Process,
            EventFields::ProcessCreation(process_fields(
                "/usr/bin/chmod",
                "chmod +x malware",
                Some("/tmp"),
            )),
        );
        assert_eq!(
            rendered(&event),
            [
                "path:/usr/bin/chmod",
                "path:/usr/bin/bash",
                "path:/tmp/malware"
            ]
        );
    }

    #[test]
    fn extraction_leaves_the_command_line_untouched() {
        let event = event(
            Platform::Linux,
            EventCategory::Process,
            EventFields::ProcessCreation(process_fields(
                "/usr/bin/chmod",
                "chmod +x ./a/../malware",
                Some("/tmp"),
            )),
        );
        let observables = extract(&event);
        assert!(observables.contains(&Observable::Path(Cow::Owned("/tmp/malware".into()))));
        assert_eq!(
            event.get_field("CommandLine"),
            Some("chmod +x ./a/../malware")
        );
    }

    #[test]
    fn verbatim_fields_are_borrowed() {
        let event = event(
            Platform::Linux,
            EventCategory::Process,
            EventFields::ProcessCreation(process_fields("/usr/bin/true", "true", None)),
        );
        assert!(extract(&event)
            .iter()
            .all(|observable| matches!(observable, Observable::Path(Cow::Borrowed(_)))));
    }

    #[test]
    fn rename_events_offer_both_paths() {
        let event = event(
            Platform::Linux,
            EventCategory::File,
            EventFields::FileEvent(FileEventFields {
                source_filename: Some("/tmp/staged".into()),
                target_filename: Some("/usr/local/bin/tool".into()),
                process_id: None,
                image: Some("/usr/bin/mv".into()),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: None,
                file_identity: None,
                path_truncated: None,
            }),
        );
        assert_eq!(
            rendered(&event),
            ["path:/usr/local/bin/tool", "path:/tmp/staged"]
        );
    }

    #[test]
    fn registry_details_are_scanned() {
        let event = event(
            Platform::Windows,
            EventCategory::Registry,
            EventFields::RegistryEvent(RegistryEventFields {
                target_object: Some(
                    r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\x".into(),
                ),
                details: Some(r#""C:\Users\Public\run me.exe" --c2 https://evil.example/"#.into()),
                process_id: None,
                image: None,
                event_type: None,
                user: None,
                new_name: None,
            }),
        );
        assert_eq!(
            rendered(&event),
            [r"path:C:\Users\Public\run me.exe", "domain:evil.example"]
        );
    }

    #[test]
    fn service_image_paths_stay_whole_and_offer_hosts() {
        let event = event(
            Platform::Windows,
            EventCategory::Service,
            EventFields::ServiceCreation(ServiceCreationFields {
                provider_name: None,
                service_name: Some("svc".into()),
                service_file_name: Some(r"C:\Program Files\svc.exe -s 203.0.113.9".into()),
                service_type: None,
                start_type: None,
                account_name: None,
                user: None,
                process_id: None,
                image: None,
            }),
        );
        assert_eq!(
            rendered(&event),
            [
                r"path:C:\Program Files\svc.exe -s 203.0.113.9",
                "ip:203.0.113.9"
            ]
        );
    }

    #[test]
    fn dns_names_are_trimmed_and_blank_names_dropped() {
        let dns = |name: Option<&str>| {
            event(
                Platform::Linux,
                EventCategory::Dns,
                EventFields::DnsQuery(DnsQueryFields {
                    user: None,
                    query_name: name.map(Into::into),
                    query_results: None,
                    record_type: None,
                    query_status: None,
                    process_id: None,
                    image: None,
                }),
            )
        };
        assert_eq!(
            rendered(&dns(Some("  EXAMPLE.TEST...\t"))),
            ["domain:EXAMPLE.TEST"]
        );
        assert!(rendered(&dns(Some(" ... "))).is_empty());
        assert!(rendered(&dns(None)).is_empty());
    }

    #[test]
    fn hashes_keep_their_algorithm() {
        assert_eq!(
            hashes(Some("aa"), None, Some("cc"))
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["md5:aa", "sha256:cc"]
        );
    }
}
