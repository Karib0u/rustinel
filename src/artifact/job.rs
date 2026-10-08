//! One queued artifact: its resolve plan, the channels that release the
//! stages waiting on it, and the error taxonomy of a resolution.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::target::{ArtifactKind, ArtifactTarget};
use super::{ArtifactNeeds, ArtifactRuntime, PeMetadata};
use crate::engine::ArtifactFieldNeeds;
use crate::ioc::{ComputedHashes, HashRequirements};
use crate::models::{Alert, CanonicalEvent, EventFields, MatchDebugLevel, NormalizedEvent};
use crate::scanner::{self, Scanner};
use crate::sensor::Platform;
use crate::stages::admission::PeSender;
use crate::stages::deferred::{DeferredFields, DeferredSender};

pub(super) const ARTIFACT_DEADLINE: Duration = Duration::from_secs(10);
const ARTIFACT_MAX_READ_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const PE_MAX_READ_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct ResolvePlan {
    pub(super) needs: ArtifactNeeds,
    /// Artifact fields the deferred pass needs for this event.
    pub(super) deferred: ArtifactFieldNeeds,
    pub(super) ioc: Option<Arc<crate::ioc::IocEngine>>,
    pub(super) yara: Option<(u64, Arc<Scanner>)>,
    pub(super) max_read_bytes: u64,
    pub(super) hash_max_bytes: u64,
    pub(super) yara_max_bytes: u64,
    pub(super) deadline: Duration,
    pub(super) match_debug: MatchDebugLevel,
}

impl ResolvePlan {
    pub(super) fn snapshot(
        runtime: &ArtifactRuntime,
        event: &CanonicalEvent,
        target: &ArtifactTarget,
    ) -> Self {
        let path = if target.process_identity.is_some()
            && !crate::utils::process::linux_exec_uses_proc(&target.display_path)
        {
            Path::new(&target.display_path)
        } else {
            target
                .process_identity
                .as_ref()
                .map(|identity| Path::new(&identity.image))
                .unwrap_or(&target.path)
        };
        // Before capture a descriptor pathname tells us nothing about the
        // executable's allowlist status. Check consumers now, allowlists after capture.
        let unresolved_proc_image = target.kind == ArtifactKind::ProcessImage
            && event.normalized().platform == Platform::Linux
            && crate::utils::process::linux_exec_uses_proc(&target.display_path)
            && target.process_identity.is_none();
        let scans_content = target.kind != ArtifactKind::LoadedImage;
        let pe_image = event.normalized().platform == Platform::Windows
            && matches!(
                event.normalized().fields,
                EventFields::ProcessCreation(_) | EventFields::ImageLoad(_)
            );
        let pe_metadata = runtime.pe_metadata && pe_image;

        let mut needs = ArtifactNeeds {
            pe_metadata,
            ..ArtifactNeeds::default()
        };
        let mut max_read_bytes = if pe_metadata { PE_MAX_READ_BYTES } else { 0 };
        let mut hash_max_bytes = 0;
        let mut yara_max_bytes = 0;
        let mut deadline = ARTIFACT_DEADLINE;
        let mut ioc = None;
        let mut yara = None;
        // Only Windows PE images carry Sysmon's `Hashes` and `Imphash`.
        let deferred = match &runtime.detectors {
            Some(detectors) if pe_image => {
                detectors.sigma().deferred_field_needs(event.normalized())
            }
            _ => ArtifactFieldNeeds::default(),
        };
        if !deferred.is_empty() {
            needs.hashes = HashRequirements {
                md5: deferred.md5,
                sha1: deferred.sha1,
                sha256: deferred.sha256,
            };
            needs.imphash = deferred.imphash;
            hash_max_bytes = PE_MAX_READ_BYTES;
            max_read_bytes = max_read_bytes.max(PE_MAX_READ_BYTES);
        }

        if scans_content {
            if let Some(detectors) = &runtime.detectors {
                let current_ioc = detectors.ioc().clone();
                if current_ioc.wants_hashing()
                    && (unresolved_proc_image
                        || !current_ioc.is_hash_allowlisted(&path.to_string_lossy()))
                {
                    let ioc_hashes = current_ioc.hash_requirements();
                    needs.hashes = HashRequirements {
                        md5: needs.hashes.md5 || ioc_hashes.md5,
                        sha1: needs.hashes.sha1 || ioc_hashes.sha1,
                        sha256: needs.hashes.sha256 || ioc_hashes.sha256,
                    };
                    // One digest pass serves both consumers, so it covers the
                    // larger of their size limits.
                    hash_max_bytes =
                        hash_max_bytes.max(nonzero_limit(current_ioc.max_file_size_bytes()));
                    max_read_bytes = max_read_bytes.max(hash_max_bytes);
                    ioc = Some(current_ioc);
                }

                let (generation, current_yara) = detectors.yara_with_generation();
                if current_yara.compiled_files() > 0
                    && (unresolved_proc_image
                        || !scanner::is_path_allowlisted(
                            &path.to_string_lossy(),
                            &runtime.yara_allowlist_paths,
                        ))
                {
                    needs.yara = true;
                    yara_max_bytes = nonzero_limit(current_yara.limits().max_file_bytes);
                    max_read_bytes = max_read_bytes.max(yara_max_bytes);
                    if !current_yara.limits().timeout.is_zero() {
                        deadline = deadline.min(current_yara.limits().timeout);
                    }
                    yara = Some((generation, current_yara));
                }
            }
        }

        Self {
            needs,
            deferred,
            ioc,
            yara,
            max_read_bytes: max_read_bytes.min(ARTIFACT_MAX_READ_BYTES),
            hash_max_bytes,
            yara_max_bytes,
            deadline,
            match_debug: runtime.match_debug,
        }
    }
}

fn nonzero_limit(limit: u64) -> u64 {
    if limit == 0 {
        ARTIFACT_MAX_READ_BYTES
    } else {
        limit
    }
}

pub(super) struct ArtifactJob {
    pub(super) target: ArtifactTarget,
    pub(super) plan: ResolvePlan,
    pub(super) enqueued_at: Instant,
    /// Present while admission waits on PE metadata for this artifact.
    pub(super) pe_ready: Option<PeSender>,
    /// Present while the deferred stage waits on this artifact's fields.
    pub(super) deferred_ready: Option<DeferredSender>,
    /// PE metadata published for this job, handed on to the deferred pass.
    pub(super) resolved_pe: Option<PeMetadata>,
    /// Hashes published for this job, retained so IOC alerts survive a later
    /// consumer failure.
    pub(super) resolved_hashes: Option<ComputedHashes>,
    pub(super) process_start_key: Option<crate::sensor::ProcessStartKey>,
    /// Fidelity limitations on the image and PID the scan alerts report.
    pub(super) provenance: crate::models::Provenance,
    pub(super) platform: Platform,
    pub(super) provider: String,
    /// The file event a written-file target came from, reported as the alert
    /// subject instead of a process image.
    pub(super) written_file: Option<Box<NormalizedEvent>>,
}

impl ArtifactJob {
    /// Alerts on a written file describe that file and its writer, the way
    /// the file event did, rather than presenting it as a process image.
    pub(super) fn describe_subject(&self, alert: &mut Alert) {
        if let Some(event) = &self.written_file {
            let mut subject = (**event).clone();
            subject.timestamp = std::mem::take(&mut alert.event.timestamp);
            subject.source_seq = None;
            subject.ingest_seq = 0;
            alert.event = subject;
        }
    }

    /// Release admission as soon as PE metadata is known, or known absent.
    pub(super) fn publish_pe(&mut self, metadata: Option<PeMetadata>) {
        if self.deferred_ready.is_some() {
            self.resolved_pe = metadata.clone();
        }
        if let Some(ready) = self.pe_ready.take() {
            let _ = ready.try_send(metadata);
        }
    }

    /// Release the deferred pass once the artifact fields are known, or known
    /// unavailable. Only the first call sends.
    pub(super) fn publish_deferred(
        &mut self,
        hashes: Option<ComputedHashes>,
        imphash: Option<String>,
    ) {
        self.resolved_hashes = hashes.clone();
        if let Some(ready) = self.deferred_ready.take() {
            let _ = ready.try_send(DeferredFields {
                hashes,
                imphash,
                pe_metadata: self.resolved_pe.take(),
            });
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ResolveError {
    #[error("cannot open artifact: {0}")]
    Open(io::Error),
    #[error("artifact identity is unavailable or changed")]
    Identity,
    #[error("cannot read artifact: {0}")]
    Read(io::Error),
    #[error("artifact size {size} exceeds shared read limit {limit}")]
    TooLarge { size: u64, limit: u64 },
    #[error("artifact deadline exceeded after {} ms", .0.as_millis())]
    Deadline(Duration),
    #[error("artifact consumer failed: {0}")]
    Consumer(String),
}

impl ResolveError {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Open(_) => "open_failed",
            Self::Identity => "identity_mismatch",
            Self::Read(_) => "read_failed",
            Self::TooLarge { .. } => "oversized",
            Self::Deadline(_) => "deadline_exceeded",
            Self::Consumer(_) => "consumer_failed",
        }
    }
}
