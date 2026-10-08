//! Bounded, single-open resolution of file artifacts.
//!
//! Every on-disk consumer (Windows PE enrichment, IOC hashing, and YARA) reads
//! the same identity-validated handle once, and the bytes fan out to each
//! requested consumer. Targets are process images, loaded images, and, when a
//! `WrittenFileSelector` chooses them, files named by canonical file events.
//!
//! This module resolves artifacts and nothing else. Admission to detection and
//! capture, and the deferred Sigma pass for `Hashes` and `Imphash`, are
//! pipeline stages in `crate::stages`; resolution feeds them through
//! channels and never routes an event itself.
//!
//! - `target`: what is opened and the identity its bytes must still have.
//! - `written_file`: which file events become targets, their settle table, and
//!   the extension and magic-byte gate.
//! - `job`: the resolve plan and the queued job.
//! - `resolver`: the I/O pool and the single-open fan-out.
//! - `stores`: per-consumer result stores.
//! - `snapshot`: counters and the doctor telemetry snapshot.
//! - `ingress`: the sensor-facing handler and the wiring of resolver and
//!   stages.

mod alerts;
mod ingress;
mod job;
mod resolver;
mod snapshot;
mod stores;
mod target;
mod written_file;

#[cfg(test)]
pub(crate) mod test_support;

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::alerts::AlertSink;
use crate::engine::DetectorStore;
use crate::ioc::{ComputedHashes, HashRequirements};
use crate::models::{MatchDebugLevel, YaraRuleMatch};
use crate::response::ResponseEngine;
use crate::sensor::Platform;
use crate::utils::file_identity::FileIdentity;
pub use crate::vocab::PeMetadata;

pub(crate) use ingress::spawn_artifact_resolver;
pub(crate) use snapshot::ArtifactResolverHandle;
pub use snapshot::ArtifactResolverSnapshot;
pub(crate) use target::open_artifact;
#[cfg(all(test, target_os = "macos"))]
pub(crate) use target::{ArtifactTarget, ExpectedIdentity};
pub(crate) use written_file::{written_file_scan_selector, WrittenFileSelector};

/// Images and written files have separate queues and I/O slots so file churn
/// cannot shed images.
pub(crate) const ARTIFACT_QUEUE_CAPACITY: usize = 256;
type ArtifactOpener = Arc<dyn Fn(&Path) -> io::Result<File> + Send + Sync>;

/// Work requested from one shared artifact read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ArtifactNeeds {
    pub hashes: HashRequirements,
    pub imphash: bool,
    pub pe_metadata: bool,
    pub signature: bool,
    pub yara: bool,
}

impl ArtifactNeeds {
    /// Whether digests or the imphash still have to come from the bytes.
    fn needs_digest_read(self) -> bool {
        self.hashes.md5 || self.hashes.sha1 || self.hashes.sha256 || self.imphash
    }

    fn is_empty(self) -> bool {
        !self.hashes.md5
            && !self.hashes.sha1
            && !self.hashes.sha256
            && !self.imphash
            && !self.pe_metadata
            && !self.signature
            && !self.yara
    }
}

/// Results computed from a single identity-validated open handle.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // imphash and signature are extension points for #319/#320.
pub(crate) struct Artifact {
    pub identity: Option<FileIdentity>,
    pub hashes: Option<ComputedHashes>,
    /// Reserved for #319; it will consume the already-read bytes here.
    pub imphash: Option<String>,
    pub pe_metadata: Option<PeMetadata>,
    /// Reserved for #320; unknown remains distinct from unsigned.
    pub signature: Option<ArtifactSignature>,
    pub yara: Option<Vec<YaraRuleMatch>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // populated by the Authenticode consumer in #320.
pub(crate) enum ArtifactSignature {
    Unknown,
    Unsigned,
    Invalid,
    Valid { signer: Option<String> },
}

#[derive(Clone)]
pub(crate) struct ArtifactRuntime {
    pub detectors: Option<Arc<DetectorStore>>,
    pub alert_sink: Option<AlertSink>,
    pub response_engine: Option<ResponseEngine>,
    pub match_debug: MatchDebugLevel,
    pub yara_allowlist_paths: Vec<String>,
    pub pe_metadata: bool,
    /// `None` selects no file events, so only process and loaded images are
    /// resolved.
    pub written_files: Option<WrittenFileSelector>,
}

impl ArtifactRuntime {
    pub(crate) fn capture(platform: Platform) -> Self {
        Self {
            detectors: None,
            alert_sink: None,
            response_engine: None,
            match_debug: MatchDebugLevel::Off,
            yara_allowlist_paths: Vec::new(),
            pe_metadata: platform == Platform::Windows,
            written_files: None,
        }
    }
}

#[cfg(windows)]
fn parse_pe_metadata_bytes(bytes: &[u8]) -> Option<PeMetadata> {
    crate::utils::pe::parse_metadata_bytes(bytes)
}

#[cfg(not(windows))]
fn parse_pe_metadata_bytes(_bytes: &[u8]) -> Option<PeMetadata> {
    None
}

#[cfg(windows)]
fn parse_imphash_bytes(bytes: &[u8]) -> Option<String> {
    crate::utils::imphash::imphash_bytes(bytes)
}

#[cfg(not(windows))]
fn parse_imphash_bytes(_bytes: &[u8]) -> Option<String> {
    None
}
