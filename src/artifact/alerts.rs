//! Detections raised directly from artifact bytes: hash IOC and YARA file
//! matches. They run after admission and never feed Sigma.
//!
//! This is the one place the artifact resolver builds YARA alerts.

use super::job::ArtifactJob;
use super::resolver::ArtifactResolver;
use super::Artifact;
use crate::ioc::ComputedHashes;
use crate::models::YaraScanSource;

impl ArtifactResolver {
    /// Raise the detections that consume artifact bytes directly. They run
    /// after admission and never feed Sigma.
    pub(super) fn apply(&self, job: &ArtifactJob, artifact: &Artifact) {
        if let Some(hashes) = &artifact.hashes {
            self.apply_hash_iocs(job, hashes);
        }

        if let Some(matches) = &artifact.yara {
            for rule_match in matches {
                let details =
                    crate::scanner::build_yara_match_details(self.runtime.match_debug, rule_match);
                let mut alert = crate::scanner::build_yara_alert(
                    rule_match,
                    &job.target.display_path,
                    job.target.pid,
                    &job.provenance,
                    details,
                    job.platform,
                    &job.provider,
                );
                job.describe_subject(&mut alert);
                if let Some(sink) = &self.runtime.alert_sink {
                    sink.write_yara_alert(&alert, YaraScanSource::File);
                }
                if let Some(response) = &self.runtime.response_engine {
                    response.handle_alert(&alert);
                }
            }
        }
    }

    pub(super) fn apply_hash_iocs(&self, job: &ArtifactJob, hashes: &ComputedHashes) {
        if let Some(ioc) = &job.plan.ioc {
            for ioc_match in ioc.match_hashes(hashes) {
                let mut alert = ioc.build_alert_for_hash_match(
                    &ioc_match,
                    &job.target.display_path,
                    job.target.pid,
                    &job.provenance,
                    job.platform,
                    &job.provider,
                );
                job.describe_subject(&mut alert);
                if let Some(sink) = &self.runtime.alert_sink {
                    sink.write_alert(&alert);
                }
                if let Some(response) = &self.runtime.response_engine {
                    response.handle_alert(&alert);
                }
            }
        }
    }
}
