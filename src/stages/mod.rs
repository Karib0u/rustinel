//! Ordered pipeline stages that sit between the sensors and detection.
//!
//! Both stages exist because enrichment from artifact resolution takes longer
//! than a sensor event can wait. Each owns one ordering rule and one time
//! budget, stated on the stage:
//!
//! - [`admission`]: events reach detection and capture in `ingest_seq` order,
//!   and PE metadata may hold an event for at most
//!   [`ADMISSION_BUDGET`](admission::ADMISSION_BUDGET).
//! - [`deferred`]: Sigma rules that select on `Hashes` or `Imphash` run once
//!   per event, in ingest order, after those fields resolve or
//!   [`DEFERRED_DETECTION_BUDGET`](deferred::DEFERRED_DETECTION_BUDGET)
//!   expires.
//!
//! The artifact resolver feeds both stages through channels and never routes an
//! event itself, so it cannot reorder anything.

pub(crate) mod admission;
pub(crate) mod deferred;

use crate::artifact::PeMetadata;
use crate::models::{CanonicalEvent, EventFields};

/// Copy resolved version-resource metadata onto a process-start or image-load
/// event and mark each filled field as derived rather than measured.
pub(crate) fn apply_pe_metadata(event: &mut CanonicalEvent, metadata: &PeMetadata) {
    let fields = match &mut event.normalized_mut().fields {
        EventFields::ProcessCreation(fields) => Some((
            &mut fields.original_file_name,
            &mut fields.product,
            &mut fields.description,
            &mut fields.company,
            &mut fields.file_version,
        )),
        EventFields::ImageLoad(fields) => Some((
            &mut fields.original_file_name,
            &mut fields.product,
            &mut fields.description,
            &mut fields.company,
            &mut fields.file_version,
        )),
        _ => None,
    };
    if let Some((original, product, description, company, version)) = fields {
        *original = metadata.original_filename.clone();
        *product = metadata.product.clone();
        *description = metadata.description.clone();
        *company = metadata.company.clone();
        *version = metadata.file_version.clone();
    }
    for (field, present) in [
        ("OriginalFileName", metadata.original_filename.is_some()),
        ("Product", metadata.product.is_some()),
        ("Description", metadata.description.is_some()),
        ("Company", metadata.company.is_some()),
        ("FileVersion", metadata.file_version.is_some()),
    ] {
        if present {
            event.normalized_mut().provenance.mark_derived(field);
        }
    }
}
