//! Sparse counts of canonical fields with known fidelity limitations for doctor.
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::models::{Fidelity, FieldId, Provenance};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldFidelitySnapshot {
    pub field: String,
    pub fidelity: Fidelity,
    pub count: u64,
}

/// Counts of fields with known fidelity limits, one set per runtime.
#[derive(Debug, Default)]
pub struct ProvenanceCounters {
    counts: Mutex<BTreeMap<(FieldId, Fidelity), u64>>,
}

impl ProvenanceCounters {
    pub(crate) fn record(&self, provenance: &Provenance) {
        if provenance.is_empty() {
            return;
        }
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for entry in provenance.entries() {
            let count = counts
                .entry((entry.field.clone(), entry.fidelity))
                .or_default();
            *count = count.saturating_add(1);
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<FieldFidelitySnapshot> {
        self.counts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .map(|((field, fidelity), count)| FieldFidelitySnapshot {
                field: field.to_string(),
                fidelity: *fidelity,
                count: *count,
            })
            .collect()
    }
}
