//! Sparse counts of canonical fields with known fidelity limitations for doctor.
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

use crate::models::{Fidelity, FieldId, Provenance};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldFidelitySnapshot {
    pub field: String,
    pub fidelity: Fidelity,
    pub count: u64,
}

static COUNTS: LazyLock<Mutex<BTreeMap<(FieldId, Fidelity), u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(crate) fn record(provenance: &Provenance) {
    if provenance.is_empty() {
        return;
    }
    let mut counts = COUNTS.lock().unwrap_or_else(|error| error.into_inner());
    for entry in provenance.entries() {
        let count = counts
            .entry((entry.field.clone(), entry.fidelity))
            .or_default();
        *count = count.saturating_add(1);
    }
}

pub(super) fn snapshot() -> Vec<FieldFidelitySnapshot> {
    COUNTS
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
