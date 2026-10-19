//! Per-consumer result stores keyed by file identity, bounded by recency.

use std::collections::{HashMap, HashSet};

use super::job::ResolvePlan;
use super::{Artifact, ArtifactNeeds, PeMetadata, SignatureVerdict};
use crate::ioc::{ComputedHashes, HashRequirements};
use crate::models::{MatchDebugLevel, YaraRuleMatch};
use crate::utils::file_identity::FileIdentity;

pub(super) const ARTIFACT_STORE_CAPACITY: usize = 10_000;
/// Eviction frees `capacity / 20` extra slots, amortizing its full-map scans.
const EVICTION_HEADROOM_DIVISOR: usize = 20;

pub(super) struct Cached<T> {
    pub(super) value: T,
}

/// Optional results a store insert records even when they are absent.
#[derive(Debug, Clone, Copy)]
pub(super) struct StoredParts {
    pub(super) pe: bool,
    pub(super) imphash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct YaraCacheKey {
    pub(super) identity: FileIdentity,
    pub(super) generation: u64,
    pub(super) match_debug: MatchDebugLevel,
}

pub(super) struct ArtifactStores {
    pub(super) pe: HashMap<FileIdentity, Cached<Option<PeMetadata>>>,
    pub(super) hashes: HashMap<FileIdentity, Cached<ComputedHashes>>,
    /// `None` records that the file has no imphash, so it is not re-read.
    pub(super) imphashes: HashMap<FileIdentity, Cached<Option<String>>>,
    pub(super) signatures: HashMap<FileIdentity, Cached<SignatureVerdict>>,
    pub(super) yara: HashMap<YaraCacheKey, Cached<Vec<YaraRuleMatch>>>,
    recency: HashMap<FileIdentity, u64>,
    pub(super) capacity: usize,
    clock: u64,
    pub(super) evicted: u64,
    pub(super) yara_generation: Option<u64>,
}

impl ArtifactStores {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            pe: HashMap::new(),
            hashes: HashMap::new(),
            imphashes: HashMap::new(),
            signatures: HashMap::new(),
            yara: HashMap::new(),
            recency: HashMap::new(),
            capacity,
            clock: 0,
            evicted: 0,
            yara_generation: None,
        }
    }

    fn touch(&mut self, identity: &FileIdentity) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.recency.insert(identity.clone(), self.clock);
        self.clock
    }

    pub(super) fn load(
        &mut self,
        identity: &FileIdentity,
        plan: &ResolvePlan,
        artifact: &mut Artifact,
        missing: &mut ArtifactNeeds,
    ) {
        self.invalidate_yara(plan.yara.as_ref().map(|(generation, _)| *generation));
        self.touch(identity);
        self.evict();
        if missing.pe_metadata {
            if let Some(entry) = self.pe.get_mut(identity) {
                artifact.pe_metadata = entry.value.clone();
                missing.pe_metadata = false;
            }
        }
        if missing.hashes.md5 || missing.hashes.sha1 || missing.hashes.sha256 {
            if let Some(entry) = self.hashes.get_mut(identity) {
                let value = &entry.value;
                if (!missing.hashes.md5 || value.md5.is_some())
                    && (!missing.hashes.sha1 || value.sha1.is_some())
                    && (!missing.hashes.sha256 || value.sha256.is_some())
                {
                    artifact.hashes = Some(value.clone());
                    missing.hashes = HashRequirements {
                        md5: false,
                        sha1: false,
                        sha256: false,
                    };
                }
            }
        }
        if missing.imphash {
            if let Some(entry) = self.imphashes.get_mut(identity) {
                artifact.imphash = entry.value.clone();
                missing.imphash = false;
            }
        }
        if missing.signature {
            if let Some(entry) = self.signatures.get_mut(identity) {
                artifact.signature = Some(entry.value.clone());
                missing.signature = false;
            }
        }
        if missing.yara {
            if let Some((generation, _)) = &plan.yara {
                let key = YaraCacheKey {
                    identity: identity.clone(),
                    generation: *generation,
                    match_debug: plan.match_debug,
                };
                if let Some(entry) = self.yara.get_mut(&key) {
                    artifact.yara = Some(entry.value.clone());
                    missing.yara = false;
                }
            }
        }
    }

    pub(super) fn insert(
        &mut self,
        identity: FileIdentity,
        plan: &ResolvePlan,
        artifact: &Artifact,
        stored: StoredParts,
    ) {
        self.touch(&identity);
        if stored.pe {
            self.pe.insert(
                identity.clone(),
                Cached {
                    value: artifact.pe_metadata.clone(),
                },
            );
        }
        if let Some(hashes) = &artifact.hashes {
            let merged = if let Some(existing) = self.hashes.remove(&identity) {
                ComputedHashes {
                    md5: hashes.md5.clone().or(existing.value.md5),
                    sha1: hashes.sha1.clone().or(existing.value.sha1),
                    sha256: hashes.sha256.clone().or(existing.value.sha256),
                }
            } else {
                hashes.clone()
            };
            self.hashes
                .insert(identity.clone(), Cached { value: merged });
        }
        if stored.imphash {
            self.imphashes.insert(
                identity.clone(),
                Cached {
                    value: artifact.imphash.clone(),
                },
            );
        }
        // An inconclusive verification is retried, not remembered.
        if let Some(signature) = artifact
            .signature
            .as_ref()
            .filter(|signature| **signature != SignatureVerdict::Unknown)
        {
            self.signatures.insert(
                identity.clone(),
                Cached {
                    value: signature.clone(),
                },
            );
        }
        if let (Some(matches), Some((generation, _))) = (&artifact.yara, &plan.yara) {
            if self.yara_generation == Some(*generation) {
                self.yara.insert(
                    YaraCacheKey {
                        identity: identity.clone(),
                        generation: *generation,
                        match_debug: plan.match_debug,
                    },
                    Cached {
                        value: matches.clone(),
                    },
                );
            }
        }
        self.evict();
    }

    pub(super) fn invalidate_yara(&mut self, generation: Option<u64>) {
        let Some(generation) = generation else {
            return;
        };
        match self.yara_generation {
            Some(active) if generation <= active => return,
            Some(_) => self.yara.clear(),
            None => {}
        }
        self.yara_generation = Some(generation);
    }

    /// Revocation freshness is independent from immutable file-derived data.
    #[allow(dead_code)] // No refresh path yet: verification checks no revocation.
    fn invalidate_signatures(&mut self) {
        self.signatures.clear();
    }

    /// Trims to `capacity` less a headroom, so the full-map scans below are
    /// paid once per batch of inserts instead of once per insert.
    fn evict(&mut self) {
        if self.recency.len() <= self.capacity {
            return;
        }
        let keep = self
            .capacity
            .saturating_sub(self.eviction_headroom())
            .max(1);
        let excess = self.recency.len().saturating_sub(keep);
        let mut by_age: Vec<(u64, &FileIdentity)> = self
            .recency
            .iter()
            .map(|(identity, used)| (*used, identity))
            .collect();
        by_age.select_nth_unstable_by_key(excess - 1, |(used, _)| *used);
        let victims: HashSet<FileIdentity> = by_age[..excess]
            .iter()
            .map(|(_, identity)| (*identity).clone())
            .collect();
        for identity in &victims {
            self.recency.remove(identity);
            self.pe.remove(identity);
            self.hashes.remove(identity);
            self.imphashes.remove(identity);
            self.signatures.remove(identity);
        }
        if !self.yara.is_empty() {
            self.yara.retain(|key, _| !victims.contains(&key.identity));
        }
        self.evicted = self.evicted.saturating_add(victims.len() as u64);
    }

    fn eviction_headroom(&self) -> usize {
        (self.capacity / EVICTION_HEADROOM_DIVISOR).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::file_identity;

    #[test]
    fn stale_yara_generation_cannot_move_the_store_backward() {
        let mut stores = ArtifactStores::new(10);
        stores.invalidate_yara(Some(2));
        stores.invalidate_yara(Some(0));
        assert_eq!(stores.yara_generation, Some(2));
    }

    fn seed(stores: &mut ArtifactStores, n: u64) {
        let identity = file_identity::synthetic(n);
        stores.touch(&identity);
        stores.hashes.insert(
            identity.clone(),
            Cached {
                value: ComputedHashes::default(),
            },
        );
        stores.pe.insert(identity.clone(), Cached { value: None });
        stores
            .imphashes
            .insert(identity.clone(), Cached { value: None });
        stores.yara.insert(
            YaraCacheKey {
                identity,
                generation: 1,
                match_debug: MatchDebugLevel::Off,
            },
            Cached { value: Vec::new() },
        );
        stores.evict();
    }

    #[test]
    fn eviction_drops_the_oldest_identities_from_every_part_in_one_batch() {
        let mut stores = ArtifactStores::new(100);
        for n in 0..100 {
            seed(&mut stores, n);
        }
        assert_eq!(stores.recency.len(), 100);
        assert_eq!(stores.evicted, 0);

        seed(&mut stores, 100);
        // 101 entries trims to 100 - 5 headroom, evicting the 6 oldest.
        assert_eq!(stores.recency.len(), 95);
        assert_eq!(stores.evicted, 6);
        for map_len in [
            stores.hashes.len(),
            stores.pe.len(),
            stores.imphashes.len(),
            stores.yara.len(),
        ] {
            assert_eq!(map_len, 95);
        }
        for n in 0..6 {
            let id = file_identity::synthetic(n);
            assert!(!stores.hashes.contains_key(&id));
            assert!(!stores.recency.contains_key(&id));
        }
        for n in 6..=100 {
            assert!(stores.hashes.contains_key(&file_identity::synthetic(n)));
        }
    }

    #[test]
    fn the_store_stays_bounded_and_keeps_the_newest_identity() {
        for capacity in [1, 2, 7, 100] {
            let mut stores = ArtifactStores::new(capacity);
            for n in 0..1_000 {
                seed(&mut stores, n);
                assert!(stores.recency.len() <= capacity);
                assert!(stores.hashes.contains_key(&file_identity::synthetic(n)));
            }
        }
    }

    /// `cargo test --release store_eviction_cost -- --ignored --nocapture`
    #[test]
    #[ignore = "timing probe, not a correctness test"]
    fn store_eviction_cost() {
        for (capacity, seeded) in [(10_000usize, 10_000u64), (30_000, 10_000)] {
            let mut stores = ArtifactStores::new(capacity);
            for n in 0..seeded {
                seed(&mut stores, n);
            }
            let ops = 20_000u64;
            let start = std::time::Instant::now();
            for n in seeded..seeded + ops {
                seed(&mut stores, n);
            }
            let per_op = start.elapsed().as_secs_f64() * 1e6 / ops as f64;
            println!(
                "capacity {capacity}: {per_op:.3} us/op, evicted {}",
                stores.evicted
            );
        }
    }
}
