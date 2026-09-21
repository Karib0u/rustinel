//! Rules evaluated in the deferred pass, after artifact resolution.
//!
//! `Hashes` and `Imphash` are computed from the file behind an event, which
//! takes longer than the admission budget allows (#427). A rule that selects
//! on either field is therefore evaluated in a separate pass on the event once
//! the artifact resolver has filled them, and never in the admission pass, so
//! every rule sees each event exactly once.
//!
//! Classification happens once at load time. A rule is deferred when its own
//! detection names one of these fields, or when a filter that applies to it
//! does, because the filter becomes part of the rule's condition.

use std::collections::HashSet;

use rsigma_parser::{
    Detection, DetectionItem, Detections, FilterRule, FilterRuleTarget, LogSource, SigmaCollection,
    SigmaRule, SigmaValue,
};

use super::logsource::logsource_key;
use super::{Engine, LogSourceKey};
use crate::models::NormalizedEvent;

/// Sysmon's multi-digest field: `SHA1=...,MD5=...,SHA256=...,IMPHASH=...`.
pub(crate) const HASHES_FIELD: &str = "Hashes";
/// The import hash on its own, as older Sigma rules spell it.
pub(crate) const IMPHASH_FIELD: &str = "Imphash";

/// Which evaluation of an event a caller is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionPass {
    /// Every rule and every inline detector, on an event that will not get a
    /// deferred pass. Replay and events without a pending artifact use this.
    All,
    /// Every rule except deferred-pass rules, plus inline detectors, on an
    /// event whose deferred pass is pending.
    Admission,
    /// Only deferred-pass rules, on the event after artifact resolution.
    Deferred,
}

impl DetectionPass {
    pub(crate) fn includes_admission(self) -> bool {
        matches!(self, Self::All | Self::Admission)
    }

    pub(crate) fn includes_deferred(self) -> bool {
        matches!(self, Self::All | Self::Deferred)
    }
}

/// Artifact-derived field values deferred-pass rules can select on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArtifactFieldNeeds {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
    pub imphash: bool,
}

impl ArtifactFieldNeeds {
    pub(crate) const ALL: Self = Self {
        md5: true,
        sha1: true,
        sha256: true,
        imphash: true,
    };

    pub fn is_empty(self) -> bool {
        !self.md5 && !self.sha1 && !self.sha256 && !self.imphash
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self {
            md5: self.md5 || other.md5,
            sha1: self.sha1 || other.sha1,
            sha256: self.sha256 || other.sha256,
            imphash: self.imphash || other.imphash,
        }
    }
}

/// Deferred-pass rules of one loaded collection.
#[derive(Debug, Default)]
pub(crate) struct DeferredRules {
    /// `(effective id, title)`, the identity RSigma puts on a result header.
    identities: HashSet<(Option<String>, String)>,
    /// What each deferred rule needs, by the logsource it routes on.
    needs: Vec<(LogSourceKey, ArtifactFieldNeeds)>,
}

impl DeferredRules {
    /// Classify an already-filtered collection whose rules carry the effective
    /// ids RSigma will report.
    pub(crate) fn classify(collection: &SigmaCollection) -> Self {
        let mut needs: Vec<ArtifactFieldNeeds> = collection
            .rules
            .iter()
            .map(|rule| detection_needs(&rule.detection))
            .collect();
        for filter in &collection.filters {
            let filter_needs = detection_needs(&filter.detection);
            if filter_needs.is_empty() {
                continue;
            }
            for (rule, rule_needs) in collection.rules.iter().zip(needs.iter_mut()) {
                if filter_applies(filter, rule) {
                    *rule_needs = rule_needs.union(filter_needs);
                }
            }
        }

        let mut deferred = Self::default();
        for (rule, rule_needs) in collection.rules.iter().zip(needs) {
            if rule_needs.is_empty() {
                continue;
            }
            deferred
                .identities
                .insert((rule.id.clone(), rule.title.clone()));
            deferred
                .needs
                .push((logsource_key(&rule.logsource), rule_needs));
        }
        deferred
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.identities.extend(other.identities);
        self.needs.extend(other.needs);
    }

    pub(crate) fn len(&self) -> usize {
        self.identities.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    pub(crate) fn contains(&self, rule_id: Option<&str>, rule_title: &str) -> bool {
        !self.is_empty()
            && self
                .identities
                .contains(&(rule_id.map(str::to_string), rule_title.to_string()))
    }

    /// The fields deferred-pass rules could select on for this event, or empty
    /// when none of them routes to its logsource.
    pub(crate) fn needs_for(&self, event: &NormalizedEvent) -> ArtifactFieldNeeds {
        if self.is_empty() {
            return ArtifactFieldNeeds::default();
        }
        let routes = Engine::concrete_logsource_routes_for_event(event);
        self.needs
            .iter()
            .filter(|(logsource, _)| {
                routes
                    .iter()
                    .any(|route| logsource.matches_tuple(&route.key))
            })
            .fold(ArtifactFieldNeeds::default(), |acc, (_, needs)| {
                acc.union(*needs)
            })
    }
}

fn detection_needs(detections: &Detections) -> ArtifactFieldNeeds {
    detections
        .named
        .values()
        .fold(ArtifactFieldNeeds::default(), |acc, detection| {
            acc.union(needs_in(detection))
        })
}

fn needs_in(detection: &Detection) -> ArtifactFieldNeeds {
    match detection {
        Detection::AllOf(items) => items
            .iter()
            .fold(ArtifactFieldNeeds::default(), |acc, item| {
                acc.union(item_needs(item))
            }),
        Detection::AnyOf(detections) | Detection::And(detections) => detections
            .iter()
            .fold(ArtifactFieldNeeds::default(), |acc, detection| {
                acc.union(needs_in(detection))
            }),
        Detection::ArrayMatch { body, .. } => needs_in(body),
        Detection::Conditional { named, .. } => named
            .values()
            .fold(ArtifactFieldNeeds::default(), |acc, detection| {
                acc.union(needs_in(detection))
            }),
        Detection::Keywords(_) => ArtifactFieldNeeds::default(),
    }
}

fn item_needs(item: &DetectionItem) -> ArtifactFieldNeeds {
    match item.field.name.as_deref() {
        Some(IMPHASH_FIELD) => ArtifactFieldNeeds {
            imphash: true,
            ..ArtifactFieldNeeds::default()
        },
        Some(HASHES_FIELD) => hashes_value_needs(&item.values),
        _ => ArtifactFieldNeeds::default(),
    }
}

/// Narrow `Hashes` to the digests a rule names by Sysmon prefix. A value that
/// names none of them (a regex, a bare digest, an `exists` check) could match
/// any part of the field, so it needs every digest.
fn hashes_value_needs(values: &[SigmaValue]) -> ArtifactFieldNeeds {
    let mut needs = ArtifactFieldNeeds::default();
    for value in values {
        let SigmaValue::String(text) = value else {
            return ArtifactFieldNeeds::ALL;
        };
        let text = text.original.to_ascii_uppercase();
        let named = ArtifactFieldNeeds {
            md5: text.contains("MD5="),
            sha1: text.contains("SHA1="),
            sha256: text.contains("SHA256="),
            imphash: text.contains("IMPHASH="),
        };
        if named.is_empty() {
            return ArtifactFieldNeeds::ALL;
        }
        needs = needs.union(named);
    }
    if needs.is_empty() {
        ArtifactFieldNeeds::ALL
    } else {
        needs
    }
}

/// Mirror RSigma's filter targeting: by rule id or title, restricted to rules
/// whose logsource the filter's logsource contains.
fn filter_applies(filter: &FilterRule, rule: &SigmaRule) -> bool {
    let targeted = match &filter.rules {
        FilterRuleTarget::Any => true,
        FilterRuleTarget::Specific(references) => references
            .iter()
            .any(|reference| rule.id.as_deref() == Some(reference) || rule.title == *reference),
    };
    targeted
        && filter
            .logsource
            .as_ref()
            .is_none_or(|logsource| logsource_contains(logsource, &rule.logsource))
}

fn logsource_contains(filter: &LogSource, rule: &LogSource) -> bool {
    let contains = |filter: &Option<String>, rule: &Option<String>| match filter {
        Some(filter) => rule
            .as_deref()
            .is_some_and(|rule| rule.eq_ignore_ascii_case(filter)),
        None => true,
    };
    contains(&filter.product, &rule.product)
        && contains(&filter.category, &rule.category)
        && contains(&filter.service, &rule.service)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(documents: &str) -> DeferredRules {
        let parsed = rsigma_parser::parse_sigma_yaml(documents).expect("rules parse");
        DeferredRules::classify(&parsed)
    }

    #[test]
    fn a_rule_naming_one_digest_needs_only_that_digest() {
        let deferred = classify(
            r#"
title: Imphash selection
id: 11111111-1111-4111-8111-111111111111
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Hashes|contains:
      - IMPHASH=AAAA
      - imphash=bbbb
  condition: selection
"#,
        );
        assert_eq!(deferred.len(), 1);
        assert_eq!(
            deferred.needs[0].1,
            ArtifactFieldNeeds {
                imphash: true,
                ..ArtifactFieldNeeds::default()
            }
        );
    }

    #[test]
    fn a_bare_hashes_value_needs_every_digest() {
        let deferred = classify(
            r#"
title: Bare digest
logsource:
  product: windows
  category: image_load
detection:
  selection:
    Hashes|contains: 0123456789abcdef
  condition: selection
"#,
        );
        assert_eq!(deferred.needs[0].1, ArtifactFieldNeeds::ALL);
        assert!(deferred.contains(None, "Bare digest"));
    }

    #[test]
    fn rules_without_artifact_fields_are_not_deferred() {
        let deferred = classify(
            r#"
title: Plain
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \whoami.exe
  keywords:
    - IMPHASH=
  condition: selection or keywords
"#,
        );
        assert!(deferred.is_empty());
    }

    #[test]
    fn a_filter_on_imphash_defers_the_rules_it_targets() {
        let deferred = classify(
            r#"
title: Target
id: 22222222-2222-4222-8222-222222222222
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \rundll32.exe
  condition: selection
---
title: Untouched
id: 33333333-3333-4333-8333-333333333333
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \cmd.exe
  condition: selection
---
title: Known imports
logsource:
  product: windows
  category: process_creation
filter:
  rules:
    - 22222222-2222-4222-8222-222222222222
  selection:
    Imphash: aaaa
  condition: not selection
"#,
        );
        assert!(deferred.contains(Some("22222222-2222-4222-8222-222222222222"), "Target"));
        assert!(!deferred.contains(Some("33333333-3333-4333-8333-333333333333"), "Untouched"));
    }
}
