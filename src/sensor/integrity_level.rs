//! Windows mandatory-label (integrity level) decoding.
//!
//! Microsoft-Windows-Kernel-Process reports a process's integrity level on its
//! start event as `MandatoryLabel`, a `win:SID` whose relative identifier is
//! one of the `SECURITY_MANDATORY_*_RID` constants in `winnt.h`. Sigma rules
//! are written against Sysmon's spelling of that level (`System`, `High`,
//! `Medium`), so the SID has to be translated before the value reaches the
//! engine (#294).
//!
//! Lives outside the `windows` module, like [`super::network_events`], so the
//! translation is unit-tested on every host rather than only on Windows.

/// Prefix of a mandatory label SID (`SECURITY_MANDATORY_LABEL_AUTHORITY`,
/// authority 16), followed by the single sub-authority that names the level.
const MANDATORY_LABEL_PREFIX: &str = "S-1-16-";

/// `SECURITY_MANDATORY_*_RID` values from `winnt.h`, paired with the level
/// names Sysmon emits. Sysmon writes them in title case with no separator, and
/// the SigmaHQ corpus matches on that spelling exactly, so the casing here is
/// part of the contract rather than cosmetic.
const MANDATORY_LABEL_LEVELS: &[(u32, &str)] = &[
    (0x0000_0000, "Untrusted"),
    (0x0000_1000, "Low"),
    (0x0000_2000, "Medium"),
    (0x0000_2100, "MediumPlus"),
    (0x0000_3000, "High"),
    (0x0000_4000, "System"),
    (0x0000_5000, "ProtectedProcess"),
];

/// Translate a `MandatoryLabel` SID into an integrity level name.
///
/// Returns `None` for anything that is not a mandatory label SID, so a
/// provider change cannot quietly put an unrelated SID in a field rules match
/// on by name. A mandatory label carrying an RID Windows has not defined is
/// passed through as the raw SID: the level is real, only its name is unknown,
/// and dropping it would hide the process from an operator reading the alert.
pub(crate) fn integrity_level_from_sid(sid: &str) -> Option<String> {
    let sid = sid.trim().trim_end_matches('\0').trim();

    // `ConvertSidToStringSidW` returns upper case, but a SID is not a
    // case-sensitive string and callers may have normalized it.
    let prefix = sid.get(..MANDATORY_LABEL_PREFIX.len())?;
    if !prefix.eq_ignore_ascii_case(MANDATORY_LABEL_PREFIX) {
        return None;
    }

    let rid = sid[MANDATORY_LABEL_PREFIX.len()..].parse::<u32>().ok()?;

    let name = MANDATORY_LABEL_LEVELS
        .iter()
        .find(|(known, _)| *known == rid)
        .map(|(_, name)| (*name).to_string());

    Some(name.unwrap_or_else(|| sid.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_levels_use_sysmon_spelling() {
        // The three the SigmaHQ corpus actually selects on, plus the rest of
        // the documented set. A change to any of these spellings silently
        // stops 29 rules from matching.
        assert_eq!(
            integrity_level_from_sid("S-1-16-16384").as_deref(),
            Some("System")
        );
        assert_eq!(
            integrity_level_from_sid("S-1-16-12288").as_deref(),
            Some("High")
        );
        assert_eq!(
            integrity_level_from_sid("S-1-16-8192").as_deref(),
            Some("Medium")
        );
        assert_eq!(
            integrity_level_from_sid("S-1-16-8448").as_deref(),
            Some("MediumPlus")
        );
        assert_eq!(
            integrity_level_from_sid("S-1-16-4096").as_deref(),
            Some("Low")
        );
        assert_eq!(
            integrity_level_from_sid("S-1-16-0").as_deref(),
            Some("Untrusted")
        );
        assert_eq!(
            integrity_level_from_sid("S-1-16-20480").as_deref(),
            Some("ProtectedProcess")
        );
    }

    #[test]
    fn sid_case_does_not_matter() {
        assert_eq!(
            integrity_level_from_sid("s-1-16-12288").as_deref(),
            Some("High")
        );
    }

    #[test]
    fn surrounding_whitespace_and_null_terminators_are_ignored() {
        assert_eq!(
            integrity_level_from_sid("S-1-16-8192\0").as_deref(),
            Some("Medium")
        );
        assert_eq!(
            integrity_level_from_sid("  S-1-16-8192  ").as_deref(),
            Some("Medium")
        );
    }

    #[test]
    fn unknown_mandatory_label_falls_back_to_the_raw_sid() {
        // Windows can define a level this table does not know; reporting the
        // SID is wrong for a rule but right for a human, and it is visible.
        assert_eq!(
            integrity_level_from_sid("S-1-16-9999").as_deref(),
            Some("S-1-16-9999")
        );
    }

    #[test]
    fn non_label_sids_are_rejected() {
        // Local System: a real SID, but not an integrity level. Emitting it
        // would be worse than emitting nothing.
        assert_eq!(integrity_level_from_sid("S-1-5-18"), None);
        assert_eq!(integrity_level_from_sid("S-1-16-"), None);
        assert_eq!(integrity_level_from_sid("S-1-16-8192-1"), None);
        assert_eq!(integrity_level_from_sid("S-1-16-0x2000"), None);
        assert_eq!(integrity_level_from_sid("S-1-16--1"), None);
        assert_eq!(integrity_level_from_sid("Medium"), None);
        assert_eq!(integrity_level_from_sid(""), None);
    }

    #[test]
    fn multibyte_input_does_not_panic() {
        assert_eq!(integrity_level_from_sid("é"), None);
        assert_eq!(integrity_level_from_sid("S-1-16é"), None);
    }
}
