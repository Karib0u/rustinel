use super::types::{IocKind, IocMatch, IocMeta};

pub(crate) fn ioc_rule_name(m: &IocMatch) -> String {
    format!("ioc:{}:{}", m.kind.as_str(), m.indicator)
}

pub(crate) fn ioc_rule_description(m: &IocMatch) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(comment) = &m.comment {
        parts.push(comment.clone());
    }
    if m.observed != m.indicator {
        parts.push(format!("observed: {}", m.observed));
    }
    parts.push(format!("source: {}", m.source));
    Some(parts.join(" | "))
}

pub(crate) fn build_match(
    kind: IocKind,
    indicator: &str,
    observed: &str,
    meta: &IocMeta,
) -> IocMatch {
    IocMatch {
        kind,
        indicator: indicator.to_string(),
        observed: observed.to_string(),
        comment: meta.comment.as_deref().map(str::to_owned),
        source: meta.source.to_string(),
        line: meta.line,
    }
}

/// Append a match unless an identical one (same kind, indicator, observed
/// value, and feed line) is already present.
///
/// An event yields a handful of matches at most, so comparing against them
/// directly is cheaper than hashing a formatted key, and a duplicate is
/// rejected before any of its strings are allocated.
pub(crate) fn push_match(
    matches: &mut Vec<IocMatch>,
    kind: IocKind,
    indicator: &str,
    observed: &str,
    meta: &IocMeta,
) {
    let duplicate = matches.iter().any(|m| {
        m.kind == kind
            && m.line == meta.line
            && m.indicator == indicator
            && m.observed == observed
            && *m.source == *meta.source
    });
    if !duplicate {
        matches.push(build_match(kind, indicator, observed, meta));
    }
}
