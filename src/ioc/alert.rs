use super::types::{IocKind, IocMatch, IocMeta};
use std::collections::HashSet;

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
        comment: meta.comment.clone(),
        source: meta.source.clone(),
        line: meta.line,
    }
}

pub(crate) fn push_match_unique(
    matches: &mut Vec<IocMatch>,
    seen: &mut HashSet<String>,
    m: IocMatch,
) {
    let key = format!(
        "{}:{}:{}:{}:{}",
        m.kind.as_str(),
        m.indicator,
        m.observed,
        m.source,
        m.line
    );
    if seen.insert(key) {
        matches.push(m);
    }
}
