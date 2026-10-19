//! Shape of a DNS query name, for rules that detect tunnelling and DGAs.
//!
//! Correlation groups by exact field values, so a rule cannot ask for "many
//! distinct subdomains of one parent" without a field that names the parent.
//! These helpers derive that field and the name-shape measurements from
//! `QueryName`. They allocate nothing: the registered domain is a suffix of
//! the name, and the rest are counts.
//!
//! The registered domain uses the Mozilla Public Suffix List compiled into the
//! `psl` crate, so it is frozen at build time and refreshed by bumping that
//! dependency (Dependabot proposes the bump).
//! Private-section entries such as `github.io` are honoured, so
//! `user.github.io` is its own registered domain.

use std::borrow::Cow;

use psl::Psl;

/// A query name without its optional root label dot.
fn trimmed(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// The registrable domain: the public suffix plus one label.
///
/// `None` for an empty name, a bare public suffix such as `co.uk`, and names
/// the list does not know, including single labels, IP-literal names and
/// reverse-lookup names under `in-addr.arpa`.
/// The returned slice keeps the case of `name`.
pub(crate) fn registered_domain(name: &str) -> Option<&str> {
    let name = trimmed(name);
    if name.is_empty() {
        return None;
    }
    // The list is lowercase and its lookup is byte-exact. Lowercasing never
    // changes a byte length, so the answer maps back onto the original.
    let lowered: Cow<'_, str> = if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    };
    let domain = psl::domain_str(&lowered)?;
    // `psl` accepts an unlisted final label as a suffix, which would make
    // `localhost.` or `host.local` a registered domain.
    // Only a known suffix is a registered domain.
    if !psl::List
        .suffix(lowered.as_bytes())
        .is_some_and(|suffix| suffix.is_known())
    {
        return None;
    }
    name.get(name.len() - domain.len()..)
}

/// Number of labels, ignoring the root label.
pub(crate) fn label_count(name: &str) -> u64 {
    let name = trimmed(name);
    if name.is_empty() {
        return 0;
    }
    name.split('.').count() as u64
}

/// Byte length of the longest label.
pub(crate) fn longest_label(name: &str) -> u64 {
    trimmed(name)
        .split('.')
        .map(|label| label.len() as u64)
        .max()
        .unwrap_or(0)
}

/// Byte length of the name without the root label dot.
pub(crate) fn name_length(name: &str) -> u64 {
    trimmed(name).len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_domain_is_public_suffix_aware() {
        assert_eq!(registered_domain("a.b.example.com"), Some("example.com"));
        assert_eq!(registered_domain("example.com"), Some("example.com"));
        assert_eq!(
            registered_domain("www.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(
            registered_domain("x.y.example.com.au"),
            Some("example.com.au")
        );
    }

    #[test]
    fn a_bare_suffix_or_unknown_name_has_no_registered_domain() {
        assert_eq!(registered_domain("co.uk"), None);
        assert_eq!(registered_domain("com"), None);
        assert_eq!(registered_domain(""), None);
        assert_eq!(registered_domain("."), None);
        assert_eq!(registered_domain("localhost"), None);
        assert_eq!(registered_domain("printer.local"), None);
    }

    #[test]
    fn private_suffixes_are_honoured() {
        assert_eq!(registered_domain("user.github.io"), Some("user.github.io"));
        assert_eq!(
            registered_domain("a.user.github.io"),
            Some("user.github.io")
        );
    }

    #[test]
    fn the_root_dot_and_case_do_not_change_the_answer() {
        assert_eq!(
            registered_domain("Mail.Example.CO.UK."),
            Some("Example.CO.UK")
        );
        assert_eq!(registered_domain("a.example.com."), Some("example.com"));
    }

    #[test]
    fn name_shape_counts_ignore_the_root_label() {
        assert_eq!(label_count("a.b.example.com"), 4);
        assert_eq!(label_count("a.b.example.com."), 4);
        assert_eq!(label_count("localhost"), 1);
        assert_eq!(label_count(""), 0);
        assert_eq!(label_count("."), 0);
        assert_eq!(longest_label("a.longlabel.com"), 9);
        assert_eq!(longest_label(""), 0);
        assert_eq!(name_length("a.b.com."), 7);
        assert_eq!(name_length(""), 0);
    }
}
