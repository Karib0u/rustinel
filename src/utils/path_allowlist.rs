//! Path-prefix matching policies used by detection and active response.
//!
//! Keep the existing policies explicit: YARA and response use directory
//! boundaries, while IOC configuration accepts raw prefixes (including empty
//! prefixes). Response comparisons fold ASCII case on Unix too. Unifying these
//! policies would change which files are scanned or which responses are allowed.

use super::normalize_path_for_comparison;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathAllowlistPolicy {
    ScannerDirectory,
    IocPrefix,
    ResponseDirectory,
}

impl PathAllowlistPolicy {
    pub fn normalize_path(self, path: &str) -> String {
        if self == Self::ResponseDirectory {
            return normalize_path_for_comparison(path);
        }
        #[cfg(windows)]
        {
            path.trim().replace('/', "\\").to_ascii_lowercase()
        }
        #[cfg(not(windows))]
        {
            path.trim().to_string()
        }
    }

    pub fn normalize_prefixes(self, values: &[String]) -> Vec<String> {
        let separator = match self {
            Self::ResponseDirectory if !cfg!(any(target_os = "linux", target_os = "macos")) => '\\',
            _ if cfg!(windows) => '\\',
            _ => '/',
        };
        values
            .iter()
            .filter(|value| self == Self::IocPrefix || !value.trim().is_empty())
            .map(|value| {
                let mut normalized = self.normalize_path(value);
                if self != Self::IocPrefix && !normalized.ends_with(separator) {
                    normalized.push(separator);
                }
                normalized
            })
            .collect()
    }

    pub fn is_match(self, path: &str, normalized_prefixes: &[String]) -> bool {
        if normalized_prefixes.is_empty() {
            return false;
        }
        matches_normalized(&self.normalize_path(path), normalized_prefixes)
    }
}

pub(crate) fn matches_normalized(path: &str, normalized_prefixes: &[String]) -> bool {
    normalized_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}
