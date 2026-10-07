//! Per-directory reporting shared by the Sigma and YARA loaders.
//!
//! A rule set is the managed pack directory plus any number of local
//! directories. Local directories load after the pack, so a local rule wins
//! when it reuses the identifier of a pack rule.

use std::path::{Path, PathBuf};

/// Where a rule directory sits in the load order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDirectoryRole {
    /// The configured `*_rules_path`, normally `rules/current/...`.
    Pack,
    /// An entry of `*_local_rules_paths`, never touched by rules install or update.
    Local,
}

impl RuleDirectoryRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pack => "pack",
            Self::Local => "local",
        }
    }
}

/// What one directory contributed to a loaded rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDirectoryReport {
    pub path: PathBuf,
    pub role: RuleDirectoryRole,
    pub exists: bool,
    /// Rule files read from the directory.
    pub files: usize,
    /// Rules that are active after filtering and collision handling.
    pub rules: usize,
}

impl RuleDirectoryReport {
    pub fn new(path: &Path, role: RuleDirectoryRole) -> Self {
        Self {
            path: path.to_path_buf(),
            role,
            exists: path.is_dir(),
            files: 0,
            rules: 0,
        }
    }

    pub fn summary(&self) -> String {
        let state = if self.exists { "" } else { ", missing" };
        format!(
            "{} ({}): {} rules from {} files{}",
            self.path.display(),
            self.role.as_str(),
            self.rules,
            self.files,
            state
        )
    }
}

/// A local rule that replaced a rule with the same identifier from an earlier
/// directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCollision {
    pub rule_id: String,
    /// Source of the rule that was dropped.
    pub overridden: String,
    /// Source of the rule that stayed active.
    pub winner: String,
}

impl RuleCollision {
    pub fn summary(&self) -> String {
        format!(
            "rule {} from {} is replaced by the local rule in {}",
            self.rule_id, self.overridden, self.winner
        )
    }
}
