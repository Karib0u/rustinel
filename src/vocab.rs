//! Shared vocabulary: the leaf module every other module may depend on.
//!
//! It imports nothing from the rest of the crate.
//! Types live here when more than one layer needs them and none of those layers should own them.

use serde::{Deserialize, Serialize};

/// `tracing` target for operator-facing console output.
pub const TARGET_CONSOLE: &str = "console";

/// Platform that produced the raw sensor event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
}

impl Platform {
    /// The lowercase platform name, matching how it is serialized.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOS => "macos",
        }
    }
}

/// High-level action emitted by a sensor event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorAction {
    Start,
    Stop,
    /// Internal process lineage update. It is consumed before canonical events.
    Fork,
    Create,
    Delete,
    Modify,
    Rename,
    Connect,
    Disconnect,
    Accept,
    Query,
    Set,
    Load,
    Execute,
    Register,
    /// A subject asked for, or exercised, access to a securable object.
    Access,
}

/// Stable process identity used to avoid PID reuse collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessStartKey {
    pub pid: u32,
    /// Platform-native process start timestamp paired with `pid`.
    pub start_time: u64,
}

/// Windows version-resource metadata. The data shape is platform-neutral so
/// artifact stores and diagnostics compile on every supported target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeMetadata {
    /// Original filename declared by the version resource.
    pub original_filename: Option<String>,
    /// Product name declared by the version resource.
    pub product: Option<String>,
    /// File description declared by the version resource.
    pub description: Option<String>,
    /// Company name declared by the version resource.
    pub company: Option<String>,
    /// File version declared by the version resource.
    pub file_version: Option<String>,
}
