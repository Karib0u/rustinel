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

/// Why a signature that exists does not verify. These are the distinctions
/// Sysmon reports in `SignatureStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFault {
    Expired,
    Revoked,
    /// The digest, chain, or trust policy rejected the signature.
    Invalid,
}

impl SignatureFault {
    fn status(self) -> &'static str {
        match self {
            Self::Expired => "Expired",
            Self::Revoked => "Revoked",
            Self::Invalid => "Invalid",
        }
    }
}

/// The outcome of verifying a file's Authenticode signature. The data shape
/// is platform-neutral so artifact stores and diagnostics compile everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureVerdict {
    /// Verification did not complete, so nothing is known about the file.
    /// This is never evidence that the file is unsigned, and it is not cached.
    Unknown,
    /// The file carries no embedded signature and no catalog lists its hash.
    Unsigned,
    /// A signature or catalog entry exists but does not verify.
    Invalid {
        fault: SignatureFault,
        signer: Option<String>,
    },
    Valid {
        signer: Option<String>,
    },
}

/// Sysmon's `Signed`, `Signature`, and `SignatureStatus` for a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFields {
    pub signed: &'static str,
    pub signature: Option<String>,
    pub status: &'static str,
}

impl SignatureVerdict {
    /// The field values a rule sees, or `None` when verification is unknown
    /// so the fields stay absent instead of reading as unsigned.
    pub fn fields(&self) -> Option<SignatureFields> {
        match self {
            Self::Unknown => None,
            Self::Unsigned => Some(SignatureFields {
                signed: "false",
                signature: None,
                status: "Unavailable",
            }),
            Self::Invalid { fault, signer } => Some(SignatureFields {
                signed: "true",
                signature: signer.clone(),
                status: fault.status(),
            }),
            Self::Valid { signer } => Some(SignatureFields {
                signed: "true",
                signature: signer.clone(),
                status: "Valid",
            }),
        }
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;

    #[test]
    fn unknown_has_no_fields_and_unsigned_does() {
        assert_eq!(SignatureVerdict::Unknown.fields(), None);
        let unsigned = SignatureVerdict::Unsigned.fields().expect("unsigned");
        assert_eq!((unsigned.signed, unsigned.status), ("false", "Unavailable"));
        assert_eq!(unsigned.signature, None);
    }

    #[test]
    fn invalid_keeps_the_signer_and_the_reason() {
        let revoked = SignatureVerdict::Invalid {
            fault: SignatureFault::Revoked,
            signer: Some("Acme".into()),
        }
        .fields()
        .expect("revoked");
        assert_eq!(revoked.signed, "true");
        assert_eq!(revoked.status, "Revoked");
        assert_eq!(revoked.signature.as_deref(), Some("Acme"));
        let valid = SignatureVerdict::Valid { signer: None }
            .fields()
            .expect("valid");
        assert_eq!((valid.signed, valid.status), ("true", "Valid"));
    }
}
