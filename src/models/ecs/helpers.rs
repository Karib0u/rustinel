pub(super) fn parse_u64(value: &Option<String>) -> Option<u64> {
    value.as_ref().and_then(|v| v.trim().parse::<u64>().ok())
}

pub(super) fn parse_u16(value: &Option<String>) -> Option<u16> {
    value.as_ref().and_then(|v| v.trim().parse::<u16>().ok())
}

pub(super) fn parse_bool(value: &Option<String>) -> Option<bool> {
    let normalized = value.as_ref()?.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "true" | "signed" | "valid" | "yes" => Some(true),
        "false" | "unsigned" | "invalid" | "no" => Some(false),
        _ => None,
    }
}

pub(super) fn basename(path: &str) -> Option<String> {
    let trimmed = path.trim_matches('"');
    let name = trimmed.rsplit(['\\', '/']).next().unwrap_or("");
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

pub(super) fn file_extension_from_path(path: &str) -> Option<String> {
    let name = basename(path)?;
    let (_, ext) = name.rsplit_once('.')?;
    if ext.is_empty() {
        None
    } else {
        Some(ext.to_string())
    }
}

/// Digests split out of a Sysmon `Hashes` value, lowercased for ECS.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct SysmonDigests {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub imphash: Option<String>,
}

impl SysmonDigests {
    pub(super) fn parse(hashes: Option<&str>) -> Self {
        let mut digests = Self::default();
        for part in hashes.unwrap_or_default().split(',') {
            let Some((algorithm, value)) = part.split_once('=') else {
                continue;
            };
            let value = Some(value.trim().to_ascii_lowercase()).filter(|value| !value.is_empty());
            match algorithm.trim().to_ascii_uppercase().as_str() {
                "MD5" => digests.md5 = value,
                "SHA1" => digests.sha1 = value,
                "SHA256" => digests.sha256 = value,
                "IMPHASH" => digests.imphash = value,
                _ => {}
            }
        }
        digests
    }
}
