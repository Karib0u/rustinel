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
