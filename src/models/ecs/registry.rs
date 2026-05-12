pub(super) fn split_registry_path(
    path: &str,
    event_type: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut parts = path.split('\\');
    let hive = parts.next().map(|value| value.to_string());
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return (hive, None, None);
    }

    let is_value = event_type
        .map(|value| value.to_ascii_lowercase().contains("value"))
        .unwrap_or(false);

    if is_value {
        let value = rest.last().unwrap().to_string();
        let key = rest[..rest.len() - 1].join("\\");
        let key = if key.is_empty() { None } else { Some(key) };
        (hive, key, Some(value))
    } else {
        let key = rest.join("\\");
        let key = if key.is_empty() { None } else { Some(key) };
        (hive, key, None)
    }
}
