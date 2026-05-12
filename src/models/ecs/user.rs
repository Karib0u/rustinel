use super::alert::EcsAlert;

pub(super) fn is_sid(value: &str) -> bool {
    value.starts_with("S-1-")
}

pub(super) fn split_user(value: &str) -> (Option<String>, Option<String>, Option<String>) {
    if is_sid(value) {
        return (None, Some(value.to_string()), None);
    }

    if let Some((domain, name)) = value.split_once('\\') {
        return (Some(name.to_string()), None, Some(domain.to_string()));
    }

    (Some(value.to_string()), None, None)
}

pub(super) fn apply_user_fields(ecs: &mut EcsAlert, user: Option<&str>) {
    let value = match user {
        Some(value) if !value.is_empty() => value,
        _ => return,
    };

    let (name, id, domain) = split_user(value);

    if ecs.user_id.is_none() {
        ecs.user_id = id;
    }

    if ecs.user_domain.is_none() {
        ecs.user_domain = domain;
    }

    if let Some(name) = name {
        if ecs.user_name.is_none() || ecs.user_name.as_deref().map(is_sid).unwrap_or(false) {
            ecs.user_name = Some(name);
        }
    }
}
