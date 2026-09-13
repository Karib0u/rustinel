use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct AttackFields {
    pub framework: Option<String>,
    pub tactic_ids: Vec<String>,
    pub tactic_names: Vec<String>,
    pub tactic_references: Vec<String>,
    pub technique_ids: Vec<String>,
    pub technique_references: Vec<String>,
    pub subtechnique_ids: Vec<String>,
    pub subtechnique_references: Vec<String>,
}

pub(super) fn attack_fields(tags: &[String]) -> AttackFields {
    let mut tactics = BTreeSet::new();
    let mut techniques = BTreeSet::new();
    let mut subtechniques = BTreeSet::new();

    for tag in tags {
        let Some(value) = tag.strip_prefix("attack.") else {
            continue;
        };
        if let Some((id, subtechnique)) = attack_technique(value) {
            techniques.insert(id);
            if let Some(subtechnique) = subtechnique {
                subtechniques.insert(subtechnique);
            }
        } else if let Some(tactic) = attack_tactic(value) {
            tactics.insert(tactic);
        }
    }

    let mapped = !tactics.is_empty() || !techniques.is_empty() || !subtechniques.is_empty();
    AttackFields {
        framework: mapped.then(|| "MITRE ATT&CK".to_string()),
        tactic_ids: tactics.iter().map(|tactic| tactic.0.to_string()).collect(),
        tactic_names: tactics.iter().map(|tactic| tactic.1.to_string()).collect(),
        tactic_references: tactics
            .iter()
            .map(|tactic| format!("https://attack.mitre.org/tactics/{}/", tactic.0))
            .collect(),
        technique_references: techniques
            .iter()
            .map(|id| format!("https://attack.mitre.org/techniques/{id}/"))
            .collect(),
        technique_ids: techniques.into_iter().collect(),
        subtechnique_references: subtechniques
            .iter()
            .map(|id| {
                let (parent, child) = id.split_once('.').expect("validated subtechnique id");
                format!("https://attack.mitre.org/techniques/{parent}/{child}/")
            })
            .collect(),
        subtechnique_ids: subtechniques.into_iter().collect(),
    }
}

fn attack_technique(value: &str) -> Option<(String, Option<String>)> {
    let id = value.strip_prefix('t')?;
    let mut parts = id.split('.');
    let parent = parts.next()?;
    if parent.len() != 4 || !parent.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let parent = format!("T{parent}");
    match (parts.next(), parts.next()) {
        (None, None) => Some((parent, None)),
        (Some(child), None)
            if child.len() == 3 && child.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Some((parent.clone(), Some(format!("{parent}.{child}"))))
        }
        _ => None,
    }
}

fn attack_tactic(value: &str) -> Option<(&'static str, &'static str)> {
    match value {
        "reconnaissance" => Some(("TA0043", "Reconnaissance")),
        "resource_development" => Some(("TA0042", "Resource Development")),
        "initial_access" => Some(("TA0001", "Initial Access")),
        "execution" => Some(("TA0002", "Execution")),
        "persistence" => Some(("TA0003", "Persistence")),
        "privilege_escalation" => Some(("TA0004", "Privilege Escalation")),
        "defense_evasion" => Some(("TA0005", "Defense Evasion")),
        "credential_access" => Some(("TA0006", "Credential Access")),
        "discovery" => Some(("TA0007", "Discovery")),
        "lateral_movement" => Some(("TA0008", "Lateral Movement")),
        "collection" => Some(("TA0009", "Collection")),
        "command_and_control" => Some(("TA0011", "Command and Control")),
        "exfiltration" => Some(("TA0010", "Exfiltration")),
        "impact" => Some(("TA0040", "Impact")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma_attack_tags_map_to_ecs_ids_and_references() {
        let fields = attack_fields(&[
            "attack.execution".to_string(),
            "attack.defense_evasion".to_string(),
            "attack.t1059.001".to_string(),
            "attack.t1059".to_string(),
            "custom.tag".to_string(),
        ]);

        assert_eq!(fields.framework.as_deref(), Some("MITRE ATT&CK"));
        assert_eq!(fields.tactic_ids, ["TA0002", "TA0005"]);
        assert_eq!(fields.tactic_names, ["Execution", "Defense Evasion"]);
        assert_eq!(fields.technique_ids, ["T1059"]);
        assert_eq!(fields.subtechnique_ids, ["T1059.001"]);
        assert_eq!(
            fields.subtechnique_references,
            ["https://attack.mitre.org/techniques/T1059/001/"]
        );
    }

    #[test]
    fn malformed_attack_tags_do_not_create_threat_fields() {
        let fields = attack_fields(&[
            "attack.t123".to_string(),
            "attack.t1059.01".to_string(),
            "attack.not-a-tactic".to_string(),
            "ATTACK.EXECUTION".to_string(),
            "attack.T1059".to_string(),
            "attack.initial-access".to_string(),
        ]);

        assert!(fields.framework.is_none());
        assert!(fields.technique_ids.is_empty());
        assert!(fields.subtechnique_ids.is_empty());
    }
}
