use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

const TRACEFS_ROOTS: [&str; 2] = [
    "/sys/kernel/tracing/events",
    "/sys/kernel/debug/tracing/events",
];

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessTracepointOffsets {
    pub exec_filename: u32,
    pub exec_pid: u32,
    pub exec_old_pid: u32,
    pub fork_parent_pid: u32,
    pub fork_child_pid: u32,
    pub clone_flags: u32,
    pub clone3_args: u32,
}

unsafe impl aya::Pod for ProcessTracepointOffsets {}

impl ProcessTracepointOffsets {
    pub(super) fn load() -> Result<Self> {
        let exec = read_format("sched", "sched_process_exec")?;
        let fork = read_format("sched", "sched_process_fork")?;
        let clone = read_format("syscalls", "sys_enter_clone")?;
        let clone3 = find_format("syscalls", "sys_enter_clone3")
            .map(std::fs::read_to_string)
            .transpose()
            .context("failed to read syscalls/sys_enter_clone3 format")?;

        Self::parse(&exec, &fork, &clone, clone3.as_deref())
    }

    fn parse(exec: &str, fork: &str, clone: &str, clone3: Option<&str>) -> Result<Self> {
        let exec = parse_fields(exec)?;
        let fork = parse_fields(fork)?;
        let clone = parse_fields(clone)?;
        let clone3 = clone3.map(parse_fields).transpose()?;

        Ok(Self {
            exec_filename: required_offset(&exec, "filename", 4)?,
            exec_pid: required_offset(&exec, "pid", 4)?,
            exec_old_pid: required_offset(&exec, "old_pid", 4)?,
            fork_parent_pid: required_offset(&fork, "parent_pid", 4)?,
            fork_child_pid: required_offset(&fork, "child_pid", 4)?,
            clone_flags: required_one_of(&clone, &["clone_flags", "flags"], 8)?,
            clone3_args: match clone3 {
                Some(fields) => required_one_of(&fields, &["uargs", "cl_args"], 8)?,
                None => 0,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TracepointField {
    offset: u32,
    size: u32,
}

fn find_format(category: &str, name: &str) -> Option<PathBuf> {
    TRACEFS_ROOTS
        .iter()
        .map(Path::new)
        .map(|root| root.join(category).join(name).join("format"))
        .find(|path| path.exists())
}

fn read_format(category: &str, name: &str) -> Result<String> {
    let path = find_format(category, name)
        .with_context(|| format!("tracepoint {category}/{name} is unavailable"))?;
    std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read tracepoint format from {}", path.display()))
}

fn parse_fields(format: &str) -> Result<HashMap<String, TracepointField>> {
    let mut fields = HashMap::new();

    for line in format.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("field:") else {
            continue;
        };
        let mut parts = rest.split(';');
        let declaration = parts.next().unwrap_or_default().trim();
        let Some(raw_name) = declaration.split_whitespace().last() else {
            bail!("tracepoint field has no name: {line}");
        };
        let name = raw_name
            .trim_start_matches('*')
            .split('[')
            .next()
            .unwrap_or_default();
        if name.is_empty() {
            bail!("tracepoint field has an unsupported declaration: {line}");
        }

        let mut offset = None;
        let mut size = None;
        for part in parts {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("offset:") {
                offset = Some(
                    value
                        .trim()
                        .parse::<u32>()
                        .with_context(|| format!("invalid offset for tracepoint field {name}"))?,
                );
            } else if let Some(value) = part.strip_prefix("size:") {
                size = Some(
                    value
                        .trim()
                        .parse::<u32>()
                        .with_context(|| format!("invalid size for tracepoint field {name}"))?,
                );
            }
        }

        let field = TracepointField {
            offset: offset.with_context(|| format!("field {name} has no offset"))?,
            size: size.with_context(|| format!("field {name} has no size"))?,
        };
        fields.insert(name.to_string(), field);
    }

    if fields.is_empty() {
        bail!("tracepoint format contains no fields");
    }
    Ok(fields)
}

fn required_offset(
    fields: &HashMap<String, TracepointField>,
    name: &str,
    expected_size: u32,
) -> Result<u32> {
    let field = fields
        .get(name)
        .with_context(|| format!("required tracepoint field {name} is absent"))?;
    if field.size != expected_size {
        bail!(
            "tracepoint field {name} has unsupported size {}, expected {expected_size}",
            field.size
        );
    }
    Ok(field.offset)
}

fn required_one_of(
    fields: &HashMap<String, TracepointField>,
    names: &[&str],
    expected_size: u32,
) -> Result<u32> {
    for name in names {
        if fields.contains_key(*name) {
            return required_offset(fields, name, expected_size);
        }
    }
    bail!("required tracepoint field {} is absent", names.join(" or "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXEC: &str = r#"
field:unsigned short common_type; offset:0; size:2; signed:0;
field:__data_loc char[] filename; offset:8; size:4; signed:0;
field:pid_t pid; offset:12; size:4; signed:1;
field:pid_t old_pid; offset:16; size:4; signed:1;
"#;

    const CLONE: &str = r#"
field:int __syscall_nr; offset:8; size:4; signed:1;
field:unsigned long clone_flags; offset:16; size:8; signed:0;
"#;

    const CLONE3: &str = r#"
field:struct clone_args * uargs; offset:16; size:8; signed:0;
"#;

    #[test]
    fn parses_data_loc_fork_layout() {
        let fork = r#"
field:__data_loc char[] parent_comm; offset:8; size:4; signed:0;
field:pid_t parent_pid; offset:12; size:4; signed:1;
field:__data_loc char[] child_comm; offset:16; size:4; signed:0;
field:pid_t child_pid; offset:20; size:4; signed:1;
"#;
        let offsets = ProcessTracepointOffsets::parse(EXEC, fork, CLONE, Some(CLONE3)).unwrap();
        assert_eq!(offsets.fork_parent_pid, 12);
        assert_eq!(offsets.fork_child_pid, 20);
    }

    #[test]
    fn parses_fixed_array_fork_layout() {
        let fork = r#"
field:char parent_comm[16]; offset:8; size:16; signed:1;
field:pid_t parent_pid; offset:24; size:4; signed:1;
field:char child_comm[16]; offset:28; size:16; signed:1;
field:pid_t child_pid; offset:44; size:4; signed:1;
"#;
        let offsets = ProcessTracepointOffsets::parse(EXEC, fork, CLONE, None).unwrap();
        assert_eq!(offsets.fork_parent_pid, 24);
        assert_eq!(offsets.fork_child_pid, 44);
        assert_eq!(offsets.clone3_args, 0);
    }

    #[test]
    fn rejects_wrong_field_size() {
        let fork = r#"
field:pid_t parent_pid; offset:12; size:8; signed:1;
field:pid_t child_pid; offset:20; size:4; signed:1;
"#;
        let err = ProcessTracepointOffsets::parse(EXEC, fork, CLONE, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent_pid has unsupported size 8"));
    }
}
