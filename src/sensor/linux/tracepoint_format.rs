//! Runtime tracepoint-layout discovery.
//!
//! Tracepoint records are not a kernel ABI. Every offset consumed by the eBPF
//! programs is resolved from tracefs and patched into the object before load.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

const TRACEFS_ROOTS: [&str; 2] = [
    "/sys/kernel/tracing/events",
    "/sys/kernel/debug/tracing/events",
];

static LAYOUTS: OnceLock<TracepointLayouts> = OnceLock::new();

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessTracepointOffsets {
    pub exec_filename: u32,
    pub exec_pid: u32,
    pub exec_old_pid: u32,
    pub fork_parent_pid: u32,
    pub fork_child_pid: u32,
    pub clone_flags: u32,
    pub clone3_args: u32,
    pub execve_argv: u32,
    pub execveat_argv: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct NetworkTracepointOffsets {
    pub connect_fd: u32,
    pub connect_addr: u32,
    pub connect_ret: u32,
    pub socket_family: u32,
    pub socket_type: u32,
    pub socket_ret: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct DnsTracepointOffsets {
    pub sendto_fd: u32,
    pub sendto_buf: u32,
    pub sendto_len: u32,
    pub sendto_addr: u32,
    pub sendmsg_fd: u32,
    pub sendmsg_msg: u32,
    pub sendmmsg_fd: u32,
    pub sendmmsg_msgvec: u32,
    pub sendmmsg_vlen: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileTracepointOffsets {
    pub openat_dfd: u32,
    pub openat_path: u32,
    pub openat_flags: u32,
    pub openat_ret: u32,
    pub open_path: u32,
    pub open_flags: u32,
    pub open_ret: u32,
    pub creat_path: u32,
    pub creat_ret: u32,
    pub openat2_dfd: u32,
    pub openat2_path: u32,
    pub openat2_how: u32,
    pub openat2_ret: u32,
    pub unlinkat_dfd: u32,
    pub unlinkat_path: u32,
    pub unlinkat_ret: u32,
    pub unlink_path: u32,
    pub unlink_ret: u32,
    pub renameat_old_dfd: u32,
    pub renameat_old_path: u32,
    pub renameat_new_dfd: u32,
    pub renameat_new_path: u32,
    pub renameat_ret: u32,
    pub renameat2_old_dfd: u32,
    pub renameat2_old_path: u32,
    pub renameat2_new_dfd: u32,
    pub renameat2_new_path: u32,
    pub renameat2_ret: u32,
    pub rename_old_path: u32,
    pub rename_new_path: u32,
    pub rename_ret: u32,
    pub mkdir_path: u32,
    pub mkdir_ret: u32,
    pub mkdirat_dfd: u32,
    pub mkdirat_path: u32,
    pub mkdirat_ret: u32,
    pub rmdir_path: u32,
    pub rmdir_ret: u32,
    pub close_fd: u32,
    pub dup2_old_fd: u32,
    pub dup2_new_fd: u32,
    pub dup3_old_fd: u32,
    pub dup3_new_fd: u32,
}

unsafe impl aya::Pod for ProcessTracepointOffsets {}
unsafe impl aya::Pod for NetworkTracepointOffsets {}
unsafe impl aya::Pod for DnsTracepointOffsets {}
unsafe impl aya::Pod for FileTracepointOffsets {}

#[derive(Debug, Default)]
pub(super) struct TracepointLayouts {
    pub process: ProcessTracepointOffsets,
    pub network: NetworkTracepointOffsets,
    pub dns: DnsTracepointOffsets,
    pub file: FileTracepointOffsets,
    unavailable: HashMap<&'static str, String>,
}

impl TracepointLayouts {
    pub(super) fn probe() -> &'static Self {
        LAYOUTS.get_or_init(|| {
            let mut layouts = Self::default();
            layouts.probe_process();
            layouts.probe_network();
            layouts.probe_dns();
            layouts.probe_file();
            layouts
        })
    }

    pub(super) fn current_unavailable_reason(program: &str) -> Option<&'static str> {
        LAYOUTS
            .get()
            .and_then(|layouts| layouts.unavailable_reason(program))
    }

    pub(super) fn unavailable_reason(&self, program: &str) -> Option<&str> {
        self.unavailable.get(program).map(String::as_str)
    }

    fn fields(
        &mut self,
        program: &'static str,
        category: &str,
        name: &str,
        specs: &[FieldSpec<'_>],
    ) -> Option<Vec<u32>> {
        match resolve_fields(category, name, specs) {
            Ok(offsets) => Some(offsets),
            Err(err) => {
                self.unavailable
                    .insert(program, format!("{category}/{name}: {err:#}"));
                None
            }
        }
    }

    fn probe_process(&mut self) {
        if let Some(v) = self.fields(
            "handle_exec",
            "sched",
            "sched_process_exec",
            &[
                FieldSpec::one("filename", 4),
                FieldSpec::one("pid", 4),
                FieldSpec::one("old_pid", 4),
            ],
        ) {
            self.process.exec_filename = v[0];
            self.process.exec_pid = v[1];
            self.process.exec_old_pid = v[2];
        }
        if let Some(v) = self.fields(
            "handle_fork",
            "sched",
            "sched_process_fork",
            &[
                FieldSpec::one("parent_pid", 4),
                FieldSpec::one("child_pid", 4),
            ],
        ) {
            self.process.fork_parent_pid = v[0];
            self.process.fork_child_pid = v[1];
        }
        if let Some(v) = self.fields(
            "handle_clone",
            "syscalls",
            "sys_enter_clone",
            &[FieldSpec::either(&["clone_flags", "flags"], 8)],
        ) {
            self.process.clone_flags = v[0];
        }
        if let Some(v) = self.fields(
            "handle_clone3",
            "syscalls",
            "sys_enter_clone3",
            &[FieldSpec::either(&["uargs", "cl_args"], 8)],
        ) {
            self.process.clone3_args = v[0];
        }
        if let Some(v) = self.fields(
            "handle_execve",
            "syscalls",
            "sys_enter_execve",
            &[FieldSpec::one("argv", 8)],
        ) {
            self.process.execve_argv = v[0];
        }
        if let Some(v) = self.fields(
            "handle_execveat",
            "syscalls",
            "sys_enter_execveat",
            &[FieldSpec::one("argv", 8)],
        ) {
            self.process.execveat_argv = v[0];
        }
    }

    fn probe_network(&mut self) {
        if let Some(v) = self.fields(
            "handle_connect",
            "syscalls",
            "sys_enter_connect",
            &[FieldSpec::one("fd", 8), FieldSpec::one("uservaddr", 8)],
        ) {
            self.network.connect_fd = v[0];
            self.network.connect_addr = v[1];
        }
        if let Some(v) = self.fields(
            "handle_connect_exit",
            "syscalls",
            "sys_exit_connect",
            &[FieldSpec::one("ret", 8)],
        ) {
            self.network.connect_ret = v[0];
        }
        if let Some(v) = self.fields(
            "handle_socket",
            "syscalls",
            "sys_enter_socket",
            &[FieldSpec::one("family", 8), FieldSpec::one("type", 8)],
        ) {
            self.network.socket_family = v[0];
            self.network.socket_type = v[1];
        }
        if let Some(v) = self.fields(
            "handle_socket_exit",
            "syscalls",
            "sys_exit_socket",
            &[FieldSpec::one("ret", 8)],
        ) {
            self.network.socket_ret = v[0];
        }
    }

    fn probe_dns(&mut self) {
        if let Some(v) = self.fields(
            "handle_sendto",
            "syscalls",
            "sys_enter_sendto",
            &[
                FieldSpec::one("fd", 8),
                FieldSpec::either(&["buff", "buf"], 8),
                FieldSpec::one("len", 8),
                FieldSpec::one("addr", 8),
            ],
        ) {
            self.dns.sendto_fd = v[0];
            self.dns.sendto_buf = v[1];
            self.dns.sendto_len = v[2];
            self.dns.sendto_addr = v[3];
        }
        if let Some(v) = self.fields(
            "handle_sendmsg",
            "syscalls",
            "sys_enter_sendmsg",
            &[FieldSpec::one("fd", 8), FieldSpec::one("msg", 8)],
        ) {
            self.dns.sendmsg_fd = v[0];
            self.dns.sendmsg_msg = v[1];
        }
        if let Some(v) = self.fields(
            "handle_sendmmsg",
            "syscalls",
            "sys_enter_sendmmsg",
            &[
                FieldSpec::one("fd", 8),
                FieldSpec::either(&["msg", "mmsg"], 8),
                FieldSpec::one("vlen", 8),
            ],
        ) {
            self.dns.sendmmsg_fd = v[0];
            self.dns.sendmmsg_msgvec = v[1];
            self.dns.sendmmsg_vlen = v[2];
        }
    }

    #[allow(clippy::too_many_lines)]
    fn probe_file(&mut self) {
        macro_rules! fields {
            ($program:literal, $name:literal, [$($field:expr),+ $(,)?]) => { self.fields($program, "syscalls", $name, &[$($field),+]) };
        }
        if let Some(v) = fields!(
            "handle_openat",
            "sys_enter_openat",
            [
                FieldSpec::one("dfd", 8),
                FieldSpec::one("filename", 8),
                FieldSpec::one("flags", 8)
            ]
        ) {
            self.file.openat_dfd = v[0];
            self.file.openat_path = v[1];
            self.file.openat_flags = v[2];
        }
        if let Some(v) = fields!(
            "handle_openat_exit",
            "sys_exit_openat",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.openat_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_open",
            "sys_enter_open",
            [FieldSpec::one("filename", 8), FieldSpec::one("flags", 8)]
        ) {
            self.file.open_path = v[0];
            self.file.open_flags = v[1];
        }
        if let Some(v) = fields!(
            "handle_open_exit",
            "sys_exit_open",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.open_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_creat",
            "sys_enter_creat",
            [FieldSpec::either(&["pathname", "filename"], 8)]
        ) {
            self.file.creat_path = v[0];
        }
        if let Some(v) = fields!(
            "handle_creat_exit",
            "sys_exit_creat",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.creat_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_openat2",
            "sys_enter_openat2",
            [
                FieldSpec::one("dfd", 8),
                FieldSpec::one("filename", 8),
                FieldSpec::one("how", 8)
            ]
        ) {
            self.file.openat2_dfd = v[0];
            self.file.openat2_path = v[1];
            self.file.openat2_how = v[2];
        }
        if let Some(v) = fields!(
            "handle_openat2_exit",
            "sys_exit_openat2",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.openat2_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_unlinkat",
            "sys_enter_unlinkat",
            [FieldSpec::one("dfd", 8), FieldSpec::one("pathname", 8)]
        ) {
            self.file.unlinkat_dfd = v[0];
            self.file.unlinkat_path = v[1];
        }
        if let Some(v) = fields!(
            "handle_unlinkat_exit",
            "sys_exit_unlinkat",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.unlinkat_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_unlink",
            "sys_enter_unlink",
            [FieldSpec::one("pathname", 8)]
        ) {
            self.file.unlink_path = v[0];
        }
        if let Some(v) = fields!(
            "handle_unlink_exit",
            "sys_exit_unlink",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.unlink_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_renameat",
            "sys_enter_renameat",
            [
                FieldSpec::one("olddfd", 8),
                FieldSpec::one("oldname", 8),
                FieldSpec::one("newdfd", 8),
                FieldSpec::one("newname", 8)
            ]
        ) {
            self.file.renameat_old_dfd = v[0];
            self.file.renameat_old_path = v[1];
            self.file.renameat_new_dfd = v[2];
            self.file.renameat_new_path = v[3];
        }
        if let Some(v) = fields!(
            "handle_renameat_exit",
            "sys_exit_renameat",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.renameat_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_renameat2",
            "sys_enter_renameat2",
            [
                FieldSpec::one("olddfd", 8),
                FieldSpec::one("oldname", 8),
                FieldSpec::one("newdfd", 8),
                FieldSpec::one("newname", 8)
            ]
        ) {
            self.file.renameat2_old_dfd = v[0];
            self.file.renameat2_old_path = v[1];
            self.file.renameat2_new_dfd = v[2];
            self.file.renameat2_new_path = v[3];
        }
        if let Some(v) = fields!(
            "handle_renameat2_exit",
            "sys_exit_renameat2",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.renameat2_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_rename",
            "sys_enter_rename",
            [FieldSpec::one("oldname", 8), FieldSpec::one("newname", 8)]
        ) {
            self.file.rename_old_path = v[0];
            self.file.rename_new_path = v[1];
        }
        if let Some(v) = fields!(
            "handle_rename_exit",
            "sys_exit_rename",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.rename_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_mkdir",
            "sys_enter_mkdir",
            [FieldSpec::one("pathname", 8)]
        ) {
            self.file.mkdir_path = v[0];
        }
        if let Some(v) = fields!(
            "handle_mkdir_exit",
            "sys_exit_mkdir",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.mkdir_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_mkdirat",
            "sys_enter_mkdirat",
            [FieldSpec::one("dfd", 8), FieldSpec::one("pathname", 8)]
        ) {
            self.file.mkdirat_dfd = v[0];
            self.file.mkdirat_path = v[1];
        }
        if let Some(v) = fields!(
            "handle_mkdirat_exit",
            "sys_exit_mkdirat",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.mkdirat_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_rmdir",
            "sys_enter_rmdir",
            [FieldSpec::one("pathname", 8)]
        ) {
            self.file.rmdir_path = v[0];
        }
        if let Some(v) = fields!(
            "handle_rmdir_exit",
            "sys_exit_rmdir",
            [FieldSpec::one("ret", 8)]
        ) {
            self.file.rmdir_ret = v[0];
        }
        if let Some(v) = fields!(
            "handle_file_close",
            "sys_enter_close",
            [FieldSpec::one("fd", 8)]
        ) {
            self.file.close_fd = v[0];
        }
        if let Some(v) = fields!(
            "handle_file_dup2",
            "sys_enter_dup2",
            [FieldSpec::one("oldfd", 8), FieldSpec::one("newfd", 8)]
        ) {
            self.file.dup2_old_fd = v[0];
            self.file.dup2_new_fd = v[1];
        }
        if let Some(v) = fields!(
            "handle_file_dup3",
            "sys_enter_dup3",
            [FieldSpec::one("oldfd", 8), FieldSpec::one("newfd", 8)]
        ) {
            self.file.dup3_old_fd = v[0];
            self.file.dup3_new_fd = v[1];
        }
    }
}

#[derive(Clone, Copy)]
struct FieldSpec<'a> {
    name: &'a str,
    alternate: Option<&'a str>,
    size: u32,
}

impl<'a> FieldSpec<'a> {
    const fn one(name: &'a str, size: u32) -> Self {
        Self {
            name,
            alternate: None,
            size,
        }
    }
    const fn either(names: &'a [&'a str], size: u32) -> Self {
        Self {
            name: names[0],
            alternate: Some(names[1]),
            size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TracepointField {
    offset: u32,
    size: u32,
}

pub(super) fn tracepoint_exists(category: &str, name: &str) -> bool {
    find_file(category, name, "id").is_some()
}

fn find_file(category: &str, name: &str, file: &str) -> Option<PathBuf> {
    TRACEFS_ROOTS
        .iter()
        .map(Path::new)
        .map(|root| root.join(category).join(name).join(file))
        .find(|path| path.exists())
}

fn read_format(category: &str, name: &str) -> Result<String> {
    let path = find_file(category, name, "format").with_context(|| "tracepoint is unavailable")?;
    std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read tracepoint format from {}", path.display()))
}

fn resolve_fields(category: &str, name: &str, specs: &[FieldSpec<'_>]) -> Result<Vec<u32>> {
    let fields = parse_fields(&read_format(category, name)?)?;
    specs
        .iter()
        .map(|spec| required_spec(&fields, spec))
        .collect()
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
            bail!("tracepoint field has no name: {line}")
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
        fields.insert(
            name.to_string(),
            TracepointField {
                offset: offset.with_context(|| format!("field {name} has no offset"))?,
                size: size.with_context(|| format!("field {name} has no size"))?,
            },
        );
    }
    if fields.is_empty() {
        bail!("tracepoint format contains no fields");
    }
    Ok(fields)
}

fn required_one_of(
    fields: &HashMap<String, TracepointField>,
    names: &[&str],
    size: u32,
) -> Result<u32> {
    for name in names {
        if let Some(field) = fields.get(*name) {
            if field.size != size {
                bail!(
                    "tracepoint field {name} has unsupported size {}, expected {size}",
                    field.size
                );
            }
            return Ok(field.offset);
        }
    }
    bail!("required tracepoint field {} is absent", names.join(" or "))
}

fn required_spec(fields: &HashMap<String, TracepointField>, spec: &FieldSpec<'_>) -> Result<u32> {
    match spec.alternate {
        Some(alternate) => required_one_of(fields, &[spec.name, alternate], spec.size),
        None => required_one_of(fields, &[spec.name], spec.size),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_and_data_loc_fields_by_name() {
        let format = r#"
field:char parent_comm[16]; offset:8; size:16; signed:1;
field:pid_t parent_pid; offset:24; size:4; signed:1;
field:__data_loc char[] child_comm; offset:28; size:4; signed:0;
field:pid_t child_pid; offset:32; size:4; signed:1;
"#;
        let fields = parse_fields(format).unwrap();
        assert_eq!(required_one_of(&fields, &["parent_pid"], 4).unwrap(), 24);
        assert_eq!(required_one_of(&fields, &["child_pid"], 4).unwrap(), 32);
    }

    #[test]
    fn accepts_field_aliases() {
        let fields =
            parse_fields("field:unsigned long flags; offset:16; size:8; signed:0;").unwrap();
        assert_eq!(
            required_one_of(&fields, &["clone_flags", "flags"], 8).unwrap(),
            16
        );
    }

    #[test]
    fn rejects_wrong_field_size() {
        let fields = parse_fields("field:pid_t pid; offset:12; size:8; signed:1;").unwrap();
        assert!(required_one_of(&fields, &["pid"], 4)
            .unwrap_err()
            .to_string()
            .contains("unsupported size 8"));
    }
}
