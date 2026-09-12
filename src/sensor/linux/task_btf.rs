//! Resolve bounded probe-read plans from runtime BTF, without compiled layouts.
//! Encoding reference: https://docs.kernel.org/bpf/btf.html

use super::events::task_identity_abi::*;
use anyhow::{anyhow, bail, ensure, Context, Result};

pub const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
pub const FIELD_NAMES: [&str; FIELD_COUNT] = [
    "start_boottime",
    "euid",
    "egid",
    "mount_namespace",
    "pid_namespace",
    "network_namespace",
    "session_id",
    "tty_major",
    "tty_minor",
    "tty_index",
];

unsafe impl aya::Pod for ReadPlan {}

pub struct TaskPlans {
    pub plans: [ReadPlan; FIELD_COUNT],
    pub warnings: Vec<(String, String)>,
}

impl TaskPlans {
    pub fn load() -> Self {
        Self::resolve(
            std::fs::read(BTF_PATH)
                .context("reading kernel BTF")
                .and_then(|bytes| Btf::parse(&bytes)),
        )
    }

    fn resolve(btf: Result<Btf>) -> Self {
        let mut result = Self {
            plans: [ReadPlan::default(); FIELD_COUNT],
            warnings: Vec::new(),
        };
        for (index, name) in FIELD_NAMES.iter().enumerate() {
            let plan = match &btf {
                Ok(btf) => btf.plan(index),
                Err(error) => Err(anyhow!("{error:#}")),
            };
            match plan {
                Ok(plan) => result.plans[index] = plan,
                Err(error) => result
                    .warnings
                    .push((format!("linux_task_{name}"), format!("{error:#}"))),
            }
        }
        result
    }
}

#[derive(Debug)]
struct Member {
    name: String,
    ty: u32,
    bits: u32,
    bitfield: bool,
}

#[derive(Debug, Default)]
struct Type {
    name: String,
    kind: u32,
    size_type: u32,
    members: Vec<Member>,
    array: Option<(u32, u32)>,
    int_encoding: u32,
}

struct Btf {
    types: Vec<Type>,
}

fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .context("truncated BTF word")?;
    Ok(u32::from_le_bytes(value.try_into()?))
}

impl Btf {
    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.get(..4) == Some(&[0x9f, 0xeb, 1, 0]),
            "unsupported BTF header (expected little-endian v1)"
        );
        let header = word(bytes, 4)? as usize;
        ensure!(
            header >= 24 && header <= bytes.len(),
            "invalid BTF header length"
        );
        let section = |offset, length| -> Result<&[u8]> {
            let start = header
                .checked_add(word(bytes, offset)? as usize)
                .context("BTF offset overflow")?;
            let end = start
                .checked_add(word(bytes, length)? as usize)
                .context("BTF length overflow")?;
            bytes.get(start..end).context("truncated BTF section")
        };
        let data = section(8, 12)?;
        let strings = section(16, 20)?;
        ensure!(strings.first() == Some(&0), "invalid BTF string table");
        let name = |offset: u32| -> Result<String> {
            let tail = strings
                .get(offset as usize..)
                .context("invalid BTF string offset")?;
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .context("unterminated BTF string")?;
            Ok(std::str::from_utf8(&tail[..end])?.to_owned())
        };
        let mut types = vec![Type::default()];
        let mut cursor = 0;
        while cursor < data.len() {
            let info = word(data, cursor + 4)?;
            let kind = (info >> 24) & 31;
            let count = (info & 0xffff) as usize;
            let extra = match kind {
                1 | 14 | 17 => 4,
                3 => 12,
                4 | 5 | 15 | 19 => count * 12,
                6 | 13 => count * 8,
                2 | 7..=12 | 16 | 18 => 0,
                _ => bail!("unsupported BTF kind {kind}"),
            };
            let mut ty = Type {
                name: name(word(data, cursor)?)?,
                kind,
                size_type: word(data, cursor + 8)?,
                ..Type::default()
            };
            cursor += 12;
            let payload = data
                .get(cursor..cursor + extra)
                .context("truncated BTF type")?;
            if kind == 4 || kind == 5 {
                for member in payload.as_chunks::<12>().0 {
                    let raw = word(member, 8)?;
                    let flagged = info >> 31 != 0;
                    ty.members.push(Member {
                        name: name(word(member, 0)?)?,
                        ty: word(member, 4)?,
                        bits: if flagged { raw & 0xffffff } else { raw },
                        bitfield: flagged && raw >> 24 != 0,
                    });
                }
            } else if kind == 13 {
                for param in payload.as_chunks::<8>().0 {
                    ty.members.push(Member {
                        name: name(word(param, 0)?)?,
                        ty: word(param, 4)?,
                        bits: 0,
                        bitfield: false,
                    });
                }
            } else if kind == 6 {
                for entry in payload.as_chunks::<8>().0 {
                    ty.members.push(Member {
                        name: name(word(entry, 0)?)?,
                        ty: 0,
                        bits: word(entry, 4)?,
                        bitfield: false,
                    });
                }
            } else if kind == 3 {
                ty.array = Some((word(payload, 0)?, word(payload, 8)?));
            } else if kind == 1 {
                ty.int_encoding = word(payload, 0)?;
            }
            types.push(ty);
            cursor += extra;
        }
        Ok(Self { types })
    }

    fn ty(&self, mut id: u32) -> Result<&Type> {
        for _ in 0..32 {
            let ty = self
                .types
                .get(id as usize)
                .context("invalid BTF type reference")?;
            if matches!(ty.kind, 8..=11 | 18) {
                id = ty.size_type;
            } else {
                return Ok(ty);
            }
        }
        bail!("cyclic BTF type reference")
    }

    fn member(&self, ty: &Type, name: &str, depth: usize) -> Result<(u32, u32)> {
        ensure!(
            depth < 16 && matches!(ty.kind, 4 | 5),
            "unsupported composite for {name}"
        );
        for member in &ty.members {
            if member.bitfield || member.bits % 8 != 0 {
                continue;
            }
            let offset = member.bits / 8;
            if member.name == name {
                let flexible = self
                    .ty(member.ty)?
                    .array
                    .is_some_and(|(_, count)| count == 0);
                ensure!(
                    offset < ty.size_type || (flexible && offset == ty.size_type),
                    "member outside struct: {name}"
                );
                return Ok((offset, member.ty));
            }
            if member.name.is_empty() {
                if let Ok((inner, id)) = self.member(self.ty(member.ty)?, name, depth + 1) {
                    return Ok((
                        offset
                            .checked_add(inner)
                            .context("member offset overflow")?,
                        id,
                    ));
                }
            }
        }
        bail!("missing or unsupported member {}.{name}", ty.name)
    }

    fn plan(&self, field: usize) -> Result<ReadPlan> {
        let path: &[&str] = match field {
            START_BOOTTIME => &["group_leader", "start_boottime"],
            EUID => &["cred", "euid", "val"],
            EGID => &["cred", "egid", "val"],
            MOUNT_NS => &["nsproxy", "mnt_ns", "ns", "inum"],
            PID_NS => &["thread_pid", "numbers", "@active", "ns", "ns", "inum"],
            NET_NS => &["nsproxy", "net_ns", "ns", "inum"],
            SESSION_ID => &["signal", "pids", "@session", "numbers", "@first", "nr"],
            TTY_MAJOR => &["signal", "tty", "driver", "major"],
            TTY_MINOR => &["signal", "tty", "driver", "minor_start"],
            TTY_INDEX => &["signal", "tty", "index"],
            _ => bail!("unknown task field"),
        };
        let mut ty = self
            .types
            .iter()
            .find(|ty| ty.kind == 4 && ty.name == "task_struct")
            .context("missing task_struct")?;
        let mut plan = ReadPlan::default();
        let mut step = ReadStep::default();
        let mut array_parent = None;
        for component in path {
            while ty.kind == 2 {
                ensure!((plan.len as usize) < MAX_STEPS - 1, "too many pointer hops");
                plan.steps[plan.len as usize] = step;
                plan.len += 1;
                step = ReadStep::default();
                ty = self.ty(ty.size_type)?;
            }
            if component.starts_with('@') {
                let (element, count) = ty.array.context("expected BTF array")?;
                ty = self.ty(element)?;
                let size = if ty.kind == 2 { 8 } else { ty.size_type };
                match *component {
                    "@active" => {
                        let parent = array_parent.context("missing pid array parent")?;
                        let (offset, level_type) = self.member(parent, "level", 0)?;
                        self.scalar(self.ty(level_type)?, 4)?;
                        ensure!(
                            size > 0 && size <= 255 && offset <= 65535,
                            "unsupported pid layout"
                        );
                        step.stride = size;
                        step.level_offset = offset;
                    }
                    "@session" => {
                        // PIDTYPE_SID is a kernel enum, resolved rather than assumed.
                        let sid = self.enum_value("pid_type", "PIDTYPE_SID")?;
                        ensure!(sid < count, "session PID index outside array");
                        step.offset = step
                            .offset
                            .checked_add(sid.checked_mul(size).context("array overflow")?)
                            .context("offset overflow")?;
                    }
                    "@first" => (),
                    _ => bail!("unsupported array selector"),
                }
            } else {
                array_parent = Some(ty);
                let (offset, id) = self.member(ty, component, 0)?;
                step.offset = step.offset.checked_add(offset).context("offset overflow")?;
                ty = self.ty(id)?;
            }
            ensure!(
                step.offset <= 65535 && step.offset + 32 * step.stride <= 65535,
                "BTF offset exceeds verifier bounds"
            );
        }
        self.scalar(ty, if field == START_BOOTTIME { 8 } else { 4 })?;
        plan.steps[plan.len as usize] = step;
        plan.len += 1;
        if matches!(field, START_BOOTTIME | EUID | EGID) {
            ensure!(
                plan.len == 2 && plan.steps.iter().all(|step| step.stride == 0),
                "unsupported credential or birth-time pointer layout"
            );
        }
        Ok(plan)
    }

    fn socket_field(&self, root: &str, path: &[&str], width: u32) -> Result<u32> {
        let mut ty = self
            .types
            .iter()
            .find(|ty| ty.kind == 4 && ty.name == root)
            .with_context(|| format!("missing {root}"))?;
        let mut offset = 0u32;
        for component in path {
            let (delta, id) = self.member(ty, component, 0)?;
            offset = offset
                .checked_add(delta)
                .context("socket offset overflow")?;
            ty = self.ty(id)?;
        }
        ensure!(offset <= 65535, "socket offset exceeds verifier bounds");
        match width {
            16 => ensure!(
                ty.kind == 4 && ty.size_type == 16,
                "unsupported IPv6 address layout"
            ),
            8 => {
                ensure!(ty.kind == 2, "expected socket pointer");
                let pointee = self.ty(ty.size_type)?;
                ensure!(
                    pointee.kind == 4 && pointee.name == "sock",
                    "expected pointer to sock"
                );
            }
            _ => self.scalar(ty, width)?,
        }
        Ok(offset)
    }

    fn file_field(&self, root: &str, path: &[&str], target: FileFieldType) -> Result<u32> {
        let mut ty = self
            .types
            .iter()
            .find(|ty| ty.kind == 4 && ty.name == root)
            .with_context(|| format!("missing {root}"))?;
        let mut offset = 0u32;
        for component in path {
            let (delta, id) = self.member(ty, component, 0)?;
            offset = offset
                .checked_add(delta)
                .context("file identity offset overflow")?;
            ty = self.ty(id)?;
        }
        ensure!(
            offset <= 65535,
            "file identity offset exceeds verifier bounds"
        );
        match target {
            FileFieldType::Scalar(width) => self.scalar(ty, width)?,
            FileFieldType::Pointer(name) => {
                ensure!(ty.kind == 2, "expected pointer to {name}");
                ensure!(
                    self.ty(ty.size_type)?.kind == 4 && self.ty(ty.size_type)?.name == name,
                    "expected pointer to {name}"
                );
            }
            FileFieldType::PointerToPointer(name) => {
                ensure!(ty.kind == 2, "expected pointer-to-pointer to {name}");
                let pointer = self.ty(ty.size_type)?;
                ensure!(pointer.kind == 2, "expected pointer-to-pointer to {name}");
                ensure!(
                    self.ty(pointer.size_type)?.kind == 4
                        && self.ty(pointer.size_type)?.name == name,
                    "expected pointer-to-pointer to {name}"
                );
            }
        }
        Ok(offset)
    }

    fn function_parameter(&self, function: &str, parameter: &str, pointee: &str) -> Result<usize> {
        let func = self
            .types
            .iter()
            .find(|ty| ty.kind == 12 && ty.name == function)
            .with_context(|| format!("missing function {function}"))?;
        let proto = self.ty(func.size_type)?;
        ensure!(proto.kind == 13, "missing function prototype");
        let (index, member) = proto
            .members
            .iter()
            .enumerate()
            .find(|(_, member)| member.name == parameter)
            .with_context(|| format!("missing parameter {function}.{parameter}"))?;
        let pointer = self.ty(member.ty)?;
        ensure!(pointer.kind == 2, "expected pointer parameter {parameter}");
        ensure!(
            self.ty(pointer.size_type)?.kind == 4 && self.ty(pointer.size_type)?.name == pointee,
            "unexpected parameter type for {function}.{parameter}"
        );
        Ok(index)
    }

    fn file_identity_layout(&self) -> Result<FileIdentityLayout> {
        use super::file_identity_abi::FileIdentityOffsets;
        let offsets = FileIdentityOffsets {
            enabled: 1,
            task_files: self.file_field(
                "task_struct",
                &["files"],
                FileFieldType::Pointer("files_struct"),
            )?,
            files_fdt: self.file_field(
                "files_struct",
                &["fdt"],
                FileFieldType::Pointer("fdtable"),
            )?,
            fdtable_max_fds: self.file_field("fdtable", &["max_fds"], FileFieldType::Scalar(4))?,
            fdtable_fd: self.file_field(
                "fdtable",
                &["fd"],
                FileFieldType::PointerToPointer("file"),
            )?,
            file_inode: self.file_field("file", &["f_inode"], FileFieldType::Pointer("inode"))?,
            dentry_inode: self.file_field(
                "dentry",
                &["d_inode"],
                FileFieldType::Pointer("inode"),
            )?,
            inode_ino: self.file_field("inode", &["i_ino"], FileFieldType::Scalar(8))?,
            inode_sb: self.file_field("inode", &["i_sb"], FileFieldType::Pointer("super_block"))?,
            super_block_dev: self.file_field(
                "super_block",
                &["s_dev"],
                FileFieldType::Scalar(4),
            )?,
            renamedata_old_dentry: self.file_field(
                "renamedata",
                &["old_dentry"],
                FileFieldType::Pointer("dentry"),
            )?,
        };
        Ok(FileIdentityLayout {
            offsets,
            unlink_program: dentry_program(
                "handle_vfs_unlink_identity",
                self.function_parameter("vfs_unlink", "dentry", "dentry")?,
            )?,
            rmdir_program: dentry_program(
                "handle_vfs_rmdir_identity",
                self.function_parameter("vfs_rmdir", "dentry", "dentry")?,
            )?,
            mkdir_program: dentry_program(
                "handle_vfs_mkdir_identity",
                self.function_parameter("vfs_mkdir", "dentry", "dentry")?,
            )?,
        })
    }

    fn function(&self, name: &str, returns_sock: bool) -> Result<usize> {
        let func = self
            .types
            .iter()
            .find(|ty| ty.kind == 12 && ty.name == name)
            .with_context(|| format!("missing function {name}"))?;
        let proto = self.ty(func.size_type)?;
        ensure!(proto.kind == 13, "missing function prototype");
        let ret = self.ty(proto.size_type)?;
        if returns_sock {
            ensure!(
                ret.kind == 2 && self.ty(ret.size_type)?.name == "sock",
                "unexpected accept return type"
            );
        } else {
            self.scalar(ret, 4)?;
        }
        let first = self.ty(proto
            .members
            .first()
            .context("missing socket parameter")?
            .ty)?;
        ensure!(first.kind == 2, "expected socket argument pointer");
        ensure!(
            self.ty(first.size_type)?.name == if returns_sock { "sock" } else { "socket" },
            "unexpected socket argument"
        );
        Ok(proto.members.len())
    }

    fn socket_layout(&self) -> Result<SocketLayout> {
        use super::socket_tuple_abi::SocketOffsets;
        ensure!(
            self.function("inet_stream_connect", false)? == 4,
            "unsupported stream connect prototype"
        );
        ensure!(
            self.function("inet_dgram_connect", false)? == 4,
            "unsupported datagram connect prototype"
        );
        let accept_args = self.function("inet_csk_accept", true)?;
        ensure!(
            matches!(accept_args, 2 | 4),
            "unsupported accept prototype: {accept_args} arguments"
        );
        let field = |name, width| self.socket_field("sock", &["__sk_common", name], width);
        let (protocol, protocol_width) = match self.socket_field("sock", &["sk_protocol"], 1) {
            Ok(offset) => (offset, 1),
            Err(_) => (self.socket_field("sock", &["sk_protocol"], 2)?, 2),
        };
        Ok(SocketLayout {
            offsets: SocketOffsets {
                socket_sk: self.socket_field("socket", &["sk"], 8)?,
                family: field("skc_family", 2)?,
                saddr: field("skc_rcv_saddr", 4)?,
                daddr: field("skc_daddr", 4)?,
                sport: field("skc_num", 2)?,
                dport: field("skc_dport", 2)?,
                saddr6: field("skc_v6_rcv_saddr", 16)?,
                daddr6: field("skc_v6_daddr", 16)?,
                protocol,
                protocol_width,
            },
            accept_program: if accept_args == 2 {
                "handle_accept2"
            } else {
                "handle_accept4"
            },
        })
    }

    fn scalar(&self, ty: &Type, width: u32) -> Result<()> {
        ensure!(
            ty.kind == 1 && ty.size_type == width && ty.int_encoding & 0xffffff == width * 8,
            "unsupported scalar width or bitfield"
        );
        Ok(())
    }

    fn enum_value(&self, name: &str, member: &str) -> Result<u32> {
        let ty = self
            .types
            .iter()
            .find(|ty| ty.kind == 6 && ty.name == name)
            .context("missing BTF enum")?;
        ty.members
            .iter()
            .find(|entry| entry.name == member)
            .map(|entry| entry.bits)
            .context("missing BTF enum value")
    }
}

enum FileFieldType {
    Scalar(u32),
    Pointer(&'static str),
    PointerToPointer(&'static str),
}

fn dentry_program(prefix: &'static str, index: usize) -> Result<&'static str> {
    match (prefix, index) {
        ("handle_vfs_unlink_identity", 1) => Ok("handle_vfs_unlink_identity1"),
        ("handle_vfs_unlink_identity", 2) => Ok("handle_vfs_unlink_identity2"),
        ("handle_vfs_rmdir_identity", 1) => Ok("handle_vfs_rmdir_identity1"),
        ("handle_vfs_rmdir_identity", 2) => Ok("handle_vfs_rmdir_identity2"),
        ("handle_vfs_mkdir_identity", 1) => Ok("handle_vfs_mkdir_identity1"),
        ("handle_vfs_mkdir_identity", 2) => Ok("handle_vfs_mkdir_identity2"),
        _ => bail!("unsupported {prefix} dentry argument index {index}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(cred_offset: u32, euid_offset: u32, euid_name: &str, width: u32) -> Vec<u8> {
        let mut strings = vec![0];
        let mut data = Vec::new();
        let mut name = |s: &str| {
            let offset = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            offset
        };
        let mut words = |values: &[u32]| {
            for value in values {
                data.extend(value.to_le_bytes());
            }
        };
        words(&[name("u32"), 1 << 24, width, width * 8]); // 1
        words(&[name("kuid_t"), (4 << 24) | 1, width, name("val"), 1, 0]); // 2
        words(&[
            name("cred"),
            (4 << 24) | 2,
            64,
            name(euid_name),
            2,
            euid_offset * 8,
            name("egid"),
            2,
            40 * 8,
        ]); // 3
        words(&[0, 2 << 24, 3]); // 4 pointer
        words(&[
            name("task_struct"),
            (4 << 24) | 1,
            4096,
            name("cred"),
            4,
            cred_offset * 8,
        ]); // 5
        let mut bytes = vec![0x9f, 0xeb, 1, 0];
        for value in [
            24,
            0,
            data.len() as u32,
            data.len() as u32,
            strings.len() as u32,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(data);
        bytes.extend(strings);
        bytes
    }

    #[test]
    fn offsets_follow_running_layout_and_zero_is_valid() {
        for (cred, euid) in [(2720, 24), (2984, 20), (3328, 0)] {
            let plans = TaskPlans::resolve(Btf::parse(&fixture(cred, euid, "euid", 4)));
            assert_eq!(plans.plans[EUID].len, 2);
            assert_eq!(plans.plans[EUID].steps[0].offset, cred);
            assert_eq!(plans.plans[EUID].steps[1].offset, euid);
        }
    }

    #[test]
    fn missing_member_disables_only_affected_field() {
        let plans = TaskPlans::resolve(Btf::parse(&fixture(2720, 24, "renamed_euid", 4)));
        assert_eq!(plans.plans[EUID].len, 0);
        assert_eq!(plans.plans[EGID].len, 2);
        assert!(plans
            .warnings
            .iter()
            .any(|(name, _)| name == "linux_task_euid"));
        assert!(!plans
            .warnings
            .iter()
            .any(|(name, _)| name == "linux_task_egid"));
    }

    #[test]
    fn changed_scalar_width_is_disabled() {
        let plans = TaskPlans::resolve(Btf::parse(&fixture(2720, 24, "euid", 8)));
        assert_eq!(plans.plans[EUID].len, 0);
        assert_eq!(plans.plans[EGID].len, 0);
    }

    #[test]
    fn bitfields_and_unbounded_offsets_are_disabled() {
        let mut bytes = fixture(2720, 24, "euid", 4);
        // Header (24), int (16), kuid (24), then cred's header and members.
        let cred = 24 + 16 + 24;
        bytes[cred + 4..cred + 8].copy_from_slice(&((1u32 << 31) | (4 << 24) | 2).to_le_bytes());
        bytes[cred + 20..cred + 24].copy_from_slice(&((16u32 << 24) | (24 * 8)).to_le_bytes());
        let plans = TaskPlans::resolve(Btf::parse(&bytes));
        assert_eq!(plans.plans[EUID].len, 0);
        assert_eq!(plans.plans[EGID].len, 2);
        let plans = TaskPlans::resolve(Btf::parse(&fixture(65536, 24, "euid", 4)));
        assert_eq!(plans.plans[EUID].len, 0);
    }

    #[test]
    fn truncated_and_malformed_btf_never_panics() {
        let bytes = fixture(2720, 24, "euid", 4);
        for len in 0..bytes.len() {
            assert!(Btf::parse(&bytes[..len]).is_err());
        }
        for offset in [4, 8, 12, 16, 20] {
            let mut corrupt = bytes.clone();
            corrupt[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(Btf::parse(&corrupt).is_err());
        }
        let plans = TaskPlans::resolve(Btf::parse(&[]));
        assert_eq!(plans.warnings.len(), FIELD_COUNT);
        assert!(plans.plans.iter().all(|plan| plan.len == 0));
    }
}

unsafe impl aya::Pod for super::socket_tuple_abi::SocketOffsets {}
unsafe impl aya::Pod for super::file_identity_abi::FileIdentityOffsets {}

pub struct FileIdentityLayout {
    pub offsets: super::file_identity_abi::FileIdentityOffsets,
    pub unlink_program: &'static str,
    pub rmdir_program: &'static str,
    pub mkdir_program: &'static str,
}

impl FileIdentityLayout {
    pub fn load() -> Result<Self> {
        Self::from_bytes(&std::fs::read(BTF_PATH).context("reading kernel BTF")?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Btf::parse(bytes)?.file_identity_layout()
    }
}

pub struct SocketLayout {
    pub offsets: super::socket_tuple_abi::SocketOffsets,
    pub accept_program: &'static str,
}

impl SocketLayout {
    pub fn load() -> Result<Self> {
        Self::from_bytes(&std::fs::read(BTF_PATH).context("reading kernel BTF")?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Btf::parse(bytes)?.socket_layout()
    }
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    fn fixture(protocol_offset: u32, accept_args: usize) -> Btf {
        let scalar = |size| Type {
            kind: 1,
            size_type: size,
            int_encoding: size * 8,
            ..Type::default()
        };
        let member = |name: &str, ty, offset: u32| Member {
            name: name.into(),
            ty,
            bits: offset * 8,
            bitfield: false,
        };
        let composite = |name: &str, size, members| Type {
            name: name.into(),
            kind: 4,
            size_type: size,
            members,
            ..Type::default()
        };
        let proto = |first, count, ret| Type {
            kind: 13,
            size_type: ret,
            members: (0..count)
                .map(|i| member("", if i == 0 { first } else { 3 }, 0))
                .collect(),
            ..Type::default()
        };
        let func = |name: &str, proto| Type {
            name: name.into(),
            kind: 12,
            size_type: proto,
            ..Type::default()
        };
        Btf {
            types: vec![
                Type::default(),
                scalar(1),
                scalar(2),
                scalar(4),                         // 0..3
                composite("in6_addr", 16, vec![]), // 4
                composite(
                    "sock_common",
                    128,
                    vec![
                        // 5
                        member("skc_daddr", 3, 0),
                        member("skc_rcv_saddr", 3, 4),
                        member("skc_dport", 2, 12),
                        member("skc_num", 2, 14),
                        member("skc_family", 2, 16),
                        member("skc_v6_daddr", 4, 56),
                        member("skc_v6_rcv_saddr", 4, 72),
                    ],
                ),
                composite(
                    "sock",
                    1024,
                    vec![
                        member("__sk_common", 5, 0),
                        member("sk_protocol", 2, protocol_offset),
                    ],
                ), // 6
                Type {
                    kind: 2,
                    size_type: 6,
                    ..Type::default()
                }, // 7
                composite("socket", 128, vec![member("sk", 7, 24)]), // 8
                Type {
                    kind: 2,
                    size_type: 8,
                    ..Type::default()
                }, // 9
                proto(9, 4, 3),                                      // 10
                func("inet_stream_connect", 10),
                func("inet_dgram_connect", 10), // 11,12
                proto(7, accept_args, 7),
                func("inet_csk_accept", 13), // 13,14
            ],
        }
    }

    #[test]
    fn socket_offsets_and_accept_index_follow_kernel_btf() {
        for (offset, args) in [(540, 4), (548, 4), (516, 4), (548, 2)] {
            let layout = fixture(offset, args).socket_layout().unwrap();
            assert_eq!(layout.offsets.protocol, offset);
            assert_eq!(layout.offsets.protocol_width, 2);
            assert_eq!(layout.offsets.daddr, 0);
            assert_eq!(layout.offsets.socket_sk, 24);
            assert_eq!(
                layout.accept_program,
                if args == 2 {
                    "handle_accept2"
                } else {
                    "handle_accept4"
                }
            );
        }
    }

    #[test]
    fn unsupported_layouts_select_fallback_without_guessed_offsets() {
        assert!(SocketLayout::from_bytes(&[]).is_err());
        assert!(fixture(548, 3).socket_layout().is_err());
        assert!(fixture(65536, 4).socket_layout().is_err());
        let mut btf = fixture(548, 4);
        btf.types[6].members[1].name = "renamed_protocol".into();
        assert!(btf.socket_layout().is_err());
        btf.types[6].members[1].name = "sk_protocol".into();
        btf.types[6].members[1].bitfield = true;
        assert!(btf.socket_layout().is_err());
        btf.types[6].members[1].bitfield = false;
        btf.types[10].members.pop();
        assert!(btf.socket_layout().is_err());
    }

    #[test]
    fn protocol_width_is_resolved_and_unknown_width_is_rejected() {
        let mut btf = fixture(516, 4);
        btf.types[6].members[1].ty = 1;
        assert_eq!(btf.socket_layout().unwrap().offsets.protocol_width, 1);
        btf.types[6].members[1].ty = 3;
        assert!(btf.socket_layout().is_err());
    }
}

#[cfg(test)]
mod file_identity_tests {
    use super::*;

    fn fixture(dentry_index: usize) -> Btf {
        let scalar = |size| Type {
            kind: 1,
            size_type: size,
            int_encoding: size * 8,
            ..Type::default()
        };
        let member = |name: &str, ty, offset: u32| Member {
            name: name.into(),
            ty,
            bits: offset * 8,
            bitfield: false,
        };
        let composite = |name: &str, size, members| Type {
            name: name.into(),
            kind: 4,
            size_type: size,
            members,
            ..Type::default()
        };
        let pointer = |target| Type {
            kind: 2,
            size_type: target,
            ..Type::default()
        };
        let proto = |dentry_index| Type {
            kind: 13,
            size_type: 1,
            members: (0..=dentry_index)
                .map(|index| member(if index == dentry_index { "dentry" } else { "" }, 8, 0))
                .collect(),
            ..Type::default()
        };
        let func = |name: &str, prototype| Type {
            name: name.into(),
            kind: 12,
            size_type: prototype,
            ..Type::default()
        };
        Btf {
            types: vec![
                Type::default(),
                scalar(4), // 1
                scalar(8), // 2
                composite(
                    "inode",
                    256,
                    vec![member("i_ino", 2, 64), member("i_sb", 6, 72)],
                ), // 3
                pointer(3), // 4
                composite("super_block", 256, vec![member("s_dev", 1, 16)]), // 5
                pointer(5), // 6
                composite("dentry", 128, vec![member("d_inode", 4, 48)]), // 7
                pointer(7), // 8
                composite("file", 192, vec![member("f_inode", 4, 80)]), // 9
                pointer(9), // 10
                pointer(10), // 11
                composite(
                    "fdtable",
                    64,
                    vec![member("max_fds", 1, 0), member("fd", 11, 8)],
                ), // 12
                pointer(12), // 13
                composite("files_struct", 128, vec![member("fdt", 13, 24)]), // 14
                pointer(14), // 15
                composite("task_struct", 4096, vec![member("files", 15, 1024)]), // 16
                composite("renamedata", 64, vec![member("old_dentry", 8, 16)]), // 17
                proto(dentry_index), // 18
                func("vfs_unlink", 18), // 19
                proto(dentry_index), // 20
                func("vfs_rmdir", 20), // 21
                proto(dentry_index), // 22
                func("vfs_mkdir", 22), // 23
            ],
        }
    }

    #[test]
    fn file_offsets_and_dentry_arguments_follow_kernel_btf() {
        for index in [1, 2] {
            let layout = fixture(index).file_identity_layout().unwrap();
            assert_eq!(layout.offsets.enabled, 1);
            assert_eq!(layout.offsets.task_files, 1024);
            assert_eq!(layout.offsets.file_inode, 80);
            assert_eq!(layout.offsets.inode_ino, 64);
            assert_eq!(layout.offsets.super_block_dev, 16);
            assert_eq!(
                layout.unlink_program,
                if index == 1 {
                    "handle_vfs_unlink_identity1"
                } else {
                    "handle_vfs_unlink_identity2"
                }
            );
        }
    }

    #[test]
    fn unsupported_file_layout_selects_identity_fallback() {
        assert!(FileIdentityLayout::from_bytes(&[]).is_err());
        assert!(fixture(3).file_identity_layout().is_err());
        let mut btf = fixture(2);
        btf.types[3].members[0].name = "renamed_ino".into();
        assert!(btf.file_identity_layout().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires readable BTF from the running Linux kernel"]
    fn running_kernel_file_identity_layout_is_supported() {
        let layout = FileIdentityLayout::load().expect("running kernel file identity layout");
        assert_eq!(layout.offsets.enabled, 1);
    }
}
