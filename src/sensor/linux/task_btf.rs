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
