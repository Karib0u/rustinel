//! Probe reads use only plans resolved from the running kernel's BTF.

use crate::task_identity_abi::*;
use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_get_current_uid_gid, bpf_probe_read_kernel},
    macros::map,
    maps::Array,
};

#[map]
static TASK_IDENTITY_OFFSETS: Array<ReadPlan> = Array::with_max_entries(FIELD_COUNT as u32, 0);

// Credentials and birth time have one pointer hop. Keep this path straight-line
// because it also runs inside the bounded DNS batching loops on older verifiers.
#[inline(always)]
unsafe fn read_pair(task: u64, plan: &ReadPlan, wide: bool) -> Option<u64> {
    if plan.len != 2 {
        return None;
    }
    let pointer: u64 =
        bpf_probe_read_kernel((task + (plan.steps[0].offset & 0xffff) as u64) as *const u64)
            .ok()?;
    if pointer == 0 {
        return None;
    }
    let address = pointer + (plan.steps[1].offset & 0xffff) as u64;
    if wide {
        bpf_probe_read_kernel(address as *const u64).ok()
    } else {
        bpf_probe_read_kernel(address as *const u32)
            .ok()
            .map(u64::from)
    }
}

#[inline(always)]
unsafe fn read_field(task: u64, plan: &ReadPlan, wide: bool) -> Option<u64> {
    if plan.len == 0 || plan.len > MAX_STEPS as u32 {
        return None;
    }
    let mut address = task;
    let mut i = 0;
    while i < MAX_STEPS {
        let step = &plan.steps[i];
        if address == 0 {
            return None;
        }
        let mut offset = step.offset & 0xffff;
        if step.stride != 0 {
            let level: u32 = bpf_probe_read_kernel(
                (address + (step.level_offset & 0xffff) as u64) as *const u32,
            )
            .ok()?;
            // Linux limits PID namespace nesting to 32 levels.
            if level > 32 {
                return None;
            }
            offset += level * (step.stride & 0xff);
        }
        address += (offset & 0xffff) as u64;
        if i as u32 + 1 == plan.len {
            return if wide {
                bpf_probe_read_kernel(address as *const u64).ok()
            } else {
                bpf_probe_read_kernel(address as *const u32)
                    .ok()
                    .map(u64::from)
            };
        }
        address = bpf_probe_read_kernel(address as *const u64).ok()?;
        i += 1;
    }
    None
}

#[inline(always)]
pub unsafe fn capture(identity: *mut TaskIdentity) {
    (*identity).valid = 0;
    (*identity).real_gid = (bpf_get_current_uid_gid() >> 32) as u32;
    let task = bpf_get_current_task();
    let mut field = 0;
    while field < FIELD_COUNT {
        (*identity).values[field] = 0;
        if let Some(plan) = TASK_IDENTITY_OFFSETS.get(field as u32) {
            if let Some(value) = read_field(task, plan, field == START_BOOTTIME) {
                (*identity).values[field] = value;
                (*identity).valid |= 1 << field;
            }
        }
        field += 1;
    }
}

#[inline(always)]
pub unsafe fn start_boottime() -> Option<u64> {
    let plan = TASK_IDENTITY_OFFSETS.get(START_BOOTTIME as u32)?;
    read_pair(bpf_get_current_task(), plan, true)
}

#[inline(always)]
pub unsafe fn effective_uid() -> Option<u32> {
    let plan = TASK_IDENTITY_OFFSETS.get(EUID as u32)?;
    read_pair(bpf_get_current_task(), plan, false).map(|value| value as u32)
}
