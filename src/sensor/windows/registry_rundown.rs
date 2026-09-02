//! Naming the registry keys that were already open when the session started.
//!
//! `Microsoft-Windows-Kernel-Registry` names a key exactly once, on the
//! `CreateKey`/`OpenKey` that produced the handle, and every later event
//! identifies it only by `KeyObject`. A key whose handle predates the trace
//! session is therefore unnameable from the event stream alone, and the value
//! writes that land on it are dropped. That is not a corner case: Explorer, the
//! service host and svchost hold `Run`, `Winlogon` and IFEO keys open for the
//! life of the boot, so a boot-start agent is blind to writes through them
//! (#341).
//!
//! Measured on Windows 11 26200, the provider offers no way out:
//!
//! - `QueryKey` (4) declares a `KeyName` and delivers it empty on 100% of
//!   events, as do `QueryValueKey`, `EnumerateKey` and every write event. Only
//!   `CreateKey` and `OpenKey` carry `BaseName`/`RelativeName` at all.
//! - `EnableTraceEx2` with `EVENT_CONTROL_CODE_CAPTURE_STATE` returns success
//!   and emits nothing; the manifest declares no rundown event.
//! - `KeyObject` is the per-handle `CM_KEY_BODY` pointer, not the shared key
//!   control block: one `Get-ItemProperty` on a single key produced 29
//!   `OpenKey` events with 29 distinct `KeyObject` values. So no amount of
//!   extra naming traffic from other processes can name someone else's handle.
//!
//! What does work is the kernel handle table. The `Object` pointer
//! `NtQuerySystemInformation(SystemExtendedHandleInformation)` reports for a
//! key handle is bit-for-bit the `KeyObject` the provider puts on that handle's
//! events, verified by writing through a handle opened before the session and
//! matching the two pointers. Duplicating the handle and asking
//! `NtQueryKey(KeyNameInformation)` for its path turns the table into a seed
//! for [`super::registry_paths::RegistryPathCache`].
//!
//! Measured cost of one sweep, as SYSTEM on an idle desktop: 82,819 handles,
//! 6,665 of them registry keys, **5,908 named (88.9%) in 32 ms**. The 731
//! failures were all `OpenProcess` denials from 16 protected processes:
//! System, smss, csrss, wininit, services, lsass, the Defender services and
//! four protected svchosts. PPL denial is kernel-enforced, so neither SYSTEM
//! nor `SeDebugPrivilege` recovers them; none of them is a process an attacker
//! writes persistence through.
//!
//! The sweep runs *after* the session is started, which is what makes it
//! gapless: a key is then either in this snapshot or has an `OpenKey` event.

use std::collections::HashMap;

use tracing::debug;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

/// `SYSTEM_INFORMATION_CLASS::SystemExtendedHandleInformation`.
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
/// `KEY_INFORMATION_CLASS::KeyNameInformation`.
const KEY_NAME_INFORMATION: u32 = 3;
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004

/// Starting size of the handle-table buffer, in `u64` words. The table was
/// 2.6 MB on the measured desktop (83k handles at 32 bytes), so 4 MB usually
/// avoids the retry entirely.
///
/// The buffer is words rather than bytes so that it is guaranteed aligned for
/// the entry array, which `Vec<u8>` would not be.
const INITIAL_TABLE_WORDS: usize = 4 * 1024 * 1024 / 8;
/// Ceiling on the handle-table buffer. A machine with more than ~2M open
/// handles is pathological, and the sweep is a startup nicety rather than
/// something worth allocating unbounded memory for.
const MAX_TABLE_WORDS: usize = 64 * 1024 * 1024 / 8;

/// Longest key path accepted, in UTF-16 code units. The registry's own limit
/// on a fully qualified key path is far below this.
const MAX_KEY_NAME_UNITS: usize = 2048;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut u8,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;

    fn NtQueryKey(
        KeyHandle: HANDLE,
        KeyInformationClass: u32,
        KeyInformation: *mut u8,
        Length: u32,
        ResultLength: *mut u32,
    ) -> i32;
}

/// `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX`.
#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy)]
struct SystemHandleTableEntryInfoEx {
    Object: usize,
    UniqueProcessId: usize,
    HandleValue: usize,
    GrantedAccess: u32,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u16,
    HandleAttributes: u32,
    Reserved: u32,
}

/// `SYSTEM_HANDLE_INFORMATION_EX`, without its trailing entry array.
#[repr(C)]
#[allow(non_snake_case)]
struct SystemHandleInformationExHeader {
    NumberOfHandles: usize,
    Reserved: usize,
}

/// Snapshot every registry key handle open on the machine, keyed by the
/// `KeyObject` pointer the provider reports for it.
///
/// Never fails the caller: an empty map means the sensor behaves as it did
/// before, resolving only keys opened inside the session.
pub(super) fn snapshot_open_keys() -> HashMap<u64, String> {
    let table = match query_handle_table() {
        Some(table) => table,
        None => {
            debug!("Registry rundown: could not read the handle table");
            return HashMap::new();
        }
    };
    let entries = parse_entries(&table);

    let mut paths: HashMap<u64, String> = HashMap::new();
    let mut processes = ProcessHandles::new();
    // The object type index for `Key` is assigned at boot and is not stable
    // across builds, so it is learned from the first handle that answers
    // `NtQueryKey` rather than hardcoded. Until then every handle is tried.
    let mut key_type_index: Option<u16> = None;
    let mut denied_keys = 0usize;

    for entry in entries {
        if key_type_index.is_some_and(|index| index != entry.ObjectTypeIndex) {
            continue;
        }
        let object = entry.Object as u64;
        if object == 0 || paths.contains_key(&object) {
            continue;
        }

        let Ok(pid) = u32::try_from(entry.UniqueProcessId) else {
            continue;
        };
        let Some(process) = processes.get(pid) else {
            // Only counted once the type index is known, so the tally is
            // denied *key* handles rather than denied handles of every kind.
            denied_keys += usize::from(key_type_index.is_some());
            continue;
        };

        let Some(duplicate) = duplicate_handle(process, entry.HandleValue) else {
            continue;
        };
        let name = key_name(duplicate);
        // SAFETY: `duplicate` came from `DuplicateHandle` into this process and
        // is not used again.
        unsafe {
            let _ = CloseHandle(duplicate);
        }

        if let Some(name) = name {
            key_type_index.get_or_insert(entry.ObjectTypeIndex);
            paths.insert(object, name);
        }
    }

    debug!(
        keys = paths.len(),
        denied_keys,
        inaccessible_processes = processes.denied(),
        "Registry rundown: seeded the key-path index from the handle table"
    );
    paths
}

/// Read `SystemExtendedHandleInformation` into a buffer, growing on the
/// length mismatch the table's own churn makes routine.
fn query_handle_table() -> Option<Vec<u64>> {
    let mut words = INITIAL_TABLE_WORDS;
    loop {
        let mut buffer = vec![0u64; words];
        let bytes = words * size_of::<u64>();
        let mut needed = 0u32;
        // SAFETY: the buffer holds `bytes` bytes and that length is what is
        // passed; `needed` is a valid out pointer.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer.as_mut_ptr().cast::<u8>(),
                bytes as u32,
                &mut needed,
            )
        };
        if status == 0 {
            return Some(buffer);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return None;
        }

        // `needed` describes a table that keeps growing while it is read, so
        // ask for headroom rather than exactly what the last call wanted.
        let wanted = (needed as usize)
            .div_ceil(size_of::<u64>())
            .saturating_mul(2)
            .max(words * 2);
        if wanted > MAX_TABLE_WORDS {
            return None;
        }
        words = wanted;
    }
}

/// Borrow the entry array out of the raw table buffer.
///
/// Both structs are `#[repr(C)]` and pointer-sized-aligned, and the buffer is
/// a `Vec<u64>`, so the entry array is aligned by construction.
fn parse_entries(table: &[u64]) -> &[SystemHandleTableEntryInfoEx] {
    const _: () = assert!(align_of::<SystemHandleTableEntryInfoEx>() <= align_of::<u64>());
    const _: () =
        assert!(size_of::<SystemHandleInformationExHeader>().is_multiple_of(size_of::<u64>()));

    let bytes = size_of_val(table);
    let header_size = size_of::<SystemHandleInformationExHeader>();
    let entry_size = size_of::<SystemHandleTableEntryInfoEx>();
    if bytes < header_size {
        return &[];
    }

    // SAFETY: the buffer was filled by `NtQuerySystemInformation` for this
    // class, so it starts with the header this reads.
    let header = unsafe { &*table.as_ptr().cast::<SystemHandleInformationExHeader>() };
    // The count comes from the kernel but the buffer length is ours, so the
    // array is clamped to what actually fits rather than trusted.
    let count = header
        .NumberOfHandles
        .min((bytes - header_size) / entry_size);

    // SAFETY: the offset is a whole number of words so the result stays
    // aligned, `count` entries fit within the buffer by the clamp above, and
    // the buffer outlives the returned slice through the caller's binding.
    unsafe {
        let entries = table.as_ptr().add(header_size / size_of::<u64>());
        std::slice::from_raw_parts(entries.cast::<SystemHandleTableEntryInfoEx>(), count)
    }
}

/// Process handles opened for duplication, kept for the life of one sweep.
///
/// A process holds hundreds of key handles, so opening it once per handle
/// would dominate the cost. Denials are cached too: the protected processes
/// that refuse `PROCESS_DUP_HANDLE` refuse it every time.
struct ProcessHandles {
    open: HashMap<u32, Option<HANDLE>>,
}

impl ProcessHandles {
    fn new() -> Self {
        Self {
            open: HashMap::new(),
        }
    }

    fn get(&mut self, pid: u32) -> Option<HANDLE> {
        *self.open.entry(pid).or_insert_with(|| {
            // SAFETY: a plain `OpenProcess` call; the handle is closed in
            // `Drop`.
            unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) }
                .ok()
                .filter(|handle| !handle.is_invalid())
        })
    }

    /// Processes that refused `PROCESS_DUP_HANDLE`, for the log line.
    fn denied(&self) -> usize {
        self.open.values().filter(|handle| handle.is_none()).count()
    }
}

impl Drop for ProcessHandles {
    fn drop(&mut self) {
        for handle in self.open.values().flatten() {
            // SAFETY: every handle here came from `OpenProcess` and is closed
            // exactly once.
            unsafe {
                let _ = CloseHandle(*handle);
            }
        }
    }
}

fn duplicate_handle(process: HANDLE, handle_value: usize) -> Option<HANDLE> {
    let mut duplicate = INVALID_HANDLE_VALUE;
    // SAFETY: `process` is a live `PROCESS_DUP_HANDLE` handle; `handle_value`
    // is interpreted in that process, and a stale value simply fails. No
    // access is requested, so this cannot widen anyone's rights.
    unsafe {
        DuplicateHandle(
            process,
            HANDLE(handle_value as *mut _),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .ok()?;
    }
    (!duplicate.is_invalid()).then_some(duplicate)
}

/// The full `\REGISTRY\...` path of a key handle, or `None` if the handle is
/// not a key.
///
/// `NtQueryKey` is what makes the sweep safe to run over arbitrary handles:
/// unlike `NtQueryObject(ObjectNameInformation)`, it cannot block on a
/// synchronous pipe, and it answers `STATUS_OBJECT_TYPE_MISMATCH` for anything
/// that is not a key.
fn key_name(handle: HANDLE) -> Option<String> {
    // `KEY_NAME_INFORMATION` is a u32 length followed by the characters.
    let mut buffer = vec![0u8; 4 + MAX_KEY_NAME_UNITS * 2];
    let mut needed = 0u32;
    // SAFETY: the buffer length passed matches its allocation.
    let status = unsafe {
        NtQueryKey(
            handle,
            KEY_NAME_INFORMATION,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut needed,
        )
    };
    if status != 0 {
        return None;
    }

    let name_bytes = u32::from_ne_bytes(buffer[..4].try_into().ok()?) as usize;
    // A truncated read would give a partial path, which is worse than none:
    // it would be indexed as if it were the whole key.
    if name_bytes == 0 || !name_bytes.is_multiple_of(2) || 4 + name_bytes > buffer.len() {
        return None;
    }

    let units: Vec<u16> = buffer[4..4 + name_bytes]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_ne_bytes(*pair))
        .collect();
    let name = String::from_utf16_lossy(&units);
    (!name.is_empty()).then_some(name)
}
