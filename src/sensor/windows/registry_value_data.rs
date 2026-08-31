//! Registry value *data*: asking the provider for it, and rendering it.
//!
//! `Microsoft-Windows-Kernel-Registry` declares `CapturedData` on `SetValueKey`
//! but delivers it empty unless the trace session asks for it, so before #292
//! `Details` carried the value *name* instead. Sysmon Event ID 13 — and the 180
//! SigmaHQ rules written against it — define `Details` as the value *data*, so
//! those rules matched the wrong string rather than nothing at all.
//!
//! The request is an `EnableTraceEx2` filter descriptor whose four payload
//! bytes have bit `0x2` set. It is undocumented and unsupported by `ferrisetw`,
//! which is why the provider is re-enabled by hand here once the session is up;
//! [`super::etw`] treats a failure as non-fatal and keeps the value-name
//! behaviour.
//!
//! Measured on Windows 11 26200 by enabling the provider once per candidate
//! payload and writing a known value under each:
//!
//! | payload | `CapturedDataSize` |
//! |---------|--------------------|
//! | absent  | 0                  |
//! | `0x0`   | 0                  |
//! | `0x1`   | 0                  |
//! | `0x2`   | full value data    |
//! | `0x3`   | full value data    |
//! | `0x4`   | 0                  |
//!
//! The descriptor `Type` is not validated — `0x1` and `0x2` behave the same as
//! `EVENT_FILTER_TYPE_NONE`, and only `EVENT_FILTER_TYPE_SCHEMATIZED` is
//! rejected (`ERROR_INVALID_PARAMETER`), which is what makes this a payload
//! flag rather than a filter. A 802-byte `REG_SZ` came back whole, so the
//! provider does not truncate at any small bound.

use std::mem::size_of;

use anyhow::{bail, Result};
use windows::core::{GUID, PCWSTR};
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, EnableTraceEx2, CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS,
    ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR,
    EVENT_FILTER_TYPE_EVENT_ID, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
};

/// The ETW property that carries the value data, once it is asked for.
pub(super) const CAPTURED_DATA_PROPERTY: &str = "CapturedData";
/// The ETW property that carries the `REG_*` type of that data.
pub(super) const VALUE_TYPE_PROPERTY: &str = "Type";

/// The four filter-payload bytes that turn `CapturedData` on.
const CAPTURE_VALUE_DATA: u32 = 0x2;
/// `EVENT_FILTER_TYPE_NONE`. The provider ignores the type of this descriptor
/// (see the module docs); the neutral value is used so the request cannot be
/// mistaken for a filter that ETW itself would act on.
const EVENT_FILTER_TYPE_NONE: u32 = 0;

/// Room for the logger and log-file names `ControlTraceW` writes back, in
/// bytes. `ControlTraceW` fails with `ERROR_BAD_LENGTH` if either does not fit.
const TRACE_NAME_BYTES: usize = 2 * 1024;

/// Aligned storage for the variable-length `ControlTraceW` properties block.
#[repr(C)]
struct PropertiesBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    names: [u8; 2 * TRACE_NAME_BYTES],
}

impl PropertiesBuffer {
    fn new() -> Box<Self> {
        Box::new(Self {
            properties: EVENT_TRACE_PROPERTIES::default(),
            names: [0; 2 * TRACE_NAME_BYTES],
        })
    }
}

/// `REG_*` value types, from `winnt.h`. `REG_NONE` (0) and `REG_BINARY` (3)
/// are deliberately absent: they take the same path as an unrecognised type.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_LINK: u32 = 6;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

/// Ask an already-started session to include registry value data in
/// `SetValueKey` events.
///
/// Re-enables the provider on the running session, which *replaces* the
/// enablement `ferrisetw` performed: the level, keywords and event-ID scope
/// have to be passed again in full, or the session would silently widen to
/// every registry event.
pub(super) fn request_value_data(
    session_name: &str,
    provider_guid: GUID,
    level: u8,
    keywords: u64,
    event_ids: &[u16],
) -> Result<()> {
    let handle = session_handle(session_name)?;

    let capture = CAPTURE_VALUE_DATA;
    let mut descriptors = vec![EVENT_FILTER_DESCRIPTOR {
        Ptr: std::ptr::addr_of!(capture) as u64,
        Size: size_of::<u32>() as u32,
        Type: EVENT_FILTER_TYPE_NONE,
    }];

    // Owned outside the `if` so the buffer outlives the `EnableTraceEx2` call.
    let event_id_filter = event_id_filter(event_ids);
    if !event_ids.is_empty() {
        descriptors.push(EVENT_FILTER_DESCRIPTOR {
            Ptr: event_id_filter.as_ptr() as u64,
            Size: std::mem::size_of_val(event_id_filter.as_slice()) as u32,
            Type: EVENT_FILTER_TYPE_EVENT_ID,
        });
    }

    let parameters = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        EnableProperty: 0,
        ControlFlags: 0,
        SourceId: GUID::zeroed(),
        EnableFilterDesc: descriptors.as_mut_ptr(),
        FilterDescCount: descriptors.len() as u32,
    };

    // SAFETY: `handle` names a session this process started, the descriptors
    // and their payloads outlive the call, and `parameters` points at them.
    let status = unsafe {
        EnableTraceEx2(
            handle,
            &provider_guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            level,
            keywords,
            0,
            0,
            Some(&parameters),
        )
    };
    if status.is_err() {
        bail!("EnableTraceEx2 failed: {status:?}");
    }
    Ok(())
}

/// Look up the control handle of a running session by name.
///
/// `ControlTraceW` with a null handle returns the session's properties, and the
/// handle itself in `Wnode.HistoricalContext`. The session was started through
/// `ferrisetw`, which keeps its handle private, so this is the only way to
/// reach it.
pub(super) fn session_handle(session_name: &str) -> Result<CONTROLTRACE_HANDLE> {
    let name: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let total = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * TRACE_NAME_BYTES;
    let mut buffer = PropertiesBuffer::new();
    let properties = &mut buffer.properties as *mut EVENT_TRACE_PROPERTIES;

    // SAFETY: `properties` points to the aligned header in `buffer`, the
    // allocation is at least `total` bytes, and both name offsets point into
    // its trailing storage.
    let status = unsafe {
        (*properties).Wnode.BufferSize = total as u32;
        (*properties).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*properties).LogFileNameOffset =
            (size_of::<EVENT_TRACE_PROPERTIES>() + TRACE_NAME_BYTES) as u32;
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            properties,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if status.is_err() {
        bail!("ControlTraceW(QUERY) failed for session '{session_name}': {status:?}");
    }

    // SAFETY: the query succeeded, so the header is initialised.
    let handle = unsafe { (*properties).Wnode.Anonymous1.HistoricalContext };
    if handle == 0 {
        bail!("session '{session_name}' reported no control handle");
    }
    Ok(CONTROLTRACE_HANDLE { Value: handle })
}

/// Build an `EVENT_FILTER_EVENT_ID` payload.
///
/// Laid out as `u16`s rather than through the struct so the buffer is aligned
/// for its `Count` and `Events` members without an unaligned write:
/// `FilterIn`/`Reserved`, `Count`, then the IDs.
fn event_id_filter(event_ids: &[u16]) -> Vec<u16> {
    let mut buffer = vec![0u16; 2 + event_ids.len().max(1)];
    buffer[0] = 1; // FilterIn = TRUE, Reserved = 0
    buffer[1] = event_ids.len() as u16;
    buffer[2..2 + event_ids.len()].copy_from_slice(event_ids);
    buffer
}

/// Render captured value data the way Sysmon Event ID 13 renders `Details`.
///
/// Rules are written against Sysmon's spelling — `DWORD (0x00000001)`, and
/// `Binary Data` for anything that is not a string or an integer — so matching
/// it is what makes the 180 `Details` rules mean what they say.
///
/// Returns `None` when there is nothing to render, which is the caller's signal
/// to fall back to the value name.
pub(super) fn format_value_data(value_type: u32, data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let rendered = match value_type {
        REG_SZ | REG_EXPAND_SZ | REG_LINK => decode_utf16(data),
        REG_MULTI_SZ => decode_utf16(data)
            .split('\0')
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        REG_DWORD => format!("DWORD (0x{:08X})", u32::from_le_bytes(first_bytes(data)?)),
        REG_DWORD_BIG_ENDIAN => {
            format!("DWORD (0x{:08X})", u32::from_be_bytes(first_bytes(data)?))
        }
        REG_QWORD => format!("QWORD (0x{:016X})", u64::from_le_bytes(first_bytes(data)?)),
        // REG_NONE, REG_BINARY, and any type this build has never heard of.
        _ => "Binary Data".to_string(),
    };
    Some(rendered)
}

fn first_bytes<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    data.get(..N)?.try_into().ok()
}

/// Decode the UTF-16 payload of a string value, dropping the terminating NUL.
///
/// The embedded NULs of a `REG_MULTI_SZ` are kept for the caller to split on;
/// only the trailing ones go.
fn decode_utf16(data: &[u8]) -> String {
    let (pairs, _odd_trailing_byte) = data.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

/// Formatting is pure and the interesting cases are the value types, so it is
/// tested here; the [`request_value_data`] side needs a live session and is
/// covered by the `Details` assertion in [`super::etw`]'s test module only in
/// so far as its fallback is.
#[cfg(test)]
mod tests {
    use super::*;

    const REG_NONE: u32 = 0;
    const REG_BINARY: u32 = 3;

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }

    #[test]
    fn string_data_is_the_value_not_the_name() {
        assert_eq!(
            format_value_data(REG_SZ, &utf16("powershell -enc SQBFAFgA")).as_deref(),
            Some("powershell -enc SQBFAFgA"),
            "a `Details|contains: 'powershell'` rule has to see the payload"
        );
    }

    #[test]
    fn expand_sz_drops_only_the_terminator() {
        assert_eq!(
            format_value_data(REG_EXPAND_SZ, &utf16("%SystemRoot%\\system32\\evil.exe")).as_deref(),
            Some("%SystemRoot%\\system32\\evil.exe")
        );
    }

    #[test]
    fn integers_use_the_sysmon_spelling() {
        // Rules match this string literally, e.g. `Details: 'DWORD (0x00000001)'`.
        assert_eq!(
            format_value_data(REG_DWORD, &1u32.to_le_bytes()).as_deref(),
            Some("DWORD (0x00000001)")
        );
        assert_eq!(
            format_value_data(REG_DWORD_BIG_ENDIAN, &1u32.to_be_bytes()).as_deref(),
            Some("DWORD (0x00000001)")
        );
        assert_eq!(
            format_value_data(REG_QWORD, &255u64.to_le_bytes()).as_deref(),
            Some("QWORD (0x00000000000000FF)")
        );
    }

    #[test]
    fn multi_sz_entries_are_separated() {
        let mut data = utf16("first");
        data.extend(utf16("second"));
        data.extend([0, 0]);
        assert_eq!(
            format_value_data(REG_MULTI_SZ, &data).as_deref(),
            Some("first\nsecond")
        );
    }

    #[test]
    fn binary_matches_sysmon_rather_than_dumping_hex() {
        assert_eq!(
            format_value_data(REG_BINARY, &[0xDE, 0xAD, 0xBE, 0xEF]).as_deref(),
            Some("Binary Data")
        );
        assert_eq!(
            format_value_data(REG_NONE, &[0x00]).as_deref(),
            Some("Binary Data")
        );
        assert_eq!(
            format_value_data(0xFFFF, &[0x00]).as_deref(),
            Some("Binary Data"),
            "an unknown type must still not be reported as a string"
        );
    }

    #[test]
    fn empty_capture_asks_the_caller_to_fall_back() {
        // The build may not populate `CapturedData` at all; that path has to
        // keep the pre-#292 value-name behaviour rather than emit nothing.
        assert_eq!(format_value_data(REG_SZ, &[]), None);
        assert_eq!(format_value_data(REG_DWORD, &[]), None);
    }

    #[test]
    fn truncated_integer_data_is_not_rendered_as_a_number() {
        assert_eq!(format_value_data(REG_DWORD, &[0x01, 0x00]), None);
        assert_eq!(
            format_value_data(REG_QWORD, &[0x01, 0x00, 0x00, 0x00]),
            None
        );
    }

    #[test]
    fn event_id_filter_has_the_documented_layout() {
        let filter = event_id_filter(&[1, 2, 5]);
        assert_eq!(filter, vec![1, 3, 1, 2, 5]);
        assert_eq!(
            std::mem::size_of_val(filter.as_slice()),
            size_of::<u16>() * 5
        );
    }
}
