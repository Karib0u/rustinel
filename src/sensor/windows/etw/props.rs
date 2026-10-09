//! The seam between ETW decoding and the OS.
//!
//! Decoders read a record's header and its named properties through
//! [`EtwHeader`] and [`EtwProperties`] instead of ferrisetw's `EventRecord` and
//! `Parser`, neither of which a test can construct. Production implements them
//! for ferrisetw; tests implement them for [`fixture::FixtureRecord`], loaded
//! from properties recorded on a real host.
//!
//! The typed getters mirror ferrisetw's rules rather than an idealised model: a
//! primitive parse succeeds for any property of the same byte width, so a
//! 4-byte property is a `u32` to `get_u32` whatever its manifest type. That is
//! what the decoders were written against, so the fixtures exercise it too.

use ferrisetw::parser::Parser;
use ferrisetw::{EventRecord, GUID};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Header fields every decoder may consult.
pub(crate) trait EtwHeader {
    fn provider_id(&self) -> GUID;
    fn event_id(&self) -> u16;
    fn opcode(&self) -> u8;
    fn version(&self) -> u8;
    fn process_id(&self) -> u32;
    fn raw_timestamp(&self) -> i64;
}

impl EtwHeader for EventRecord {
    fn provider_id(&self) -> GUID {
        EventRecord::provider_id(self)
    }
    fn event_id(&self) -> u16 {
        EventRecord::event_id(self)
    }
    fn opcode(&self) -> u8 {
        EventRecord::opcode(self)
    }
    fn version(&self) -> u8 {
        EventRecord::version(self)
    }
    fn process_id(&self) -> u32 {
        EventRecord::process_id(self)
    }
    fn raw_timestamp(&self) -> i64 {
        EventRecord::raw_timestamp(self)
    }
}

/// Typed, name-addressed access to one record's payload.
///
/// Every getter is `None` when the property is absent or has the wrong width,
/// never a panic: providers add and drop properties between versions.
pub(crate) trait EtwProperties {
    fn get_string(&self, name: &str) -> Option<String>;
    fn get_u8(&self, name: &str) -> Option<u8>;
    fn get_u16(&self, name: &str) -> Option<u16>;
    fn get_u32(&self, name: &str) -> Option<u32>;
    fn get_u64(&self, name: &str) -> Option<u64>;
    fn get_i64(&self, name: &str) -> Option<i64>;
    fn get_ip(&self, name: &str) -> Option<IpAddr>;
    fn get_bytes(&self, name: &str) -> Option<Vec<u8>>;
}

impl EtwProperties for Parser<'_, '_> {
    fn get_string(&self, name: &str) -> Option<String> {
        self.try_parse::<String>(name).ok()
    }
    fn get_u8(&self, name: &str) -> Option<u8> {
        self.try_parse::<u8>(name).ok()
    }
    fn get_u16(&self, name: &str) -> Option<u16> {
        self.try_parse::<u16>(name).ok()
    }
    fn get_u32(&self, name: &str) -> Option<u32> {
        self.try_parse::<u32>(name).ok()
    }
    fn get_u64(&self, name: &str) -> Option<u64> {
        self.try_parse::<u64>(name).ok()
    }
    fn get_i64(&self, name: &str) -> Option<i64> {
        self.try_parse::<i64>(name).ok()
    }
    fn get_ip(&self, name: &str) -> Option<IpAddr> {
        self.try_parse::<IpAddr>(name).ok()
    }
    fn get_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.try_parse::<Vec<u8>>(name).ok()
    }
}

/// One property as a decoder saw it.
///
/// Integers keep their byte width because that, not signedness, decides which
/// getter succeeds. `U64` also satisfies `get_i64`, as in ferrisetw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecordedValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    String(String),
    Ip(IpAddr),
    /// Lower-case hex, so a binary property stays readable in a diff.
    Bytes(String),
}

impl RecordedValue {
    fn raw_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::U8(v) => Some(v.to_ne_bytes().to_vec()),
            Self::U16(v) => Some(v.to_ne_bytes().to_vec()),
            Self::U32(v) => Some(v.to_ne_bytes().to_vec()),
            Self::U64(v) => Some(v.to_ne_bytes().to_vec()),
            Self::Bytes(hex) => hex::decode(hex).ok(),
            Self::String(_) | Self::Ip(_) => None,
        }
    }
}

/// A property set backed by a map: the test-side [`EtwProperties`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct RecordedProperties(pub(super) BTreeMap<String, RecordedValue>);

impl EtwProperties for RecordedProperties {
    fn get_string(&self, name: &str) -> Option<String> {
        match self.0.get(name)? {
            RecordedValue::String(value) => Some(value.clone()),
            _ => None,
        }
    }
    fn get_u8(&self, name: &str) -> Option<u8> {
        match self.0.get(name)? {
            RecordedValue::U8(value) => Some(*value),
            _ => None,
        }
    }
    fn get_u16(&self, name: &str) -> Option<u16> {
        match self.0.get(name)? {
            RecordedValue::U16(value) => Some(*value),
            _ => None,
        }
    }
    fn get_u32(&self, name: &str) -> Option<u32> {
        match self.0.get(name)? {
            RecordedValue::U32(value) => Some(*value),
            _ => None,
        }
    }
    fn get_u64(&self, name: &str) -> Option<u64> {
        match self.0.get(name)? {
            RecordedValue::U64(value) => Some(*value),
            _ => None,
        }
    }
    fn get_i64(&self, name: &str) -> Option<i64> {
        self.get_u64(name).map(|value| value as i64)
    }
    fn get_ip(&self, name: &str) -> Option<IpAddr> {
        match self.0.get(name)? {
            RecordedValue::Ip(value) => Some(*value),
            _ => None,
        }
    }
    fn get_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.0.get(name)?.raw_bytes()
    }
}

/// Header fields as recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RecordedHeader {
    pub(super) provider: GuidText,
    pub(super) event_id: u16,
    pub(super) opcode: u8,
    pub(super) version: u8,
    pub(super) process_id: u32,
    pub(super) timestamp: i64,
}

/// One record as saved by the recorder and loaded by the fixture tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RecordedRecord {
    pub(super) header: RecordedHeader,
    pub(super) properties: RecordedProperties,
}

/// A GUID that serializes as its canonical string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GuidText(pub(super) GUID);

impl Serialize for GuidText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let g = &self.0;
        serializer.serialize_str(&format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            g.data1,
            g.data2,
            g.data3,
            g.data4[0],
            g.data4[1],
            g.data4[2],
            g.data4[3],
            g.data4[4],
            g.data4[5],
            g.data4[6],
            g.data4[7],
        ))
    }
}

impl<'de> Deserialize<'de> for GuidText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let trimmed = text.trim_matches(|c| c == '{' || c == '}');
        let mut parts = trimmed.split('-');
        let mut next = |len: usize| -> Result<u128, D::Error> {
            let part = parts
                .next()
                .filter(|part| part.len() == len)
                .ok_or_else(|| serde::de::Error::custom(format!("bad GUID {text:?}")))?;
            u128::from_str_radix(part, 16).map_err(serde::de::Error::custom)
        };
        let (d1, d2, d3, d4, d5) = (next(8)?, next(4)?, next(4)?, next(4)?, next(12)?);
        let tail = ((d4 << 48) | d5).to_be_bytes();
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&tail[8..]);
        Ok(Self(GUID::from_values(
            d1 as u32, d2 as u16, d3 as u16, data4,
        )))
    }
}

impl EtwHeader for RecordedHeader {
    fn provider_id(&self) -> GUID {
        self.provider.0
    }
    fn event_id(&self) -> u16 {
        self.event_id
    }
    fn opcode(&self) -> u8 {
        self.opcode
    }
    fn version(&self) -> u8 {
        self.version
    }
    fn process_id(&self) -> u32 {
        self.process_id
    }
    fn raw_timestamp(&self) -> i64 {
        self.timestamp
    }
}

/// The live [`EtwProperties`]: ferrisetw's parser, optionally noting every
/// property a decoder successfully reads so the record can be saved as a
/// fixture (see [`recorder`]).
pub(super) struct LiveProperties<'a, 'b, 'c> {
    parser: &'c Parser<'a, 'b>,
    seen: Option<RefCell<BTreeMap<String, RecordedValue>>>,
}

impl<'a, 'b, 'c> LiveProperties<'a, 'b, 'c> {
    pub(super) fn new(parser: &'c Parser<'a, 'b>) -> Self {
        Self {
            parser,
            seen: recorder::enabled().then(|| RefCell::new(BTreeMap::new())),
        }
    }

    /// Append this record to the recording, if one is active.
    pub(super) fn finish(self, header: &impl EtwHeader) {
        if let Some(seen) = self.seen {
            recorder::write(header, RecordedProperties(seen.into_inner()));
        }
    }

    fn note(&self, name: &str, value: RecordedValue) {
        if let Some(seen) = &self.seen {
            seen.borrow_mut().entry(name.to_string()).or_insert(value);
        }
    }
}

impl EtwProperties for LiveProperties<'_, '_, '_> {
    fn get_string(&self, name: &str) -> Option<String> {
        let value = self.parser.get_string(name)?;
        self.note(name, RecordedValue::String(value.clone()));
        Some(value)
    }
    fn get_u8(&self, name: &str) -> Option<u8> {
        let value = self.parser.get_u8(name)?;
        self.note(name, RecordedValue::U8(value));
        Some(value)
    }
    fn get_u16(&self, name: &str) -> Option<u16> {
        let value = self.parser.get_u16(name)?;
        self.note(name, RecordedValue::U16(value));
        Some(value)
    }
    fn get_u32(&self, name: &str) -> Option<u32> {
        let value = self.parser.get_u32(name)?;
        self.note(name, RecordedValue::U32(value));
        Some(value)
    }
    fn get_u64(&self, name: &str) -> Option<u64> {
        let value = self.parser.get_u64(name)?;
        self.note(name, RecordedValue::U64(value));
        Some(value)
    }
    fn get_i64(&self, name: &str) -> Option<i64> {
        let value = self.parser.get_i64(name)?;
        self.note(name, RecordedValue::U64(value as u64));
        Some(value)
    }
    fn get_ip(&self, name: &str) -> Option<IpAddr> {
        let value = self.parser.get_ip(name)?;
        self.note(name, RecordedValue::Ip(value));
        Some(value)
    }
    fn get_bytes(&self, name: &str) -> Option<Vec<u8>> {
        let value = self.parser.get_bytes(name)?;
        self.note(name, RecordedValue::Bytes(hex::encode(&value)));
        Some(value)
    }
}

/// Fixture recording: `RUSTINEL_ETW_RECORD=<file>` appends one JSON object per
/// decoded record, holding the header and every property the decoders read.
///
/// This is a developer tool for building the fixtures under
/// `tests/fixtures/etw`; see `docs/development.md`. It is off unless the
/// variable is set, and capped by `RUSTINEL_ETW_RECORD_MAX` (default 5000) so a
/// forgotten variable cannot fill a disk.
///
/// Recording only happens while a file named `<file>.on` exists, so a workload
/// can bracket the records it wants out of the machine's background noise.
pub(super) mod recorder {
    use super::{EtwHeader, GuidText, RecordedHeader, RecordedProperties, RecordedRecord};
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};

    const DEFAULT_MAX_RECORDS: usize = 5000;

    struct Recorder {
        gate: std::path::PathBuf,
        /// Milliseconds since `started` at which the gate was last checked,
        /// plus one; zero means never.
        checked_at: AtomicU64,
        open: std::sync::atomic::AtomicBool,
        started: std::time::Instant,
        file: Mutex<File>,
        written: AtomicUsize,
        max: usize,
    }

    impl Recorder {
        /// Whether the gate file exists, looked up at most every 50 ms.
        fn gate_open(&self) -> bool {
            let now = self.started.elapsed().as_millis() as u64 + 1;
            let last = self.checked_at.load(Ordering::Relaxed);
            if last == 0 || now.saturating_sub(last) >= 50 {
                self.checked_at.store(now, Ordering::Relaxed);
                self.open.store(self.gate.exists(), Ordering::Relaxed);
            }
            self.open.load(Ordering::Relaxed)
        }
    }

    fn recorder() -> Option<&'static Recorder> {
        static RECORDER: OnceLock<Option<Recorder>> = OnceLock::new();
        RECORDER
            .get_or_init(|| {
                let path = std::env::var_os("RUSTINEL_ETW_RECORD")?;
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .map_err(|err| {
                        tracing::warn!("ETW recording disabled, cannot open {path:?}: {err}")
                    })
                    .ok()?;
                let max = std::env::var("RUSTINEL_ETW_RECORD_MAX")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(DEFAULT_MAX_RECORDS);
                tracing::warn!(
                    "Recording ETW records to {path:?} (max {max}); \
                     this is a developer tool and captures command lines and paths"
                );
                let gate = std::path::PathBuf::from(format!("{}.on", path.to_string_lossy()));
                Some(Recorder {
                    gate,
                    checked_at: AtomicU64::new(0),
                    open: std::sync::atomic::AtomicBool::new(false),
                    started: std::time::Instant::now(),
                    file: Mutex::new(file),
                    written: AtomicUsize::new(0),
                    max,
                })
            })
            .as_ref()
    }

    pub(in super::super) fn enabled() -> bool {
        recorder().is_some_and(|r| r.written.load(Ordering::Relaxed) < r.max && r.gate_open())
    }

    pub(in super::super) fn write(header: &impl EtwHeader, properties: RecordedProperties) {
        let Some(recorder) = recorder() else { return };
        if !recorder.gate_open() {
            return;
        }
        if recorder.written.fetch_add(1, Ordering::Relaxed) >= recorder.max {
            return;
        }
        let record = RecordedRecord {
            header: RecordedHeader {
                provider: GuidText(header.provider_id()),
                event_id: header.event_id(),
                opcode: header.opcode(),
                version: header.version(),
                process_id: header.process_id(),
                timestamp: header.raw_timestamp(),
            },
            properties,
        };
        let Ok(line) = serde_json::to_string(&record) else {
            return;
        };
        let mut file = recorder.file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(file, "{line}");
    }
}
