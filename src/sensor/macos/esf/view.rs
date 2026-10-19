//! The seam between Endpoint Security decoding and the OS.
//!
//! The `build_*_event` functions read a message through [`EsMessage`] instead
//! of the `endpoint-sec` types, which a test cannot construct. Production
//! implements it for the live [`Message`]; tests implement it for
//! [`EsRecord`], loaded from messages recorded on a real Mac.
//!
//! Everything a decoder reads is plain data here, so the same structs are the
//! recording format: [`EsRecord::capture`] copies a view and `serde` writes it.

use std::ffi::OsStr;

use endpoint_sec::{
    Event, EventCreateDestinationFile, EventRenameDestinationFile, Message, Process,
};
use serde::{Deserialize, Serialize};

/// A message's `timespec`, as read from the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EsTime {
    pub sec: i64,
    pub nsec: i64,
}

/// The `stat` fields the file identity is built from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EsStat {
    pub dev: i32,
    pub ino: u64,
    pub size: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl EsStat {
    fn from_libc(stat: &libc::stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            size: stat.st_size,
            mtime_sec: stat.st_mtime,
            mtime_nsec: stat.st_mtime_nsec,
            ctime_sec: stat.st_ctime,
            ctime_nsec: stat.st_ctime_nsec,
        }
    }

    pub(crate) fn to_libc(self) -> libc::stat {
        // SAFETY: libc::stat is a plain C struct that admits the zero value.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        stat.st_dev = self.dev;
        stat.st_ino = self.ino;
        stat.st_size = self.size;
        stat.st_mtime = self.mtime_sec;
        stat.st_mtime_nsec = self.mtime_nsec;
        stat.st_ctime = self.ctime_sec;
        stat.st_ctime_nsec = self.ctime_nsec;
        stat
    }
}

/// A file ESF names: its path and the `stat` it captured.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EsFile {
    pub path: String,
    pub stat: EsStat,
}

/// The acting process of any message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EsActor {
    pub pid: i32,
    pub pidversion: i32,
    pub euid: u32,
    pub executable: String,
    /// Process start, nanoseconds since the Unix epoch.
    pub start_time_ns: Option<u64>,
}

/// The process an exec event starts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EsTarget {
    pub pid: i32,
    pub pidversion: i32,
    pub euid: u32,
    pub ruid: u32,
    pub ppid: i32,
    pub original_ppid: i32,
    /// `(pid, pidversion)` of the parent, absent below message version 4.
    pub parent_token: Option<(i32, i32)>,
    pub executable: EsFile,
    pub start_time_ns: Option<u64>,
    pub codesigning_flags: u32,
    pub signing_id: String,
    pub team_id: String,
    /// Hex of the 20 byte code directory hash.
    pub cdhash: String,
    pub is_platform_binary: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EsExec {
    pub target: EsTarget,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub script: Option<String>,
}

/// Where a create or rename lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum EsDestination {
    ExistingFile(EsFile),
    NewPath { directory: String, filename: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum EsEvent {
    Exec(EsExec),
    Exit,
    Create {
        destination: Option<EsDestination>,
    },
    Unlink {
        target: EsFile,
    },
    Rename {
        source: EsFile,
        destination: Option<EsDestination>,
    },
    Close {
        modified: bool,
        target: EsFile,
    },
}

/// What the decoders read from one Endpoint Security message.
pub(crate) trait EsMessage {
    fn raw_time(&self) -> EsTime;
    fn global_seq_num(&self) -> Option<u64>;
    fn actor(&self) -> EsActor;
    /// `None` for an event class the sensor does not map.
    fn event(&self) -> Option<EsEvent>;
}

fn text(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn start_nanos(process: &Process<'_>) -> Option<u64> {
    process.start_time().map(super::system_time_nanos)
}

fn file(file: &endpoint_sec::File<'_>) -> EsFile {
    EsFile {
        path: text(file.path()),
        stat: EsStat::from_libc(file.stat()),
    }
}

impl EsMessage for Message {
    fn raw_time(&self) -> EsTime {
        let time = Message::raw_time(self);
        EsTime {
            sec: time.tv_sec,
            nsec: time.tv_nsec,
        }
    }

    fn global_seq_num(&self) -> Option<u64> {
        Message::global_seq_num(self)
    }

    fn actor(&self) -> EsActor {
        let process = self.process();
        let token = process.audit_token();
        EsActor {
            pid: token.pid(),
            pidversion: token.pidversion(),
            euid: token.euid(),
            executable: text(process.executable().path()),
            start_time_ns: start_nanos(&process),
        }
    }

    fn event(&self) -> Option<EsEvent> {
        Some(match Message::event(self)? {
            Event::NotifyExec(exec) => {
                let target = exec.target();
                let token = target.audit_token();
                EsEvent::Exec(EsExec {
                    target: EsTarget {
                        pid: token.pid(),
                        pidversion: token.pidversion(),
                        euid: token.euid(),
                        ruid: token.ruid(),
                        ppid: target.ppid(),
                        original_ppid: target.original_ppid(),
                        parent_token: target
                            .parent_audit_token()
                            .map(|token| (token.pid(), token.pidversion())),
                        executable: file(&target.executable()),
                        start_time_ns: start_nanos(&target),
                        codesigning_flags: target.codesigning_flags(),
                        signing_id: text(target.signing_id()),
                        team_id: text(target.team_id()),
                        cdhash: hex::encode(target.cdhash()),
                        is_platform_binary: target.is_platform_binary(),
                    },
                    args: exec.args().map(text).collect(),
                    cwd: exec.cwd().map(|cwd| text(cwd.path())),
                    script: exec.script().map(|script| text(script.path())),
                })
            }
            Event::NotifyExit(_) => EsEvent::Exit,
            Event::NotifyCreate(create) => EsEvent::Create {
                destination: create.destination().and_then(|dest| match dest {
                    EventCreateDestinationFile::ExistingFile { file: f, .. } => {
                        Some(EsDestination::ExistingFile(file(&f)))
                    }
                    EventCreateDestinationFile::NewPath {
                        directory,
                        filename,
                        ..
                    } => Some(EsDestination::NewPath {
                        directory: text(directory.path()),
                        filename: text(filename),
                    }),
                    _ => None,
                }),
            },
            Event::NotifyUnlink(unlink) => EsEvent::Unlink {
                target: file(&unlink.target()),
            },
            Event::NotifyRename(rename) => EsEvent::Rename {
                source: file(&rename.source()),
                destination: rename.destination().and_then(|dest| match dest {
                    EventRenameDestinationFile::ExistingFile { file: f, .. } => {
                        Some(EsDestination::ExistingFile(file(&f)))
                    }
                    EventRenameDestinationFile::NewPath {
                        directory,
                        filename,
                        ..
                    } => Some(EsDestination::NewPath {
                        directory: text(directory.path()),
                        filename: text(filename),
                    }),
                    _ => None,
                }),
            },
            Event::NotifyClose(close) => EsEvent::Close {
                modified: close.modified(),
                target: file(&close.target()),
            },
            _ => return None,
        })
    }
}

/// One recorded message: the owned form of an [`EsMessage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EsRecord {
    pub time: EsTime,
    pub global_seq_num: Option<u64>,
    pub actor: EsActor,
    pub event: EsEvent,
}

impl EsRecord {
    /// Copy everything the decoders read, or `None` for an unmapped event.
    pub(crate) fn capture(msg: &impl EsMessage) -> Option<Self> {
        Some(Self {
            time: msg.raw_time(),
            global_seq_num: msg.global_seq_num(),
            actor: msg.actor(),
            event: msg.event()?,
        })
    }
}

impl EsMessage for EsRecord {
    fn raw_time(&self) -> EsTime {
        self.time
    }

    fn global_seq_num(&self) -> Option<u64> {
        self.global_seq_num
    }

    fn actor(&self) -> EsActor {
        self.actor.clone()
    }

    fn event(&self) -> Option<EsEvent> {
        Some(self.event.clone())
    }
}
