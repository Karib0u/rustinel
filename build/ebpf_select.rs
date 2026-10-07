//! Which eBPF object `build.rs` embeds.
//!
//! The decision is a pure function of its inputs so it can be unit-tested; the
//! build script gathers the inputs and acts on the result. The file is shared
//! by `build.rs` and, under `cfg(test)`, by the Linux sensor module.

use std::time::SystemTime;

/// Where the embedded object comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectSource {
    /// `ebpf/rustinel-ebpf.o`, built earlier and not older than the sources.
    Prebuilt,
    /// Compiled from `ebpf/` and `ebpf-common/` with the nightly toolchain.
    Source,
    /// A bare ELF header with no programs. Never suitable for live telemetry.
    Stub,
}

impl ObjectSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prebuilt => "prebuilt",
            Self::Source => "source",
            Self::Stub => "stub",
        }
    }
}

/// Facts the build script collects before choosing.
#[derive(Debug, Clone, Copy)]
pub struct Inputs {
    /// `RUSTINEL_EBPF_STUB=1`.
    pub stub_requested: bool,
    /// `RUSTINEL_EBPF_PREBUILT=1`: use the prebuilt object whatever its age.
    pub prebuilt_forced: bool,
    /// Modification time of `ebpf/rustinel-ebpf.o`, when the file exists.
    pub prebuilt_modified: Option<SystemTime>,
    /// Newest modification time under the eBPF inputs, when any could be read.
    pub newest_input_modified: Option<SystemTime>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Selection {
    pub source: ObjectSource,
    /// Shown as a `cargo:warning`, so the choice is visible in build output.
    pub warning: Option<String>,
}

/// Precedence, highest first:
///
/// 1. `RUSTINEL_EBPF_STUB=1` selects the stub. Combining it with
///    `RUSTINEL_EBPF_PREBUILT=1` is a contradiction and is an error.
/// 2. `RUSTINEL_EBPF_PREBUILT=1` requires the prebuilt object and uses it
///    whatever its age, which is what CI sets after downloading the artifact.
/// 3. A prebuilt object that is not older than every eBPF input is used.
/// 4. Otherwise the object is compiled from source. A stale prebuilt object is
///    ignored with a warning, because it would silently embed old programs.
pub fn select(inputs: Inputs) -> Result<Selection, String> {
    if inputs.stub_requested {
        if inputs.prebuilt_forced {
            return Err(
                "RUSTINEL_EBPF_STUB=1 and RUSTINEL_EBPF_PREBUILT=1 contradict each \
                        other; set only one"
                    .into(),
            );
        }
        return Ok(Selection {
            source: ObjectSource::Stub,
            warning: Some(
                "RUSTINEL_EBPF_STUB=1: embedding an eBPF stub with no programs; the sensor \
                 refuses to start with it"
                    .into(),
            ),
        });
    }

    if inputs.prebuilt_forced {
        return match inputs.prebuilt_modified {
            Some(_) => Ok(Selection {
                source: ObjectSource::Prebuilt,
                warning: None,
            }),
            None => Err("RUSTINEL_EBPF_PREBUILT=1 but ebpf/rustinel-ebpf.o does not exist".into()),
        };
    }

    match (inputs.prebuilt_modified, inputs.newest_input_modified) {
        (Some(object), Some(newest)) if object < newest => Ok(Selection {
            source: ObjectSource::Source,
            warning: Some(
                "ignoring ebpf/rustinel-ebpf.o: it is older than the eBPF sources, so it would \
                 embed stale programs; building from source (delete the file or set \
                 RUSTINEL_EBPF_PREBUILT=1 to silence this)"
                    .into(),
            ),
        }),
        (Some(_), _) => Ok(Selection {
            source: ObjectSource::Prebuilt,
            warning: None,
        }),
        (None, _) => Ok(Selection {
            source: ObjectSource::Source,
            warning: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> Option<SystemTime> {
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    fn inputs() -> Inputs {
        Inputs {
            stub_requested: false,
            prebuilt_forced: false,
            prebuilt_modified: None,
            newest_input_modified: at(100),
        }
    }

    #[test]
    fn no_prebuilt_object_builds_from_source() {
        let chosen = select(inputs()).unwrap();
        assert_eq!(chosen.source, ObjectSource::Source);
        assert_eq!(chosen.warning, None);
    }

    #[test]
    fn a_prebuilt_object_newer_than_the_sources_is_used() {
        let chosen = select(Inputs {
            prebuilt_modified: at(200),
            ..inputs()
        })
        .unwrap();
        assert_eq!(chosen.source, ObjectSource::Prebuilt);
    }

    #[test]
    fn changing_an_ebpf_source_makes_the_prebuilt_object_stale() {
        let fresh = Inputs {
            prebuilt_modified: at(200),
            ..inputs()
        };
        assert_eq!(select(fresh).unwrap().source, ObjectSource::Prebuilt);

        let edited = Inputs {
            newest_input_modified: at(300),
            ..fresh
        };
        let chosen = select(edited).unwrap();
        assert_eq!(chosen.source, ObjectSource::Source);
        assert!(chosen.warning.unwrap().contains("stale"));
    }

    #[test]
    fn a_forced_prebuilt_object_is_used_whatever_its_age() {
        let chosen = select(Inputs {
            prebuilt_forced: true,
            prebuilt_modified: at(1),
            newest_input_modified: at(300),
            ..inputs()
        })
        .unwrap();
        assert_eq!(chosen.source, ObjectSource::Prebuilt);
        assert_eq!(chosen.warning, None);
    }

    #[test]
    fn forcing_a_missing_prebuilt_object_is_an_error() {
        let result = select(Inputs {
            prebuilt_forced: true,
            ..inputs()
        });
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn the_stub_wins_over_an_existing_prebuilt_object() {
        let chosen = select(Inputs {
            stub_requested: true,
            prebuilt_modified: at(200),
            ..inputs()
        })
        .unwrap();
        assert_eq!(chosen.source, ObjectSource::Stub);
        assert!(chosen.warning.is_some());
    }

    #[test]
    fn stub_and_forced_prebuilt_together_are_rejected() {
        let result = select(Inputs {
            stub_requested: true,
            prebuilt_forced: true,
            prebuilt_modified: at(200),
            ..inputs()
        });
        assert!(result.unwrap_err().contains("contradict"));
    }
}
