//! Attach and sample bounded activity maps without producing file events.

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, PerCpuArray};
use rustinel_ebpf_common::activity_abi::{
    ActivityLoss, ActivityProcessKey, IA32_FILE_ACTIVITY_INDEX, IO_URING_ACTIVITY_INDEX,
};
use tracing::warn;

use super::{try_attach_tracepoint, LinuxEbpfCounters, LoadedEbpf};
use crate::telemetry::{LinuxActivityProcessSnapshot, LinuxActivitySnapshot};

pub(super) struct ActivityMonitor {
    sources: Vec<ActivitySource>,
    loss: PerCpuArray<MapData, ActivityLoss>,
}

struct ActivitySource {
    kind: &'static str,
    index: u32,
    counts: HashMap<MapData, ActivityProcessKey, u64>,
}

struct SourceSpec {
    feature: &'static str,
    program: &'static str,
    map: &'static str,
    kind: &'static str,
    index: u32,
}

const IO_URING: SourceSpec = SourceSpec {
    feature: "io_uring_activity",
    program: "handle_io_uring_submit",
    map: "IO_URING_ACTIVITY",
    kind: "io_uring_submissions",
    index: IO_URING_ACTIVITY_INDEX,
};

const IA32_FILE: SourceSpec = SourceSpec {
    feature: "ia32_file_activity",
    program: "handle_ia32_file_exit",
    map: "IA32_FILE_ACTIVITY",
    kind: "ia32_file_syscalls",
    index: IA32_FILE_ACTIVITY_INDEX,
};

impl ActivityMonitor {
    pub(super) fn attach(
        bpf: &mut LoadedEbpf,
        io_uring: Result<&str>,
        ia32: Result<()>,
    ) -> Result<Self> {
        let mut sources = Vec::new();
        for (spec, tracepoint) in [
            (IO_URING, io_uring.map(|name| ("io_uring", name))),
            (IA32_FILE, ia32.map(|()| ("raw_syscalls", "sys_exit"))),
        ] {
            let attached = tracepoint.and_then(|(category, name)| {
                try_attach_tracepoint(bpf, spec.program, category, name)
            });
            match attached {
                Ok(()) => {
                    bpf.counters()
                        .record_hook(spec.feature, spec.program, true, None);
                    sources.push(ActivitySource {
                        kind: spec.kind,
                        index: spec.index,
                        counts: HashMap::try_from(bpf.take_map(spec.map).with_context(|| {
                            format!("missing Linux activity map {}", spec.map)
                        })?)?,
                    });
                }
                Err(error) => {
                    let reason = format!("{error:#}");
                    bpf.counters()
                        .record_hook(spec.feature, spec.program, false, Some(&reason));
                    warn!(feature = spec.feature, %reason, "Linux activity hook unavailable");
                }
            }
        }
        let loss = PerCpuArray::try_from(
            bpf.take_map("ACTIVITY_LOSS")
                .context("missing Linux activity loss map")?,
        )?;
        Ok(Self { sources, loss })
    }

    pub(super) fn refresh(&self, telemetry: &LinuxEbpfCounters) {
        let snapshots = self
            .sources
            .iter()
            .filter_map(|source| match self.sample(source) {
                Ok(snapshot) => Some(snapshot),
                Err(error) => {
                    warn!(kind = source.kind, %error, "Failed to read Linux activity counters");
                    None
                }
            })
            .collect();
        telemetry.set_activity(snapshots);
    }

    fn sample(&self, source: &ActivitySource) -> Result<LinuxActivitySnapshot> {
        let counts = source.counts.iter().collect::<Result<Vec<_>, _>>()?;
        let loss = self.loss.get(&source.index, 0)?;
        Ok(snapshot(source.kind, counts, loss.iter().copied()))
    }
}

fn snapshot(
    kind: &str,
    counts: impl IntoIterator<Item = (ActivityProcessKey, u64)>,
    loss: impl IntoIterator<Item = ActivityLoss>,
) -> LinuxActivitySnapshot {
    let mut processes: Vec<_> = counts
        .into_iter()
        .map(|(key, count)| LinuxActivityProcessSnapshot {
            pid: key.pid,
            process_start_time: key.process_start_time,
            count,
        })
        .collect();
    processes.sort_unstable_by_key(|row| (row.pid, row.process_start_time));
    let mut sample = LinuxActivitySnapshot {
        kind: kind.to_owned(),
        unattributed: 0,
        map_full: 0,
        processes,
    };
    for cpu in loss {
        sample.unattributed = sample.unattributed.saturating_add(cpu.unattributed);
        sample.map_full = sample.map_full.saturating_add(cpu.map_full);
    }
    sample
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_uring_submissions_keep_process_lifetimes_and_loss_separate() {
        let key = |process_start_time| ActivityProcessKey {
            pid: 42,
            _pad: 0,
            process_start_time,
        };
        let row = snapshot(
            "io_uring_submissions",
            [(key(700), 3), (key(200), 5)],
            [
                ActivityLoss {
                    unattributed: 4,
                    map_full: 1,
                },
                ActivityLoss {
                    unattributed: 3,
                    map_full: 0,
                },
            ],
        );
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/linux_file_coverage/io_uring_activity.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(row).unwrap(), expected);
    }

    #[test]
    fn ia32_file_activity_classifies_synthetic_syscall_exits() {
        use rustinel_ebpf_common::activity_abi::{ia32_file_syscall, ia32_successful_exit};

        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            id: i64,
            status: u32,
            result: i64,
            counted: bool,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/linux_file_coverage/ia32_file_exit.json"
        ))
        .unwrap();
        for case in cases {
            assert_eq!(
                ia32_file_syscall(case.id) && ia32_successful_exit(case.status, case.result),
                case.counted,
                "{}",
                case.name
            );
        }
    }
}
