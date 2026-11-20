//! Attach and sample bounded activity maps without producing file events.

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, PerCpuArray};
use rustinel_ebpf_common::activity_abi::{
    ActivityLoss, ActivityProcessKey, IO_URING_ACTIVITY_INDEX,
};
use tracing::warn;

use super::{try_attach_tracepoint, LinuxEbpfCounters, LoadedEbpf};
use crate::telemetry::{LinuxActivityProcessSnapshot, LinuxActivitySnapshot};

const IO_URING_FEATURE: &str = "io_uring_activity";
const IO_URING_PROGRAM: &str = "handle_io_uring_submit";

pub(super) struct ActivityMonitor {
    sources: Vec<ActivitySource>,
    loss: PerCpuArray<MapData, ActivityLoss>,
}

struct ActivitySource {
    kind: &'static str,
    index: u32,
    counts: HashMap<MapData, ActivityProcessKey, u64>,
}

impl ActivityMonitor {
    pub(super) fn attach(bpf: &mut LoadedEbpf, io_uring: Result<(&str, u32)>) -> Result<Self> {
        let mut sources = Vec::new();
        let attached = io_uring.and_then(|(tracepoint, _)| {
            try_attach_tracepoint(bpf, IO_URING_PROGRAM, "io_uring", tracepoint)
        });
        match attached {
            Ok(()) => {
                bpf.counters()
                    .record_hook(IO_URING_FEATURE, IO_URING_PROGRAM, true, None);
                sources.push(ActivitySource {
                    kind: "io_uring_submissions",
                    index: IO_URING_ACTIVITY_INDEX,
                    counts: HashMap::try_from(
                        bpf.take_map("IO_URING_ACTIVITY")
                            .context("missing io_uring activity map")?,
                    )?,
                });
            }
            Err(error) => {
                let reason = format!("{error:#}");
                bpf.counters().record_hook(
                    IO_URING_FEATURE,
                    IO_URING_PROGRAM,
                    false,
                    Some(&reason),
                );
                warn!(feature = IO_URING_FEATURE, %reason, "Linux activity hook unavailable");
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
}
