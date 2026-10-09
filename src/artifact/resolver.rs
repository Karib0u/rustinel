//! The resolver: one identity-validated open per artifact, fanned out to the
//! consumers that asked for its bytes, on a bounded pool of isolated I/O
//! threads.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info};

use super::io_pool::IoPool;
use super::job::{ArtifactJob, ResolveError, ResolvePlan, PE_MAX_READ_BYTES};
use super::snapshot::ResolverState;
use super::stores::StoredParts;
#[cfg(target_os = "linux")]
use super::target::open_linux_process_path;
use super::target::{
    arrival_identity, ArrivalIdentity, ArtifactKind, ArtifactTarget, ExpectedIdentity,
};
use super::written_file::{written_file_qualifies, WrittenFileSettler, WRITTEN_FILE_SETTLE_DELAY};
use super::{
    parse_imphash_bytes, parse_pe_metadata_bytes, Artifact, ArtifactOpener, ArtifactRuntime,
    PeMetadata,
};
use crate::ioc::{ComputedHashes, HashRequirements};
use crate::scanner::ScanError;
use crate::state::HostState;
use crate::utils::file_identity;

pub(super) const ARTIFACT_IO_ISOLATION_LIMIT: usize = 4;

#[derive(Clone)]
pub(super) struct ArtifactResolver {
    pub(super) host_state: Arc<HostState>,
    pub(super) runtime: ArtifactRuntime,
    pub(super) state: Arc<ResolverState>,
    /// How long a written file waits before it is opened. A field, not the
    /// constant, so a test can pick a delay that makes the scan timeout's
    /// ordering observable without racing the real clock.
    pub(super) settle_delay: Duration,
    #[cfg(target_os = "linux")]
    pub(super) process_path_opener: ArtifactOpener,
}

impl ArtifactResolver {
    pub(super) fn new(
        host_state: Arc<HostState>,
        runtime: ArtifactRuntime,
        state: Arc<ResolverState>,
    ) -> Self {
        Self {
            host_state,
            runtime,
            state,
            settle_delay: WRITTEN_FILE_SETTLE_DELAY,
            #[cfg(target_os = "linux")]
            process_path_opener: Arc::new(|path| open_linux_process_path(path, libc::O_PATH)),
        }
    }

    /// Resolve queued artifacts on up to [`ARTIFACT_IO_ISOLATION_LIMIT`] I/O
    /// threads. A thread blocked in the OS keeps its slot until the call
    /// returns; a job that cannot get a slot before its deadline is skipped.
    pub(super) fn run(&self, rx: &mut mpsc::Receiver<ArtifactJob>, open: ArtifactOpener) {
        self.run_queue(rx, open, false);
    }

    pub(super) fn run_queue(
        &self,
        rx: &mut mpsc::Receiver<ArtifactJob>,
        open: ArtifactOpener,
        written_files: bool,
    ) {
        info!(target: "artifact", written_files, "Artifact resolver worker started");
        // Each queue owns its slots. A blocked written-file open or scan
        // cannot delay images, even when every written-file slot is occupied.
        let mut pool = IoPool::new("artifact-io", ARTIFACT_IO_ISOLATION_LIMIT);
        let mut latest_deadline = Instant::now();
        let timer = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("artifact resolver timer runtime");
        let mut settling = WrittenFileSettler::new(self.settle_delay);
        let mut channel_closed = false;
        loop {
            let now = Instant::now();
            if let Some(job) = settling.pop_ready(now) {
                self.dispatch_job(job, &open, &mut pool, &mut latest_deadline);
                continue;
            }
            let wait = settling
                .next_deadline()
                .map(|deadline| deadline.saturating_duration_since(now));
            if channel_closed {
                let Some(wait) = wait else {
                    break;
                };
                std::thread::sleep(wait);
                continue;
            }
            // Keep receiving at capacity: duplicate writes still refresh the
            // debounce deadline, and vanished targets can free their slots.
            let received = match wait {
                Some(wait) => timer
                    .block_on(async { tokio::time::timeout(wait, rx.recv()).await })
                    .ok(),
                None => Some(timer.block_on(rx.recv())),
            };
            let job = match received {
                Some(Some(job)) => job,
                Some(None) => {
                    channel_closed = true;
                    continue;
                }
                None => continue,
            };
            if written_files {
                let Some(job) = self.measure_arrival_identity(job, &settling) else {
                    continue;
                };
                if settling.is_full_for(&job.target) {
                    let missing = settling.reclaim_missing(Path::try_exists);
                    // These files would fail to open after settling anyway.
                    // Count them as absent, not as scans shed under pressure.
                    self.state
                        .counters
                        .open_failed
                        .fetch_add(missing as u64, Ordering::Relaxed);
                }
                match settling.insert(job) {
                    Ok(true) => {
                        self.state
                            .counters
                            .written_file_coalesced
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(false) => {}
                    Err(job) => {
                        self.state.record_drop(job.target.kind);
                        self.state
                            .counters
                            .queue_saturated
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            } else {
                self.dispatch_job(job, &open, &mut pool, &mut latest_deadline);
            }
        }
        // In-flight work gets until its own deadline. A thread still blocked
        // in the OS after that is detached: a deadline cannot cancel it.
        pool.wait_idle(latest_deadline);
        info!(target: "artifact", "Artifact resolver worker stopped");
    }

    /// Bind a written-file job whose sensor reports no object identity to the
    /// object at its path now, before the settle delay. See
    /// [`super::target::measures_identity_on_arrival`]. Returns `None` for a job that cannot
    /// be bound, which is counted and skipped.
    fn measure_arrival_identity(
        &self,
        mut job: ArtifactJob,
        settling: &WrittenFileSettler,
    ) -> Option<ArtifactJob> {
        if job.target.expected.is_some() {
            return Some(job);
        }
        // Only a create or rename can put another object at the path, so a
        // write to a pending path keeps its object. This spares one open per
        // write, which a large file makes in the thousands.
        let measured = if job.target.content_write {
            settling.measured_object(&job.target.path)
        } else {
            None
        };
        let measured = match measured {
            Some(object) => ArrivalIdentity::Measured(object),
            None => arrival_identity(&job.target.path),
        };
        match measured {
            ArrivalIdentity::Measured(object) => {
                job.target.expected = Some(ExpectedIdentity::Object(object));
                job.target.measured_on_arrival = true;
                Some(job)
            }
            ArrivalIdentity::Unsupported => {
                self.state
                    .counters
                    .identity_unavailable
                    .fetch_add(1, Ordering::Relaxed);
                None
            }
            ArrivalIdentity::OpenFailed => {
                // Usually a temporary file already removed by its writer.
                self.state
                    .counters
                    .open_failed
                    .fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn dispatch_job(
        &self,
        mut job: ArtifactJob,
        open: &ArtifactOpener,
        pool: &mut IoPool,
        latest_deadline: &mut Instant,
    ) {
        let eligible_at = if job.target.kind == ArtifactKind::WrittenFile {
            job.enqueued_at
                .checked_add(self.settle_delay)
                .unwrap_or(job.enqueued_at)
        } else {
            job.enqueued_at
        };
        let deadline_at = eligible_at
            .checked_add(job.plan.deadline)
            .unwrap_or_else(Instant::now);
        // A cached identity needs no open and no I/O thread.
        if self.resolve_from_store(&mut job) {
            return;
        }
        let Some(slot) = pool.acquire(deadline_at) else {
            self.drop_late(job.target.kind);
            return;
        };
        if Instant::now() >= deadline_at {
            pool.release(slot);
            self.drop_late(job.target.kind);
            return;
        }

        let kind = job.target.kind;
        let resolver = self.clone();
        let open = Arc::clone(open);
        let submitted = pool.submit(slot, move || {
            resolver.resolve_job(job, deadline_at, |path| open(path));
        });
        match submitted {
            Ok(()) => *latest_deadline = (*latest_deadline).max(deadline_at),
            Err(error) => {
                self.state.record_drop(kind);
                self.state
                    .counters
                    .worker_saturated
                    .fetch_add(1, Ordering::Relaxed);
                debug!(target: "artifact", %error, "Could not isolate artifact I/O");
            }
        }
    }

    fn drop_late(&self, kind: ArtifactKind) {
        self.state.record_drop(kind);
        self.state
            .counters
            .deadline_exceeded
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Serve a job whose event carries the file's exact identity from the
    /// stores, without an open. Returns false when anything is missing, the
    /// file needs a live process check, or a consumer would alert, so the
    /// worker path handles it.
    fn resolve_from_store(&self, job: &mut ArtifactJob) -> bool {
        let Some(ExpectedIdentity::Exact(identity)) = job.target.expected.clone() else {
            return false;
        };
        if job.target.kind == ArtifactKind::WrittenFile
            || job.target.process_identity.is_some()
            || job.plan.max_read_bytes == 0
            || identity.size() > job.plan.max_read_bytes
        {
            return false;
        }
        let mut artifact = Artifact {
            identity: Some(identity.clone()),
            ..Artifact::default()
        };
        let mut missing = job.plan.needs;
        self.state
            .stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .load(&identity, &job.plan, &mut artifact, &mut missing);
        if !missing.is_empty()
            || artifact
                .yara
                .as_ref()
                .is_some_and(|matches| !matches.is_empty())
        {
            return false;
        }
        if let (Some(ioc), Some(hashes)) = (&job.plan.ioc, &artifact.hashes) {
            if !ioc.match_hashes(hashes).is_empty() {
                return false;
            }
        }
        if job.plan.needs.pe_metadata {
            self.publish_pe(job, artifact.pe_metadata.clone());
        }
        job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
        self.state
            .counters
            .cache_hits
            .fetch_add(1, Ordering::Relaxed);
        self.state.counters.resolved.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn resolve_job<F>(&self, mut job: ArtifactJob, deadline_at: Instant, open: F)
    where
        F: FnOnce(&Path) -> io::Result<File>,
    {
        let target = job.target.clone();
        let plan = job.plan.clone();
        match self.resolve_until_with_opener(
            &target,
            &plan,
            deadline_at,
            &AtomicBool::new(false),
            &mut job,
            open,
        ) {
            Ok(artifact) => {
                job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
                self.apply(&job, &artifact);
                self.state.counters.resolved.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                if matches!(error, ResolveError::Deadline(_)) {
                    self.state.record_drop(target.kind);
                }
                if let Some(hashes) = &job.resolved_hashes {
                    self.apply_hash_iocs(&job, hashes);
                }
                // Evaluate the deferred pass now rather than at its budget.
                job.publish_deferred(None, None);
                debug!(
                    target: "artifact",
                    file = %target.path.display(),
                    outcome = error.kind(),
                    error = %error,
                    "Artifact resolution did not complete"
                );
            }
        }
    }

    #[cfg(test)]
    pub(super) fn resolve_with_opener<F>(
        &self,
        target: &ArtifactTarget,
        plan: &ResolvePlan,
        open: F,
    ) -> Result<Artifact, ResolveError>
    where
        F: FnOnce(&Path) -> io::Result<File>,
    {
        let deadline_at = Instant::now()
            .checked_add(plan.deadline)
            .unwrap_or_else(Instant::now);
        let mut job = ArtifactJob {
            target: target.clone(),
            plan: plan.clone(),
            enqueued_at: Instant::now(),
            pe_ready: None,
            deferred_ready: None,
            resolved_pe: None,
            resolved_hashes: None,
            process_start_key: None,
            provenance: Default::default(),
            platform: crate::sensor::Platform::Linux,
            provider: "test".to_string(),
            written_file: None,
        };
        self.resolve_until_with_opener(
            target,
            plan,
            deadline_at,
            &AtomicBool::new(false),
            &mut job,
            open,
        )
    }

    fn identity_error(&self) -> ResolveError {
        self.state
            .counters
            .identity_mismatch
            .fetch_add(1, Ordering::Relaxed);
        ResolveError::Identity
    }

    /// False means an unavailable process with an identity-checked host fallback.
    /// A queried but mismatched lifetime never qualifies for that fallback.
    fn validate_process_target(&self, target: &ArtifactTarget) -> Result<bool, ResolveError> {
        let Some(expected) = &target.process_identity else {
            return Ok(true);
        };
        if expected.start_time.is_none() {
            return Err(self.identity_error());
        }
        if let Some(current) = crate::utils::query_process_identity(expected.pid) {
            expected
                .matches(&current)
                .map_err(|_| self.identity_error())?;
            return Ok(true);
        }
        #[cfg(target_os = "linux")]
        if matches!(target.expected, Some(ExpectedIdentity::Exact(_)))
            && target
                .linux_process_path
                .as_ref()
                .is_some_and(|context| context.host_fallback.is_some())
        {
            return Ok(false);
        }
        Err(self.identity_error())
    }

    pub(super) fn prepare_process_target(
        &self,
        target: &mut ArtifactTarget,
    ) -> Result<(), ResolveError> {
        let live = self.validate_process_target(target)?;
        #[cfg(target_os = "linux")]
        {
            let needs_path_resolution = live
                && target.expected.is_none()
                && target
                    .linux_process_path
                    .as_ref()
                    .is_some_and(|context| target.path == context.contextual);
            let live = if needs_path_resolution {
                target.resolve_linux_process_path(&self.process_path_opener);
                // It may have exited during the potentially blocking traversal.
                self.validate_process_target(target)?
            } else {
                live
            };
            if !live {
                let context = target.linux_process_path.as_ref().unwrap();
                target.path = context.host_fallback.clone().unwrap();
                // The exact captured file identity now guards the host open.
                target.process_identity = None;
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = live;
        if target.process_identity.is_some() && target.expected.is_none() {
            return Err(self.identity_error());
        }
        Ok(())
    }

    fn resolve_until_with_opener<F>(
        &self,
        target: &ArtifactTarget,
        plan: &ResolvePlan,
        deadline_at: Instant,
        deadline_recorded: &AtomicBool,
        job: &mut ArtifactJob,
        open: F,
    ) -> Result<Artifact, ResolveError>
    where
        F: FnOnce(&Path) -> io::Result<File>,
    {
        let mut prepared = target.clone();
        self.prepare_process_target(&mut prepared)?;
        let target = &prepared;
        if Instant::now() >= deadline_at {
            self.record_deadline(deadline_recorded);
            return Err(ResolveError::Deadline(plan.deadline));
        }
        let mut file = open(&target.path).map_err(|error| {
            self.state
                .counters
                .open_failed
                .fetch_add(1, Ordering::Relaxed);
            ResolveError::Open(error)
        })?;
        let identity = file_identity::from_file(&file).ok_or_else(|| {
            self.state
                .counters
                .identity_mismatch
                .fetch_add(1, Ordering::Relaxed);
            ResolveError::Identity
        })?;
        if target
            .expected
            .as_ref()
            .is_some_and(|expected| !expected.matches(&identity))
        {
            self.state
                .counters
                .identity_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::Identity);
        }

        self.validate_process_target(target)?;

        let mut artifact = Artifact {
            identity: Some(identity.clone()),
            ..Artifact::default()
        };
        let size = file
            .metadata()
            .map_err(|error| {
                self.state
                    .counters
                    .read_failed
                    .fetch_add(1, Ordering::Relaxed);
                ResolveError::Read(error)
            })?
            .len();
        if plan.max_read_bytes == 0 || size > plan.max_read_bytes {
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::TooLarge {
                size,
                limit: plan.max_read_bytes,
            });
        }
        if target.kind == ArtifactKind::WrittenFile
            && !written_file_qualifies(&target.path, &mut file, size).map_err(|error| {
                self.state
                    .counters
                    .read_failed
                    .fetch_add(1, Ordering::Relaxed);
                ResolveError::Read(error)
            })?
        {
            return Ok(artifact);
        }

        let mut missing = plan.needs;
        {
            let mut stores = self
                .state
                .stores
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            stores.load(&identity, plan, &mut artifact, &mut missing);
        }
        if plan.needs.pe_metadata && !missing.pe_metadata {
            self.publish_pe(job, artifact.pe_metadata.clone());
        }
        if !missing.pe_metadata && !missing.needs_digest_read() {
            job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
        }
        if Instant::now() >= deadline_at {
            self.record_deadline(deadline_recorded);
            return Err(ResolveError::Deadline(plan.deadline));
        }
        if missing.is_empty() {
            self.state
                .counters
                .cache_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(artifact);
        }
        self.state
            .counters
            .cache_misses
            .fetch_add(1, Ordering::Relaxed);

        if missing.pe_metadata && size > PE_MAX_READ_BYTES {
            missing.pe_metadata = false;
            self.publish_pe(job, None);
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if (missing.hashes.md5 || missing.hashes.sha1 || missing.hashes.sha256)
            && size > plan.hash_max_bytes
        {
            missing.hashes = HashRequirements::default();
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if missing.imphash && size > PE_MAX_READ_BYTES {
            missing.imphash = false;
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if missing.yara && size > plan.yara_max_bytes {
            missing.yara = false;
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
        }
        if !missing.pe_metadata && !missing.needs_digest_read() {
            job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
        }
        if missing.is_empty() {
            return Ok(artifact);
        }

        let mut bytes = Vec::with_capacity(size.min(1024 * 1024) as usize);
        (&mut file)
            .take(plan.max_read_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                self.state
                    .counters
                    .read_failed
                    .fetch_add(1, Ordering::Relaxed);
                ResolveError::Read(error)
            })?;
        if bytes.len() as u64 > plan.max_read_bytes {
            self.state
                .counters
                .oversized
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::TooLarge {
                size: bytes.len() as u64,
                limit: plan.max_read_bytes,
            });
        }
        if file_identity::from_file(&file).as_ref() != Some(&identity) {
            self.state
                .counters
                .identity_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::Identity);
        }
        if Instant::now() >= deadline_at {
            self.record_deadline(deadline_recorded);
            return Err(ResolveError::Deadline(plan.deadline));
        }

        if missing.pe_metadata {
            artifact.pe_metadata = parse_pe_metadata_bytes(&bytes);
            // Cache and publish before the slower consumers run, so a missed
            // admission budget still warms the next start of this image.
            self.state
                .stores
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    identity.clone(),
                    plan,
                    &artifact,
                    StoredParts {
                        pe: true,
                        imphash: false,
                    },
                );
            self.publish_pe(job, artifact.pe_metadata.clone());
            if !missing.needs_digest_read() {
                job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
            }
            if Instant::now() >= deadline_at {
                self.record_deadline(deadline_recorded);
                return Err(ResolveError::Deadline(plan.deadline));
            }
        }
        if missing.hashes.md5 || missing.hashes.sha1 || missing.hashes.sha256 {
            let computed = crate::ioc::compute_hashes_from_bytes(&bytes, missing.hashes);
            // Keep digests the store already had for algorithms not missing.
            artifact.hashes = Some(match artifact.hashes.take() {
                Some(cached) => ComputedHashes {
                    md5: computed.md5.or(cached.md5),
                    sha1: computed.sha1.or(cached.sha1),
                    sha256: computed.sha256.or(cached.sha256),
                },
                None => computed,
            });
            if Instant::now() >= deadline_at {
                self.record_deadline(deadline_recorded);
                return Err(ResolveError::Deadline(plan.deadline));
            }
        }
        if missing.imphash {
            artifact.imphash = parse_imphash_bytes(&bytes);
        }
        if missing.needs_digest_read() {
            // Store and publish before YARA, so a slow scan neither delays the
            // deferred pass nor loses digests that are already known.
            self.state
                .stores
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    identity.clone(),
                    plan,
                    &artifact,
                    StoredParts {
                        pe: false,
                        imphash: missing.imphash,
                    },
                );
            job.publish_deferred(artifact.hashes.clone(), artifact.imphash.clone());
        }
        if missing.yara {
            if let Some((_, scanner)) = &plan.yara {
                let remaining = deadline_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    self.record_deadline(deadline_recorded);
                    return Err(ResolveError::Deadline(plan.deadline));
                }
                match scanner.scan_bytes_with_timeout(&bytes, self.runtime.match_debug, remaining) {
                    Ok(matches) => artifact.yara = Some(matches),
                    Err(error) => {
                        if matches!(
                            &error,
                            ScanError::TimedOut { .. } | ScanError::ProcessDeadline { .. }
                        ) {
                            self.record_deadline(deadline_recorded);
                            return Err(ResolveError::Deadline(plan.deadline));
                        } else {
                            self.state
                                .counters
                                .consumer_failed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        debug!(
                            target: "artifact",
                            file = %target.path.display(),
                            outcome = error.kind(),
                            error = %error,
                            "Artifact YARA consumer did not complete"
                        );
                        return Err(ResolveError::Consumer(error.to_string()));
                    }
                }
            }
        }

        if Instant::now() >= deadline_at {
            self.record_deadline(deadline_recorded);
            return Err(ResolveError::Deadline(plan.deadline));
        }

        let mut stores = self
            .state
            .stores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stores.insert(
            identity,
            plan,
            &artifact,
            StoredParts {
                pe: false,
                imphash: false,
            },
        );
        Ok(artifact)
    }

    fn record_deadline(&self, recorded: &AtomicBool) {
        if !recorded.swap(true, Ordering::Relaxed) {
            self.state
                .counters
                .deadline_exceeded
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Hand PE metadata to admission and executable metadata to the process cache.
    pub(super) fn publish_pe(&self, job: &mut ArtifactJob, metadata: Option<PeMetadata>) {
        if job.target.kind == ArtifactKind::ProcessImage {
            if let (Some(metadata), Some(key)) = (&metadata, job.process_start_key) {
                self.host_state
                    .processes
                    .enrich_pe_metadata(key.pid, key.start_time, metadata);
            }
        }
        job.publish_pe(metadata);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use tokio::sync::mpsc;

    use super::*;
    use crate::alerts::AlertSink;
    use crate::artifact::job::*;
    use crate::artifact::stores::*;
    use crate::artifact::target::*;
    use crate::artifact::test_support::*;
    use crate::artifact::*;
    use crate::ioc::HashRequirements;
    use crate::models::{CanonicalEvent, EventFields};
    use crate::scanner::{self, Scanner};
    use crate::sensor::Platform;
    use crate::state::HostState;
    use crate::utils::file_identity::{self};

    #[test]
    fn one_open_supplies_hash_and_yara_and_reload_invalidates_only_yara() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let runtime = runtime_with_consumers(temp.path(), bytes);
        let event = process_event(&path, Platform::Linux);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let state = Arc::new(ResolverState::new());
        let worker = ArtifactResolver::new(
            Arc::new(HostState::default()),
            runtime.clone(),
            Arc::clone(&state),
        );
        let opens = AtomicUsize::new(0);

        let first_plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let first = worker
            .resolve_with_opener(&target, &first_plan, |path| {
                opens.fetch_add(1, Ordering::Relaxed);
                File::open(path)
            })
            .unwrap();
        assert!(first.hashes.unwrap().sha256.is_some());
        assert_eq!(first.yara.unwrap().len(), 1);
        assert_eq!(opens.load(Ordering::Relaxed), 1);

        let clean_rules = temp.path().join("clean-yara");
        std::fs::create_dir(&clean_rules).unwrap();
        std::fs::write(
            clean_rules.join("clean.yar"),
            r#"rule Clean { strings: $marker = "not-present" condition: $marker }"#,
        )
        .unwrap();
        runtime
            .detectors
            .as_ref()
            .unwrap()
            .swap_yara(Arc::new(Scanner::new(&clean_rules).unwrap()));
        let second_plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let second = worker
            .resolve_with_opener(&target, &second_plan, |path| {
                opens.fetch_add(1, Ordering::Relaxed);
                File::open(path)
            })
            .unwrap();
        assert!(second.hashes.unwrap().sha256.is_some());
        assert!(second.yara.unwrap().is_empty());
        let snapshot = state.snapshot();
        assert_eq!(snapshot.hash_entries, 1);
        assert_eq!(snapshot.yara_entries, 1);
        assert_eq!(opens.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn hash_ioc_alert_survives_yara_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let mut runtime = runtime_with_consumers(temp.path(), bytes);

        let slow_rules = temp.path().join("slow-yara");
        std::fs::create_dir(&slow_rules).unwrap();
        std::fs::write(
            slow_rules.join("slow.yar"),
            r#"rule Slow {
                condition:
                    for all i in (0..2000000000) : (uint8(i % 6) != 0xff)
            }"#,
        )
        .unwrap();
        let timeout = Duration::from_secs(1);
        let scanner = Scanner::new(&slow_rules)
            .unwrap()
            .with_limits(crate::scanner::ScanLimits {
                timeout,
                max_file_bytes: 1024,
            });
        runtime
            .detectors
            .as_ref()
            .unwrap()
            .swap_yara(Arc::new(scanner));

        let alerts_path = temp.path().join("alerts.ndjson");
        let (writer, guard) = tracing_appender::non_blocking(File::create(&alerts_path).unwrap());
        runtime.alert_sink = Some(AlertSink::new(writer));
        let event = process_event(&path, Platform::Linux);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let deadline_at = Instant::now() + plan.deadline;
        let state = Arc::new(ResolverState::new());
        let worker =
            ArtifactResolver::new(Arc::new(HostState::default()), runtime, Arc::clone(&state));
        worker.resolve_job(
            ArtifactJob {
                target,
                plan,
                enqueued_at: Instant::now(),
                pe_ready: None,
                deferred_ready: None,
                resolved_pe: None,
                resolved_hashes: None,
                process_start_key: None,
                provenance: scanner::scan_subject_provenance(event.provenance()),
                platform: event.normalized().platform,
                provider: event.normalized().provider.clone(),
                written_file: None,
            },
            deadline_at,
            open_artifact,
        );
        drop(guard);

        let alerts = read_alerts(&alerts_path);
        assert_eq!(alerts.len(), 1, "only the completed hash IOC may alert");
        assert_eq!(alerts[0]["edr.rule.engine"], "Ioc");
        let snapshot = state.snapshot();
        assert_eq!(snapshot.hash_entries, 1);
        assert_eq!(snapshot.yara_entries, 0, "a timeout is not a clean scan");
        assert_eq!(snapshot.deadline_exceeded, 1);
        assert_eq!(snapshot.resolved, 0);
    }

    #[test]
    fn expired_job_is_skipped_without_opening_the_file() {
        let state = Arc::new(ResolverState::new());
        let runtime = ArtifactRuntime::capture(Platform::Windows);
        let event = image_event(Path::new("definitely-missing.exe"));
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let (pe_tx, pe_rx) = std::sync::mpsc::sync_channel(1);
        let (tx, mut rx) = mpsc::channel(1);
        tx.blocking_send(ArtifactJob {
            target,
            plan,
            enqueued_at: Instant::now() - ARTIFACT_DEADLINE,
            pe_ready: Some(pe_tx),
            deferred_ready: None,
            resolved_pe: None,
            resolved_hashes: None,
            process_start_key: None,
            provenance: Default::default(),
            platform: Platform::Windows,
            provider: "test".into(),
            written_file: None,
        })
        .unwrap();
        drop(tx);

        let opens = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&opens);
        ArtifactResolver::new(Arc::new(HostState::default()), runtime, Arc::clone(&state)).run(
            &mut rx,
            Arc::new(move |path| {
                counted.fetch_add(1, Ordering::Relaxed);
                File::open(path)
            }),
        );

        assert_eq!(opens.load(Ordering::Relaxed), 0);
        assert_eq!(state.snapshot().deadline_exceeded, 1);
        assert!(
            matches!(
                pe_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Disconnected)
            ),
            "a skipped job must release admission immediately"
        );
    }

    #[test]
    fn blocked_io_keeps_its_slot_and_shutdown_detaches_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("blocked.exe");
        std::fs::write(&path, b"artifact").unwrap();
        let state = Arc::new(ResolverState::new());
        let runtime = ArtifactRuntime::capture(Platform::Windows);
        let event = image_event(&path);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let mut plan = ResolvePlan::snapshot(&runtime, &event, &target);
        plan.deadline = Duration::from_millis(50);
        let (tx, mut rx) = mpsc::channel(ARTIFACT_IO_ISOLATION_LIMIT + 1);
        for _ in 0..=ARTIFACT_IO_ISOLATION_LIMIT {
            tx.blocking_send(ArtifactJob {
                target: target.clone(),
                plan: plan.clone(),
                enqueued_at: Instant::now(),
                pe_ready: None,
                deferred_ready: None,
                resolved_pe: None,
                resolved_hashes: None,
                process_start_key: None,
                provenance: Default::default(),
                platform: Platform::Windows,
                provider: "test".into(),
                written_file: None,
            })
            .unwrap();
        }
        drop(tx);

        let gate = Gate::new();
        let started = Instant::now();
        ArtifactResolver::new(Arc::new(HostState::default()), runtime, Arc::clone(&state))
            .run(&mut rx, gate.opener(None));

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited on blocked I/O"
        );
        assert_eq!(
            state.snapshot().deadline_exceeded,
            1,
            "only the job that never got an I/O slot is skipped at dequeue"
        );
        gate.release();
    }

    #[test]
    fn loaded_image_pe_metadata_stays_out_of_the_process_cache() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("library.dll");
        std::fs::write(&image, b"artifact").unwrap();
        let runtime = ArtifactRuntime::capture(Platform::Windows);
        let mut event = image_event(&image);
        let process_key = crate::sensor::ProcessStartKey {
            pid: 42,
            start_time: 100,
        };
        event.process_start_key = Some(process_key);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let state = Arc::new(ResolverState::new());
        let host_state = Arc::new(HostState::default());
        let resolver = ArtifactResolver::new(Arc::clone(&host_state), runtime, Arc::clone(&state));
        let executable_metadata = PeMetadata {
            original_filename: Some("application.exe".into()),
            product: Some("Application".into()),
            description: Some("Application executable".into()),
            company: Some("Executable Company".into()),
            file_version: Some("1.0.0".into()),
        };
        let reused_process_metadata = PeMetadata {
            original_filename: Some("new-application.exe".into()),
            product: Some("New Application".into()),
            description: Some("Reused PID executable".into()),
            company: Some("New Executable Company".into()),
            file_version: Some("2.0.0".into()),
        };
        host_state.processes.add(
            process_key.pid,
            process_key.start_time,
            r"C:\Program Files\Application\application.exe".into(),
            None,
            None,
            None,
            None,
            None,
            executable_metadata.original_filename.clone(),
            executable_metadata.product.clone(),
            executable_metadata.description.clone(),
            executable_metadata.company.clone(),
            executable_metadata.file_version.clone(),
            None,
            None,
        );
        host_state.processes.add(
            process_key.pid,
            200,
            r"C:\Program Files\Application\new-application.exe".into(),
            None,
            None,
            None,
            None,
            None,
            reused_process_metadata.original_filename.clone(),
            reused_process_metadata.product.clone(),
            reused_process_metadata.description.clone(),
            reused_process_metadata.company.clone(),
            reused_process_metadata.file_version.clone(),
            None,
            None,
        );

        let dll_metadata = PeMetadata {
            original_filename: Some("library.dll".into()),
            product: Some("Shared Library".into()),
            description: Some("Loaded DLL".into()),
            company: Some("Library Company".into()),
            file_version: Some("9.9.9".into()),
        };
        state.stores.lock().unwrap().insert(
            file_identity::from_path(&image).unwrap(),
            &plan,
            &Artifact {
                pe_metadata: Some(dll_metadata.clone()),
                ..Artifact::default()
            },
            StoredParts {
                pe: true,
                imphash: false,
            },
        );

        for _ in 0..2 {
            let (pe_ready, pe) = std::sync::mpsc::sync_channel(1);
            resolver.resolve_job(
                ArtifactJob {
                    target: target.clone(),
                    plan: plan.clone(),
                    enqueued_at: Instant::now(),
                    pe_ready: Some(pe_ready),
                    deferred_ready: None,
                    resolved_pe: None,
                    resolved_hashes: None,
                    process_start_key: Some(process_key),
                    provenance: Default::default(),
                    platform: Platform::Windows,
                    provider: "test".into(),
                    written_file: None,
                },
                Instant::now() + ARTIFACT_DEADLINE,
                open_artifact,
            );
            assert_eq!(pe.recv().unwrap(), Some(dll_metadata.clone()));
            assert_eq!(
                host_state
                    .processes
                    .get_metadata_by_key(process_key.pid, process_key.start_time)
                    .unwrap()
                    .original_filename,
                executable_metadata.original_filename
            );
        }

        assert_eq!(state.snapshot().pe_entries, 1);
        assert_eq!(state.snapshot().cache_hits, 2);
        assert_eq!(
            host_state
                .processes
                .get_metadata_by_key(process_key.pid, 200)
                .unwrap()
                .original_filename,
            reused_process_metadata.original_filename
        );

        let mut subsequent = windows_file_event(2).into_normalized();
        host_state.enrich_process_context(&mut subsequent, Some(process_key));
        let context = subsequent.process_context.unwrap();
        assert_eq!(
            context.original_file_name,
            executable_metadata.original_filename
        );
        assert_eq!(context.product, executable_metadata.product);
        assert_eq!(context.description, executable_metadata.description);
        assert_eq!(context.company, executable_metadata.company);
        assert_eq!(context.file_version, executable_metadata.file_version);
    }

    #[cfg(unix)]
    #[test]
    fn written_file_scans_its_validated_handle_and_rejects_a_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("dropped.exe");
        std::fs::write(&path, bytes).unwrap();
        let mut runtime = runtime_with_consumers(temp.path(), bytes);
        runtime.written_files = Some(select_all());
        let event = file_event(&path, FILE_CREATE_OPCODE, Some(object_identity(&path)));
        let target = ArtifactTarget::from_event(&event, runtime.written_files.as_ref()).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        assert!(plan.needs.yara && plan.needs.hashes.sha256 && !plan.needs.pe_metadata);
        let state = Arc::new(ResolverState::new());
        let worker = ArtifactResolver::new(
            Arc::new(HostState::default()),
            runtime.clone(),
            Arc::clone(&state),
        );

        let artifact = worker
            .resolve_with_opener(&target, &plan, open_artifact)
            .unwrap();
        assert_eq!(artifact.yara.unwrap().len(), 1);
        assert!(artifact.hashes.unwrap().sha256.is_some());

        let replacement = temp.path().join("replacement.bin");
        std::fs::write(&replacement, bytes).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let error = worker
            .resolve_with_opener(&target, &plan, open_artifact)
            .expect_err("a replacement must not be scanned as the written file");
        assert!(matches!(error, ResolveError::Identity));
        assert_eq!(state.snapshot().identity_mismatch, 1);
    }

    #[test]
    fn process_image_replaced_after_exec_is_an_identity_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"evil!!";
        let path = temp.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let runtime = runtime_with_consumers(temp.path(), bytes);
        let mut normalized = process_event(&path, Platform::Linux).into_normalized();
        let EventFields::ProcessCreation(fields) = &mut normalized.fields else {
            unreachable!();
        };
        fields.exec = Some(Box::new(crate::models::ExecMetadata {
            file_identity: file_identity::from_path(&path),
            ..Default::default()
        }));
        let event = CanonicalEvent::from_normalized(normalized);
        let target = ArtifactTarget::from_event(&event, None).unwrap();
        let plan = ResolvePlan::snapshot(&runtime, &event, &target);
        let state = Arc::new(ResolverState::new());
        let worker = ArtifactResolver::new(
            Arc::new(HostState::default()),
            runtime.clone(),
            Arc::clone(&state),
        );
        assert_eq!(
            worker
                .resolve_with_opener(&target, &plan, open_artifact)
                .unwrap()
                .yara
                .unwrap()
                .len(),
            1
        );

        let replacement = temp.path().join("replacement.bin");
        std::fs::write(&replacement, b"clean!").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(matches!(
            worker.resolve_with_opener(&target, &plan, open_artifact),
            Err(ResolveError::Identity)
        ));
        assert_eq!(state.snapshot().identity_mismatch, 1);
    }

    #[test]
    fn nothing_is_hashed_unless_a_loaded_consumer_needs_it() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("tool.exe");
        let (runtime, _, _, _guard) = detecting_runtime(
            temp.path(),
            &[
                windows_rule(
                    "By image",
                    "process_creation",
                    "  selection:\n    Image|endswith: tool.exe\n  condition: selection\n",
                ),
                windows_rule(
                    "Loaded imphash",
                    "image_load",
                    "  selection:\n    Imphash: 0123\n  condition: selection\n",
                ),
            ],
        );

        let process = process_event(&image, Platform::Windows);
        let process_plan = ResolvePlan::snapshot(
            &runtime,
            &process,
            &ArtifactTarget::from_event(&process, None).unwrap(),
        );
        assert!(!process_plan.needs.needs_digest_read());
        assert!(process_plan.deferred.is_empty());

        let loaded = image_event(&image);
        let loaded_plan = ResolvePlan::snapshot(
            &runtime,
            &loaded,
            &ArtifactTarget::from_event(&loaded, None).unwrap(),
        );
        assert!(loaded_plan.needs.imphash);
        assert_eq!(loaded_plan.needs.hashes, HashRequirements::default());

        let linux = process_event(&image, Platform::Linux);
        let linux_plan = ResolvePlan::snapshot(
            &runtime,
            &linux,
            &ArtifactTarget::from_event(&linux, None).unwrap(),
        );
        assert!(
            linux_plan.deferred.is_empty(),
            "only Windows PE images carry these fields"
        );
    }

    #[test]
    fn an_absent_imphash_is_cached_so_the_file_is_not_read_again() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("plain.dll");
        std::fs::write(&path, b"no imports here").unwrap();
        let identity = file_identity::from_path(&path).unwrap();
        let (runtime, _, _, _guard) = detecting_runtime(
            temp.path(),
            &[windows_rule(
                "Loaded imphash",
                "image_load",
                "  selection:\n    Imphash: 0123\n  condition: selection\n",
            )],
        );
        let event = image_event(&path);
        let plan = ResolvePlan::snapshot(
            &runtime,
            &event,
            &ArtifactTarget::from_event(&event, None).unwrap(),
        );
        let mut stores = ArtifactStores::new(10);
        stores.insert(
            identity.clone(),
            &plan,
            &Artifact::default(),
            StoredParts {
                pe: false,
                imphash: true,
            },
        );

        let mut artifact = Artifact::default();
        let mut missing = plan.needs;
        stores.load(&identity, &plan, &mut artifact, &mut missing);
        assert!(!missing.imphash);
        assert_eq!(artifact.imphash, None);
    }
}
