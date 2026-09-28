//! Drain live detection workers after the platform sensors have stopped.

use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::alerts::AlertSink;
use crate::runtime::pipeline::LivePipeline;
use crate::runtime::telemetry::TelemetryReporter;

impl LivePipeline {
    /// Any of these workers ending while the agent is running leaves detection incomplete.
    pub async fn critical_worker_exit(
        &mut self,
        sensor_worker: &mut JoinHandle<()>,
        response_worker: &mut JoinHandle<()>,
    ) -> (&'static str, Result<(), tokio::task::JoinError>) {
        tokio::select! {
            result = sensor_worker => ("sensor event", result),
            result = &mut self.artifact_worker_handle => ("artifact resolver", result),
            result = response_worker => ("response", result),
            result = async {
                match &mut self.yara_memory_worker_handle {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => ("YARA memory", result),
        }
    }
}

pub fn exit_on_critical_worker_failure(
    name: &str,
    result: Result<(), tokio::task::JoinError>,
    guards: (
        tracing_appender::non_blocking::WorkerGuard,
        tracing_appender::non_blocking::WorkerGuard,
    ),
) -> ! {
    error!(
        worker = name,
        ?result,
        "Critical worker exited before shutdown; restarting agent"
    );
    drop(guards);
    std::process::exit(1);
}

impl LivePipeline {
    /// The caller must stop sensors and drop its response-engine sender first.
    /// The sensor worker retains the router until its queued events are drained.
    /// No other router clones may outlive that worker, since they own job senders.
    pub async fn shutdown(
        self,
        sensor_worker: JoinHandle<()>,
        response_worker: JoinHandle<()>,
        dedup_worker: Option<JoinHandle<()>>,
        alert_sink: &AlertSink,
        telemetry_reporter: Option<TelemetryReporter>,
    ) {
        let artifact_resolver_handle = self.artifact_resolver_handle;
        drop(self.router);
        join_worker("sensor event", sensor_worker).await;
        join_worker("artifact resolver", self.artifact_worker_handle).await;
        for (name, handle) in [("YARA memory", self.yara_memory_worker_handle)] {
            if let Some(handle) = handle {
                join_worker(name, handle).await;
            }
        }
        if let Some(poller) = self.reload_poller {
            poller.shutdown().await;
        }
        drop(self.reload_tx);
        if let Some(handle) = self.reload_worker_handle {
            join_worker("hot-reload", handle).await;
        }
        join_worker("response", response_worker).await;

        // The response worker can still emit alerts, so flush only after it exits.
        if let Some(handle) = dedup_worker {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(dedup) = alert_sink.dedup() {
            dedup.flush_all(alert_sink);
            dedup.log_metrics();
        }
        // After the final flush, so rollups reach the webhooks before they stop.
        if let Some(webhooks) = alert_sink.webhooks() {
            webhooks
                .shutdown(crate::alerts::webhook::SHUTDOWN_GRACE)
                .await;
        }
        if let Some(reporter) = telemetry_reporter {
            reporter.finish().await;
        }
        drop(artifact_resolver_handle);
    }
}

async fn join_worker(name: &str, handle: JoinHandle<()>) {
    match handle.await {
        Ok(()) => info!(worker = name, "Worker finished"),
        Err(error) => error!(worker = name, %error, "Failed to join worker"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    struct Stopped(Arc<AtomicBool>);

    #[tokio::test]
    async fn detects_sensor_worker_panic_before_shutdown() {
        let mut sensor = tokio::spawn(async { panic!("sensor failed") });
        let artifact = tokio::spawn(std::future::pending());
        let mut response = tokio::spawn(std::future::pending());
        let mut pipeline = LivePipeline {
            router: Arc::new(crate::sensor::SensorEventRouter::new()),
            host_state: Arc::new(crate::state::HostState::default()),
            artifact_worker_handle: artifact,
            artifact_resolver_handle: crate::artifact::ArtifactResolverHandle::empty(),
            yara_memory_worker_handle: None,
            reload_poller: None,
            reload_worker_handle: None,
            reload_tx: None,
        };
        let (name, result) = pipeline
            .critical_worker_exit(&mut sensor, &mut response)
            .await;
        assert_eq!(name, "sensor event");
        assert!(result.expect_err("worker should panic").is_panic());
        pipeline.artifact_worker_handle.abort();
        response.abort();
    }

    #[test]
    fn critical_worker_failure_exits_nonzero() {
        const CHILD: &str = "RUSTINEL_TEST_CRITICAL_EXIT";
        if std::env::var_os(CHILD).is_some() {
            let (_, app_guard) = tracing_appender::non_blocking(std::io::sink());
            let (_, alert_guard) = tracing_appender::non_blocking(std::io::sink());
            exit_on_critical_worker_failure("sensor event", Ok(()), (app_guard, alert_guard));
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::shutdown::tests::critical_worker_failure_exits_nonzero",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(1));
    }

    impl Drop for Stopped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn queued_sensor_work_reaches_response_before_final_flush() {
        let (jobs, mut job_rx) = mpsc::channel(1);
        let (responses, mut response_rx) = mpsc::channel(1);
        let router = Arc::new(crate::sensor::SensorEventRouter::new());
        let worker_router = router.clone();
        let sensor = tokio::spawn(async move {
            tokio::task::yield_now().await;
            jobs.send(1).await.unwrap();
            drop(worker_router);
        });
        let artifact = tokio::spawn(async move {
            while let Some(job) = job_rx.recv().await {
                responses.send(job).await.unwrap();
            }
        });
        let completed = Arc::new(AtomicUsize::new(0));
        let dedup_stopped = Arc::new(AtomicBool::new(false));
        let completion_count = completed.clone();
        let stopped = dedup_stopped.clone();
        let response = tokio::spawn(async move {
            while let Some(job) = response_rx.recv().await {
                assert!(!stopped.load(Ordering::SeqCst));
                completion_count.fetch_add(job, Ordering::SeqCst);
            }
        });
        let marker = Stopped(dedup_stopped.clone());
        let dedup = tokio::spawn(async move {
            let _marker = marker;
            std::future::pending::<()>().await;
        });
        let (reload_tx, mut reload_rx) = mpsc::unbounded_channel();
        reload_tx.send(crate::reload::ReloadTarget::Sigma).unwrap();
        let reload = tokio::spawn(async move {
            assert_eq!(
                reload_rx.recv().await,
                Some(crate::reload::ReloadTarget::Sigma)
            );
            assert_eq!(reload_rx.recv().await, None);
        });
        let pipeline = LivePipeline {
            router,
            host_state: Arc::new(crate::state::HostState::default()),
            artifact_worker_handle: artifact,
            artifact_resolver_handle: crate::artifact::ArtifactResolverHandle::empty(),
            yara_memory_worker_handle: None,
            reload_poller: None,
            reload_worker_handle: Some(reload),
            reload_tx: Some(reload_tx),
        };
        let (writer, _guard) = tracing_appender::non_blocking(std::io::sink());
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipeline.shutdown(sensor, response, Some(dedup), &AlertSink::new(writer), None),
        )
        .await
        .expect("queued work must drain without retaining senders");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        assert!(dedup_stopped.load(Ordering::SeqCst));
    }
}
