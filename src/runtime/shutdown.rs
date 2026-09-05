//! Drain live detection workers after the platform sensors have stopped.

use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::alerts::AlertSink;
use crate::runtime::pipeline::LivePipeline;
use crate::runtime::telemetry::TelemetryReporter;

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
        drop(self.router);
        join_worker("sensor event", sensor_worker).await;
        for (name, handle) in [
            ("YARA file", self.yara_worker_handle),
            ("YARA memory", self.yara_memory_worker_handle),
            ("IOC hash", self.ioc_hash_worker_handle),
        ] {
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
        if let Some(reporter) = telemetry_reporter {
            reporter.finish().await;
        }
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
        let yara = tokio::spawn(async move {
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
            yara_worker_handle: Some(yara),
            yara_memory_worker_handle: None,
            ioc_hash_worker_handle: None,
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
