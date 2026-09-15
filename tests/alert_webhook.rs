//! Webhook delivery against local HTTP servers.
//!
//! Each test drives a real `AlertSink` with webhooks attached, so the NDJSON
//! file and the HTTP deliveries are observed side by side.

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use rustinel::alerts::webhook::{signature, DELIVERY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER};
use rustinel::alerts::{AlertSink, Deduplicator, WebhookDispatcher};
use rustinel::config::WebhookConfig;
use rustinel::models::{Alert, AlertSeverity, DetectionEngine, NormalizedEvent};
use rustinel::telemetry::WebhookSnapshot;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
struct Received {
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Reply {
    status: u16,
    delay: Duration,
    retry_after: Option<u64>,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            delay: Duration::ZERO,
            retry_after: None,
        }
    }
}

/// A minimal HTTP/1.1 server that records requests and answers from a script.
struct TestServer {
    url: String,
    received: Arc<Mutex<Vec<Received>>>,
}

impl TestServer {
    async fn start(script: impl Fn(usize) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/ingest/path-token-XYZ",
            listener.local_addr().unwrap()
        );
        let received = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let requests = Arc::new(AtomicUsize::new(0));
        let log = Arc::clone(&received);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (script, requests, log) =
                    (Arc::clone(&script), Arc::clone(&requests), Arc::clone(&log));
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    loop {
                        let mut request_line = String::new();
                        if reader.read_line(&mut request_line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let mut headers = HashMap::new();
                        loop {
                            let mut line = String::new();
                            reader.read_line(&mut line).await.unwrap();
                            let line = line.trim_end();
                            if line.is_empty() {
                                break;
                            }
                            let (name, value) = line.split_once(':').unwrap();
                            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                        }
                        let length: usize = headers
                            .get("content-length")
                            .map(|value| value.parse().unwrap())
                            .unwrap_or(0);
                        let mut body = vec![0; length];
                        reader.read_exact(&mut body).await.unwrap();
                        let index = requests.fetch_add(1, Ordering::SeqCst);
                        log.lock().unwrap().push(Received { headers, body });

                        let reply = script(index);
                        tokio::time::sleep(reply.delay).await;
                        let retry_after = reply
                            .retry_after
                            .map(|secs| format!("Retry-After: {secs}\r\n"))
                            .unwrap_or_default();
                        let response = format!(
                            "HTTP/1.1 {} Test\r\nContent-Length: 0\r\n{retry_after}\r\n",
                            reply.status
                        );
                        if writer.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { url, received }
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

/// A URL on a port nothing listens on.
async fn unreachable_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}/unreachable/path-token-XYZ")
}

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl SharedWriter {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// Everything any test in this binary logs.
///
/// One global subscriber rather than a per-test default: tracing caches
/// callsite interest process-wide, so a thread-scoped subscriber misses events
/// whose callsites another test thread reached first.
static LOG: LazyLock<SharedWriter> = LazyLock::new(|| {
    let output = SharedWriter::default();
    let writer = output.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();
    output
});

fn webhook(name: &str, url: &str) -> WebhookConfig {
    let mut config = WebhookConfig::new(url);
    config.name = Some(name.to_string());
    config.timeout_ms = 2_000;
    config.retry_initial_ms = 10;
    config.retry_max_ms = 40;
    config
}

fn sink_with(
    configs: &[WebhookConfig],
) -> (
    AlertSink,
    Arc<WebhookDispatcher>,
    SharedWriter,
    tracing_appender::non_blocking::WorkerGuard,
) {
    LazyLock::force(&LOG);
    let output = SharedWriter::default();
    let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(false)
        .finish(output.clone());
    let dispatcher = Arc::new(WebhookDispatcher::start(configs).expect("dispatcher starts"));
    let sink = AlertSink::new(writer).with_webhooks(Arc::clone(&dispatcher));
    (sink, dispatcher, output, guard)
}

fn alert(rule: &str) -> Alert {
    let event: NormalizedEvent = serde_json::from_value(serde_json::json!({
        "timestamp": "2026-09-15T10:00:00Z",
        "platform": "linux",
        "provider": "ebpf",
        "category": "Process",
        "event_id": 1,
        "opcode": 1,
        "fields": { "Image": "/usr/bin/whoami", "ProcessId": "4242" }
    }))
    .unwrap();
    Alert {
        severity: AlertSeverity::High,
        rule_name: rule.to_string(),
        rule_description: None,
        rule_id: None,
        sigma_metadata: None,
        engine: DetectionEngine::Sigma,
        event,
        match_details: None,
    }
}

async fn wait_for(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn counters(dispatcher: &WebhookDispatcher, index: usize) -> WebhookSnapshot {
    dispatcher.snapshots()[index].clone()
}

async fn file_lines(output: &SharedWriter, count: usize) -> Vec<String> {
    wait_for("alert file lines", || output.lines().len() >= count).await;
    output.lines()
}

#[tokio::test]
async fn delivers_the_ecs_document_with_signature_and_custom_headers() {
    let server = TestServer::start(|_| Reply::status(200)).await;
    let mut config = webhook("signed", &server.url);
    config.headers.insert(
        "Authorization".to_string(),
        "Bearer header-secret".to_string(),
    );
    config.secret = Some("hmac-secret".to_string());
    let (sink, dispatcher, output, _guard) = sink_with(&[config]);

    sink.write_alert(&alert("Webhook delivery"));
    wait_for("delivery", || counters(&dispatcher, 0).delivered == 1).await;

    let received = server.received();
    assert_eq!(received.len(), 1);
    let request = &received[0];
    let line = &file_lines(&output, 1).await[0];
    assert_eq!(request.body, line.as_bytes(), "body is the NDJSON line");
    let document: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(document["rule.name"], "Webhook delivery");
    assert_eq!(document["event.kind"], "alert");

    assert_eq!(request.headers["content-type"], "application/json");
    assert_eq!(request.headers["authorization"], "Bearer header-secret");
    assert!(request.headers["user-agent"].starts_with("rustinel/"));
    assert!(!request.headers[DELIVERY_HEADER].is_empty());
    let timestamp = &request.headers[TIMESTAMP_HEADER];
    assert_eq!(
        request.headers[SIGNATURE_HEADER],
        signature(b"hmac-secret", timestamp, &request.body)
    );

    dispatcher.shutdown(Duration::from_secs(2)).await;
    let snapshot = counters(&dispatcher, 0);
    assert_eq!((snapshot.queued, snapshot.delivered), (1, 1));
    assert_eq!(
        snapshot.retries + snapshot.failed + snapshot.abandoned_at_shutdown,
        0
    );
}

#[tokio::test]
async fn transient_failures_retry_with_the_same_delivery_id() {
    let server = TestServer::start(|index| match index {
        0 => Reply::status(503),
        1 => Reply {
            retry_after: Some(0),
            ..Reply::status(429)
        },
        _ => Reply::status(204),
    })
    .await;
    let (sink, dispatcher, _output, _guard) = sink_with(&[webhook("retry", &server.url)]);

    sink.write_alert(&alert("Retried delivery"));
    wait_for("delivery after retries", || {
        counters(&dispatcher, 0).delivered == 1
    })
    .await;

    let received = server.received();
    assert_eq!(received.len(), 3);
    let id = &received[0].headers[DELIVERY_HEADER];
    assert!(received
        .iter()
        .all(|request| &request.headers[DELIVERY_HEADER] == id));
    let snapshot = counters(&dispatcher, 0);
    assert_eq!((snapshot.retries, snapshot.failed), (2, 0));
}

#[tokio::test]
async fn gives_up_after_max_attempts_and_on_permanent_errors() {
    let failing = TestServer::start(|_| Reply::status(500)).await;
    let rejecting = TestServer::start(|_| Reply::status(401)).await;
    let mut bounded = webhook("bounded", &failing.url);
    bounded.max_attempts = 3;
    let (sink, dispatcher, _output, _guard) =
        sink_with(&[bounded, webhook("rejecting", &rejecting.url)]);

    sink.write_alert(&alert("Undeliverable"));
    wait_for("both destinations to give up", || {
        dispatcher
            .snapshots()
            .iter()
            .all(|snapshot| snapshot.failed == 1)
    })
    .await;

    assert_eq!(failing.received().len(), 3, "bounded attempts");
    assert_eq!(counters(&dispatcher, 0).retries, 2);
    assert_eq!(rejecting.received().len(), 1, "4xx is not retried");
    assert_eq!(counters(&dispatcher, 1).retries, 0);
}

#[tokio::test]
async fn a_full_queue_drops_without_blocking_and_the_file_keeps_everything() {
    const ALERTS: usize = 200;
    let slow = TestServer::start(|_| Reply {
        delay: Duration::from_secs(30),
        ..Reply::status(200)
    })
    .await;
    let mut config = webhook("slow", &slow.url);
    config.queue_capacity = 4;
    config.timeout_ms = 60_000;
    let (sink, dispatcher, output, _guard) = sink_with(&[config]);

    let started = Instant::now();
    for index in 0..ALERTS {
        sink.write_alert(&alert(&format!("Saturation {index}")));
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "writing alerts must not wait on the endpoint: {:?}",
        started.elapsed()
    );

    assert_eq!(file_lines(&output, ALERTS).await.len(), ALERTS);
    let snapshot = counters(&dispatcher, 0);
    assert_eq!(snapshot.queued + snapshot.dropped_queue_full, ALERTS as u64);
    assert!(
        snapshot.dropped_queue_full >= (ALERTS - 5) as u64,
        "{snapshot:?}"
    );
    assert_eq!(snapshot.high_water_mark, 4);

    dispatcher.shutdown(Duration::from_millis(200)).await;
    let snapshot = counters(&dispatcher, 0);
    assert_eq!(snapshot.delivered, 0);
    assert_eq!(snapshot.abandoned_at_shutdown, snapshot.queued);
}

#[tokio::test]
async fn one_failing_destination_affects_neither_the_healthy_one_nor_the_file() {
    const ALERTS: usize = 5;
    let healthy = TestServer::start(|_| Reply::status(200)).await;
    let mut unreachable = webhook("unreachable", &unreachable_url().await);
    unreachable.max_attempts = 2;
    let (sink, dispatcher, output, _guard) =
        sink_with(&[webhook("healthy", &healthy.url), unreachable]);

    for index in 0..ALERTS {
        sink.write_alert(&alert(&format!("Fan-out {index}")));
    }
    wait_for("both destinations to settle", || {
        let snapshots = dispatcher.snapshots();
        snapshots[0].delivered == ALERTS as u64 && snapshots[1].failed == ALERTS as u64
    })
    .await;

    let lines = file_lines(&output, ALERTS).await;
    assert_eq!(lines.len(), ALERTS);
    let bodies: Vec<Vec<u8>> = healthy.received().into_iter().map(|r| r.body).collect();
    let expected: Vec<Vec<u8>> = lines.iter().map(|line| line.as_bytes().to_vec()).collect();
    assert_eq!(bodies, expected, "delivered in order, byte for byte");
    assert_eq!(counters(&dispatcher, 1).retries, ALERTS as u64);
}

#[tokio::test]
async fn oversized_alerts_are_skipped_per_destination() {
    let server = TestServer::start(|_| Reply::status(200)).await;
    let mut tiny = webhook("tiny", &server.url);
    tiny.max_payload_bytes = 64;
    let (sink, dispatcher, output, _guard) = sink_with(&[tiny]);

    sink.write_alert(&alert("Too large for the destination"));
    assert_eq!(file_lines(&output, 1).await.len(), 1);
    let snapshot = counters(&dispatcher, 0);
    assert_eq!((snapshot.dropped_oversized, snapshot.queued), (1, 0));
    assert!(server.received().is_empty());
}

#[tokio::test]
async fn dedup_delivers_the_first_alert_and_the_rollup() {
    let server = TestServer::start(|_| Reply::status(200)).await;
    let (sink, dispatcher, _output, _guard) = sink_with(&[webhook("dedup", &server.url)]);
    let dedup = Arc::new(Deduplicator::new(60, 100));
    let sink = sink.with_deduplicator(Arc::clone(&dedup));

    for _ in 0..3 {
        sink.write_alert(&alert("Repeated"));
    }
    dedup.flush_all(&sink);
    dispatcher.shutdown(Duration::from_secs(5)).await;

    let documents: Vec<Value> = server
        .received()
        .iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap())
        .collect();
    assert_eq!(documents.len(), 2);
    assert!(documents[0].get("event.count").is_none());
    assert_eq!(documents[1]["event.count"], 2);
}

#[tokio::test]
async fn configured_secrets_never_reach_the_operational_log() {
    LazyLock::force(&LOG);
    let rejecting = TestServer::start(|_| Reply::status(403)).await;
    let mut configs = Vec::new();
    for (name, url) in [
        ("rejecting", rejecting.url.clone()),
        ("unreachable", unreachable_url().await),
    ] {
        let mut config = webhook(name, &url.replace("http://", "http://user:basic-pass@"));
        config
            .headers
            .insert("X-Api-Key".to_string(), "header-secret".to_string());
        config.secret = Some("hmac-secret".to_string());
        config.max_attempts = 2;
        configs.push(config);
    }
    let (sink, dispatcher, _alerts, _guard) = sink_with(&configs);

    sink.write_alert(&alert("Secret handling"));
    wait_for("both destinations to fail", || {
        dispatcher
            .snapshots()
            .iter()
            .all(|snapshot| snapshot.failed == 1)
    })
    .await;
    dispatcher.shutdown(Duration::from_secs(1)).await;

    let log = LOG.lines().join("\n");
    assert!(log.contains("Webhook delivery failed"), "{log}");
    assert!(log.contains("HTTP 403"), "{log}");
    assert!(
        log.contains("Webhook sends credentials over plain HTTP"),
        "{log}"
    );
    for secret in [
        "header-secret",
        "hmac-secret",
        "basic-pass",
        "path-token-XYZ",
    ] {
        assert!(
            !log.contains(secret),
            "{secret} leaked into the log:\n{log}"
        );
    }
}
