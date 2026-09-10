use super::*;
use crate::telemetry::event_log::WINDOWS_EVENT_LOG;

#[test]
fn retention_only_counts_unavailable_records_after_checkpoint() {
    assert!(!retention_wrapped(100, 100));
    assert!(!retention_wrapped(100, 101));
    assert!(retention_wrapped(100, 102));
    assert!(!retention_wrapped(u64::MAX, 1));
}

#[test]
fn checkpoint_replaces_atomically_and_survives_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("System.xml");
    for id in [100, 105, 10_000] {
        let xml = format!(
            r#"<BookmarkList><Bookmark Channel="System" RecordId="{id}" IsCurrent="true"/></BookmarkList>"#
        );
        write_checkpoint(&path, &xml).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert_eq!(bookmark_record_id(&saved, "System").unwrap(), id);
        let wide = wide_string(&saved);
        let bookmark = OwnedEvtHandle(unsafe { EvtCreateBookmark(PCWSTR(wide.as_ptr())) }.unwrap());
        assert_eq!(
            bookmark_record_id(
                &render_xml(bookmark.0, EvtRenderBookmark.0).unwrap(),
                "System"
            )
            .unwrap(),
            id
        );
    }
    assert!(bookmark_record_id("<BookmarkList/>", "System").is_err());
}

#[test]
fn invalid_checkpoint_fails_startup_without_resetting_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("checkpoint.xml");
    std::fs::write(&path, "invalid bookmark").unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let (startup_tx, _startup_rx) = mpsc::sync_channel(1);
    let source = EventLogSource::new(
        "test",
        "invalid-checkpoint-test",
        "*",
        service::source().decoder,
    );
    assert!(run_subscription_inner(
        source,
        tx,
        Arc::new(AtomicBool::new(false)),
        &startup_tx,
        &path
    )
    .is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "invalid bookmark");
    let health = WINDOWS_EVENT_LOG
        .lock()
        .unwrap()
        .iter()
        .find(|h| h.channel == source.channel)
        .unwrap()
        .clone();
    assert_eq!(health.checkpoint_errors, 1);
    assert!(!health.active);
}

#[test]
fn callback_errors_are_categorical_and_named() {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let source = EventLogSource::new(
        "test",
        "callback-error-test",
        "*",
        service::source().decoder,
    );
    let context = CallbackContext {
        source,
        tx,
        state: Mutex::new(CallbackState {
            bookmark: OwnedEvtHandle(unsafe { EvtCreateBookmark(PCWSTR::null()) }.unwrap()),
            pending: None,
            failure: None,
        }),
    };
    for code in [ERROR_EVT_QUERY_RESULT_STALE.0, 5] {
        unsafe {
            subscription_callback(
                EvtSubscribeActionError,
                (&context as *const CallbackContext).cast(),
                EVT_HANDLE(code as isize),
            );
        }
    }
    let health = WINDOWS_EVENT_LOG
        .lock()
        .unwrap()
        .iter()
        .find(|h| h.channel == source.channel)
        .unwrap()
        .clone();
    assert_eq!(health.subscription_errors, 2);
    assert_eq!(health.live_stale, 1);
    assert_eq!(health.retention_wraps, 0);
    assert!(health.last_error.unwrap().contains('5'));
    assert!(!health.active);
}

fn native_channel() -> &'static str {
    static CHANNEL: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("R429{}", std::process::id()));
    CHANNEL.as_str()
}

fn powershell(script: &str) {
    let script = script.replace("RustinelEventLog429", native_channel());
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("$ErrorActionPreference = 'Stop'; {script}"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn decode_test_record(xml: &str) -> Result<SensorEvent> {
    let document = roxmltree::Document::parse(xml)?;
    let id = document
        .descendants()
        .find(|n| n.has_tag_name("EventRecordID"))
        .and_then(|n| n.text())
        .context("missing ID")?;
    // Reuse the production decoder to provide a canonical payload for this transport test.
    (service::source().decoder)(&format!(
        r#"<Event><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><EventRecordID>{id}</EventRecordID><TimeCreated SystemTime="2026-09-10T00:00:00Z"/></System><EventData><Data Name="ServiceName">test</Data><Data Name="ImagePath">test.exe</Data></EventData></Event>"#
    ))
}

fn receive(rx: &mut tokio::sync::mpsc::Receiver<SensorEvent>) -> SensorEvent {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(event) = rx.try_recv() {
            return event;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for Event Log callback"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Creates and removes only a dedicated test channel. Requires elevation.
#[test]
#[ignore = "requires an elevated Windows lab and creates a temporary Event Log channel"]
fn native_filtered_subscription_resume_and_retention() {
    let channel = native_channel();
    powershell("New-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429; wevtutil sl RustinelEventLog429 /ms:1048576 /rt:false; if ($LASTEXITCODE -ne 0) { throw 'wevtutil failed' }");
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Remove-EventLog -LogName {}", native_channel()),
                ])
                .status();
        }
    }
    let _cleanup = Cleanup;
    powershell("Write-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429 -EventId 430 -EntryType Information -Message baseline");
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("checkpoint.xml");
    let source = EventLogSource::new(
        "native-test",
        channel,
        "*[System[EventID=429]]",
        decode_test_record,
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker =
        EventLogSubscription::start(source, tx.clone(), shutdown.clone(), path.clone()).unwrap();
    powershell("Write-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429 -EventId 429 -EntryType Information -Message first; 1..20 | ForEach-Object { Write-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429 -EventId 430 -EntryType Information -Message excluded }; Write-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429 -EventId 429 -EntryType Information -Message second");
    let first = receive(&mut rx).source_seq.unwrap();
    let second = receive(&mut rx).source_seq.unwrap();
    assert!(second > first + 1);
    assert!(rx.try_recv().is_err());
    shutdown.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    assert_eq!(
        bookmark_record_id(&std::fs::read_to_string(&path).unwrap(), channel).unwrap(),
        second
    );

    // A new worker reopens the on-disk bookmark and receives downtime events.
    powershell("Write-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429 -EventId 429 -EntryType Information -Message downtime");
    shutdown.store(false, Ordering::Relaxed);
    let worker =
        EventLogSubscription::start(source, tx.clone(), shutdown.clone(), path.clone()).unwrap();
    let third = receive(&mut rx).source_seq.unwrap();
    assert!(third > second);
    shutdown.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    let health = WINDOWS_EVENT_LOG
        .lock()
        .unwrap()
        .iter()
        .find(|h| h.channel == channel)
        .unwrap()
        .clone();
    assert_eq!(health.delivered, 3);
    assert_eq!(health.subscription_errors, 0);
    assert_eq!(health.live_stale, 0);
    assert_eq!(health.resume_failures, 0);
    assert_eq!(health.retention_wraps, 0);

    // Wrap this isolated channel while the subscriber is stopped.
    powershell("1..600 | ForEach-Object { Write-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429 -EventId 430 -EntryType Information -Message ([guid]::NewGuid().ToString() * 64) }; Write-EventLog -LogName RustinelEventLog429 -Source RustinelEventLog429 -EventId 429 -EntryType Information -Message retained");
    // Event Log metadata can lag Write-EventLog completion while buffers flush.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let oldest = oldest_record(channel).unwrap();
        if retention_wrapped(third, oldest) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "channel did not wrap: bookmark={third}, oldest={oldest}"
        );
        thread::sleep(Duration::from_millis(250));
    }
    shutdown.store(false, Ordering::Relaxed);
    let worker = EventLogSubscription::start(source, tx, shutdown.clone(), path).unwrap();
    assert!(receive(&mut rx).source_seq.unwrap() > third);
    shutdown.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    let health = WINDOWS_EVENT_LOG
        .lock()
        .unwrap()
        .iter()
        .find(|h| h.channel == channel)
        .unwrap()
        .clone();
    assert_eq!(health.retention_wraps, 1);
    assert_eq!(health.resume_failures, 1);
    assert_eq!(health.live_stale, 0);
}
