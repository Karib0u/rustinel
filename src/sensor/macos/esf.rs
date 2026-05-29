//! macOS Endpoint Security sensor.
//!
//! [`EsfSensor`] implements [`Sensor`] for macOS using Apple's Endpoint
//! Security framework via the `endpoint-sec` crate. On `start()` it spawns a
//! dedicated thread that owns the ES client — the client must be created and
//! released on the same thread — subscribes to process events, and translates
//! each message into a [`SensorEvent`] for the shared pipeline.
//!
//! Endpoint Security delivers messages on its own dispatch queue, so the
//! keepalive thread simply holds the client alive until shutdown; the actual
//! work happens in the message handler.
//!
//! Requirements: root, the `com.apple.developer.endpoint-security.client`
//! entitlement, and user approval (TCC). Dev builds can run with SIP/AMFI
//! relaxed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, Result};
use endpoint_sec::{Client, Message};
use endpoint_sec_sys::es_event_type_t;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::sensor::{Sensor, SensorEvent};

/// Poll interval for the keepalive thread to observe the shutdown flag.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// Endpoint Security event subscriptions for the macOS sensor.
const SUBSCRIPTIONS: &[es_event_type_t] = &[
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
];

/// macOS Endpoint Security sensor. Implements [`Sensor`].
pub struct EsfSensor {
    shutdown: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl EsfSensor {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        }
    }
}

impl Default for EsfSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for EsfSensor {
    /// Spawn the Endpoint Security client thread and block until the client is
    /// created and subscribed, so initialization errors (missing entitlement,
    /// not root, TCC denial) surface synchronously to the caller.
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

        let handle = std::thread::Builder::new()
            .name("rustinel-esf".to_string())
            .spawn(move || run_client(tx, shutdown, ready_tx))
            .map_err(|e| anyhow!("failed to spawn Endpoint Security thread: {e}"))?;

        *self.thread.lock().expect("esf thread mutex poisoned") = Some(handle);

        match ready_rx.recv() {
            Ok(Ok(())) => {
                info!("Endpoint Security client subscribed");
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow!("Endpoint Security client init failed: {e}")),
            Err(_) => Err(anyhow!(
                "Endpoint Security thread exited before signaling readiness"
            )),
        }
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self
            .thread
            .lock()
            .expect("esf thread mutex poisoned")
            .take()
        {
            let _ = handle.join();
        }
    }
}

/// Body of the Endpoint Security client thread.
///
/// Creates the client, subscribes, signals readiness, then keeps the client
/// alive until shutdown. The client is dropped (released) on this thread, as
/// Endpoint Security requires.
fn run_client(
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let handler = move |_client: &mut Client<'_>, msg: Message| {
        if let Some(event) = build_sensor_event(&msg) {
            try_send(&tx, event);
        }
    };

    let mut client = match Client::new(handler) {
        Ok(client) => client,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("es_new_client failed: {e:?}")));
            return;
        }
    };

    if let Err(e) = client.subscribe(SUBSCRIPTIONS) {
        let _ = ready_tx.send(Err(format!("es_subscribe failed: {e:?}")));
        return;
    }

    let _ = ready_tx.send(Ok(()));

    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SHUTDOWN_POLL);
    }

    info!("Endpoint Security sensor shutting down");
}

/// Translate an Endpoint Security message into a shared [`SensorEvent`].
///
/// Returns `None` for messages that carry no detection signal or are not yet
/// mapped. Per-event-class translation is filled in incrementally.
fn build_sensor_event(_msg: &Message) -> Option<SensorEvent> {
    None
}

fn try_send(tx: &Sender<SensorEvent>, event: SensorEvent) {
    match tx.try_send(event) {
        Ok(_) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            warn!("ESF sensor: event channel full, dropping event");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            // Pipeline has shut down; stop logging.
        }
    }
}
