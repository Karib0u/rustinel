use std::io;

use tokio::signal::unix::{signal, Signal, SignalKind};

/// Register shutdown signals before announcing that the runtime is ready.
pub(crate) struct ShutdownSignals {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
}

impl ShutdownSignals {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    pub(crate) async fn recv(&mut self) -> Option<&'static str> {
        tokio::select! {
            received = self.interrupt.recv() => received.map(|()| "SIGINT"),
            received = self.terminate.recv() => received.map(|()| "SIGTERM"),
            received = self.hangup.recv() => received.map(|()| "SIGHUP"),
        }
    }
}

impl ShutdownSignals {
    /// Wait for the first shutdown signal, as the runners expect.
    pub(crate) fn wait(mut self) -> crate::runtime::sensors::ShutdownFuture {
        Box::pin(async move { self.recv().await.map(str::to_string) })
    }
}
