//! Hot-reload support for Sigma, YARA, IOC engines, and configuration.
//!
//! The worker rebuilds and replaces detectors; the watcher detects local file
//! changes using metadata fingerprints and sends reload requests.

mod fingerprint;
mod watcher;
mod worker;

// Preserve the existing public import path for downstream callers.
pub use crate::engine::DetectorStore;
pub use watcher::{spawn_reload_poller, ReloadPoller};
pub use worker::spawn_reload_worker;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReloadTarget {
    Sigma,
    Yara,
    Ioc,
    Config,
}
