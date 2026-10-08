pub mod capture;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod live;
pub mod logging;
#[cfg(target_os = "macos")]
mod macos;
mod orchestration;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod pipeline;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod sensors;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod shutdown;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod signals;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod startup;
pub mod telemetry;
#[cfg(windows)]
mod windows;
pub mod yara;

pub use orchestration::run;
