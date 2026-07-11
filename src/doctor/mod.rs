pub mod inspect;
pub mod path;
pub mod prerequisites;
pub mod rules;
pub mod services;

pub use crate::doctor::inspect::{inspect, run_cli, DiagnosticStatus};
