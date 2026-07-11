pub mod inspect;
pub mod path;
pub mod prerequisites;
pub mod rules;
pub mod services;

pub use inspect::{
    format_human, inspect, inspect_with_options, run_cli, ConfigDiagnostic, DiagnosticResult,
    DiagnosticStatus, DoctorReport, InstallMode, ResolvedPaths, RulePackDiagnostic,
    ServiceDiagnostic,
};
