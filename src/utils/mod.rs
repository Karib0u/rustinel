//! Utility modules for Rustinel
//!
//! Provides helper functions for path normalization and PE parsing.

pub mod log_rate_limiter;
pub mod path;
#[cfg(windows)]
pub mod pe;
pub mod process;
#[cfg(target_os = "linux")]
pub mod socket;
pub mod time;
pub mod user;

pub use log_rate_limiter::LogRateLimiter;
pub use path::convert_nt_to_dos;
#[cfg(windows)]
pub use pe::parse_metadata;
#[cfg(windows)]
pub use process::query_process_command_line_from_handle;
#[cfg(target_os = "linux")]
pub use process::query_process_details;
pub use process::{
    hash_command_line, query_process_command_line, query_process_identity, ProcessIdentity,
};
#[cfg(target_os = "linux")]
pub use socket::query_socket_metadata;
pub use time::now_timestamp_string;
#[cfg(windows)]
pub use user::lookup_account_sid;
#[cfg(target_os = "linux")]
pub use user::lookup_username_by_uid;
