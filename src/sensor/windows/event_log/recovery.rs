//! Retry policy for a single Event Log subscription.
//!
//! A channel can disappear mid-run, for example while Defender re-registers
//! its channel during a platform update (`ERROR_EVT_CHANNEL_NOT_FOUND`).
//! Such errors are scoped to one source: it re-subscribes from its persisted
//! bookmark with bounded backoff while every other source and ETW keep running.
//! Only exhausted retries or a clearly permanent error escalate to the
//! sensor-wide failure.

use std::time::Duration;

/// `ERROR_ACCESS_DENIED`: the agent lost the right to read the channel.
const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_INVALID_PARAMETER`: the subscription arguments are wrong.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// `ERROR_EVT_INVALID_QUERY`: the XPath query is rejected and will stay so.
const ERROR_EVT_INVALID_QUERY: u32 = 15001;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Consecutive failed sessions tolerated before escalating (about 2.5 minutes).
const MAX_CONSECUTIVE_FAILURES: u32 = 10;
/// A session that stayed up this long counts as healthy and clears the budget.
const STABLE_SESSION: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Retryability {
    Retryable,
    Permanent,
}

/// Failures without a Win32 code (callback panic, checkpoint write) are permanent.
pub(super) fn classify(code: Option<u32>) -> Retryability {
    match code {
        None | Some(ERROR_ACCESS_DENIED | ERROR_INVALID_PARAMETER | ERROR_EVT_INVALID_QUERY) => {
            Retryability::Permanent
        }
        Some(_) => Retryability::Retryable,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Decision {
    Retry(Duration),
    Escalate,
}

#[derive(Debug, Default)]
pub(super) struct RetryState {
    consecutive_failures: u32,
}

impl RetryState {
    /// Decides what follows a failed session that stayed up for `uptime`.
    pub(super) fn on_failure(&mut self, code: Option<u32>, uptime: Duration) -> Decision {
        if classify(code) == Retryability::Permanent {
            return Decision::Escalate;
        }
        if uptime >= STABLE_SESSION {
            self.consecutive_failures = 0;
        }
        self.consecutive_failures += 1;
        if self.consecutive_failures > MAX_CONSECUTIVE_FAILURES {
            return Decision::Escalate;
        }
        Decision::Retry(backoff(self.consecutive_failures))
    }
}

fn backoff(failure: u32) -> Duration {
    INITIAL_BACKOFF
        .saturating_mul(1 << failure.saturating_sub(1).min(16))
        .min(MAX_BACKOFF)
}

/// Extracts the Win32 code from an HRESULT of the `FACILITY_WIN32` form.
pub(super) fn win32_code(hresult: i32) -> Option<u32> {
    let value = hresult as u32;
    (value >> 16 == 0x8007).then_some(value & 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL_NOT_FOUND: u32 = 15007;
    const QUERY_RESULT_STALE: u32 = 15011;

    #[test]
    fn channel_not_found_and_stale_are_retryable() {
        assert_eq!(classify(Some(CHANNEL_NOT_FOUND)), Retryability::Retryable);
        assert_eq!(classify(Some(QUERY_RESULT_STALE)), Retryability::Retryable);
        assert_eq!(classify(Some(1722)), Retryability::Retryable);
    }

    #[test]
    fn permanent_and_codeless_failures_escalate_immediately() {
        let mut state = RetryState::default();
        for code in [
            None,
            Some(ERROR_ACCESS_DENIED),
            Some(ERROR_INVALID_PARAMETER),
            Some(ERROR_EVT_INVALID_QUERY),
        ] {
            assert_eq!(state.on_failure(code, Duration::ZERO), Decision::Escalate);
        }
    }

    #[test]
    fn backoff_grows_then_caps() {
        let mut state = RetryState::default();
        let delays: Vec<_> = (0..6)
            .map(|_| state.on_failure(Some(CHANNEL_NOT_FOUND), Duration::ZERO))
            .collect();
        assert_eq!(
            delays,
            [1, 2, 4, 8, 16, 30]
                .map(|s| Decision::Retry(Duration::from_secs(s)))
                .to_vec()
        );
    }

    #[test]
    fn exhausted_retries_escalate() {
        let mut state = RetryState::default();
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            assert!(matches!(
                state.on_failure(Some(CHANNEL_NOT_FOUND), Duration::ZERO),
                Decision::Retry(_)
            ));
        }
        assert_eq!(
            state.on_failure(Some(CHANNEL_NOT_FOUND), Duration::ZERO),
            Decision::Escalate
        );
    }

    #[test]
    fn stable_session_restores_the_budget() {
        let mut state = RetryState::default();
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            state.on_failure(Some(CHANNEL_NOT_FOUND), Duration::ZERO);
        }
        assert_eq!(
            state.on_failure(Some(CHANNEL_NOT_FOUND), STABLE_SESSION),
            Decision::Retry(INITIAL_BACKOFF)
        );
    }

    #[test]
    fn the_startup_hresult_from_ci_is_retryable() {
        let code = win32_code(0x8007_3A9F_u32 as i32);
        assert_eq!(code, Some(CHANNEL_NOT_FOUND));
        assert_eq!(classify(code), Retryability::Retryable);
    }

    #[test]
    fn win32_codes_come_from_win32_hresults_only() {
        assert_eq!(win32_code(0x8007_3A9F_u32 as i32), Some(15007));
        assert_eq!(win32_code(0x8000_4005_u32 as i32), None);
        assert_eq!(win32_code(0), None);
    }
}
