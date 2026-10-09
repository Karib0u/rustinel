//! Visible outcome for tests whose precondition the host may not meet.
//!
//! libtest captures output of passing tests, so a bare `return` or `eprintln!`
//! reports `ok` for a test that checked nothing. A skip prints a stable marker
//! that CI greps for (it re-runs these tests with `--nocapture`), and panics
//! when `RUSTINEL_FAIL_ON_SKIP` is set, for runners that must meet the
//! precondition.

pub(crate) const SKIP_MARKER: &str = "RUSTINEL_TEST_SKIPPED";

pub(crate) fn skip(reason: &str) {
    eprintln!("{SKIP_MARKER}: {reason}");
    assert!(
        std::env::var_os("RUSTINEL_FAIL_ON_SKIP").is_none(),
        "{reason} (RUSTINEL_FAIL_ON_SKIP is set)"
    );
}
