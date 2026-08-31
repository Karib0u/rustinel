use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct RateLimitDecision {
    pub should_emit: bool,
    pub suppressed_since_last_emit: u64,
}

#[derive(Debug, Clone)]
struct LimiterState {
    last_emit: Instant,
    suppressed: u64,
}

#[derive(Debug, Clone)]
pub struct LogRateLimiter {
    window: Duration,
    states: HashMap<String, LimiterState>,
}

impl LogRateLimiter {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            states: HashMap::new(),
        }
    }

    pub fn should_emit(&mut self, key: &str) -> RateLimitDecision {
        let now = Instant::now();

        match self.states.get_mut(key) {
            None => {
                self.states.insert(
                    key.to_string(),
                    LimiterState {
                        last_emit: now,
                        suppressed: 0,
                    },
                );
                RateLimitDecision {
                    should_emit: true,
                    suppressed_since_last_emit: 0,
                }
            }
            Some(state) => {
                if now.duration_since(state.last_emit) >= self.window {
                    let suppressed = state.suppressed;
                    state.last_emit = now;
                    state.suppressed = 0;
                    RateLimitDecision {
                        should_emit: true,
                        suppressed_since_last_emit: suppressed,
                    }
                } else {
                    state.suppressed = state.suppressed.saturating_add(1);
                    RateLimitDecision {
                        should_emit: false,
                        suppressed_since_last_emit: 0,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract every caller relies on: the first occurrence is always
    /// reported, the burst behind it is folded away, and the next emission
    /// says how much was folded.
    #[test]
    fn the_first_event_emits_and_the_burst_behind_it_is_suppressed() {
        let mut limiter = LogRateLimiter::new(Duration::from_millis(20));

        let first = limiter.should_emit("scan_error");
        assert!(first.should_emit);
        assert_eq!(first.suppressed_since_last_emit, 0);

        for _ in 0..4 {
            assert!(!limiter.should_emit("scan_error").should_emit);
        }

        std::thread::sleep(Duration::from_millis(25));

        let next = limiter.should_emit("scan_error");
        assert!(next.should_emit, "the window has elapsed");
        assert_eq!(
            next.suppressed_since_last_emit, 4,
            "the emission accounts for everything it stood in for"
        );
        // The count resets once reported, rather than accumulating across
        // windows and overstating the next burst.
        for _ in 0..2 {
            assert!(!limiter.should_emit("scan_error").should_emit);
        }
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(
            limiter.should_emit("scan_error").suppressed_since_last_emit,
            2
        );
    }

    /// Keys are independent, so a noisy error cannot silence the first report
    /// of a different one.
    #[test]
    fn keys_are_rate_limited_independently() {
        let mut limiter = LogRateLimiter::new(Duration::from_secs(60));

        assert!(limiter.should_emit("hash_error").should_emit);
        assert!(!limiter.should_emit("hash_error").should_emit);
        assert!(limiter.should_emit("memory_scan_error").should_emit);
    }
}
