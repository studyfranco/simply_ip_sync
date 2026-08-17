//! Shared exponential-backoff-with-jitter retry policy for outbound HTTP calls — used by
//! `client.rs` (calls to remote vault endpoints) and `jobs::external_ingestion` (calls to
//! external feed sources) alike, so both pipelines treat a transient upstream failure the same
//! way.

use rand::RngExt;

/// HTTP status codes considered transient and worth retrying unchanged: rate limiting and
/// upstream/gateway errors that often resolve themselves shortly after. Deliberately excludes
/// `500` (an origin bug retrying the identical request is unlikely to fix) and `413` (handled
/// separately by adaptive batch splitting in `client::post_batch` — retrying an oversized payload
/// unchanged can never succeed, no matter how many times or how long the wait).
pub fn is_transient_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

/// Computes the delay before retry attempt `attempt` (1-based: the first retry is `attempt = 1`).
/// Exponential backoff off `config::outbound_retry_backoff()`, capped at 30s so a misconfigured
/// base value or a very high attempt count can never produce an unreasonably long sleep, plus up
/// to 50% jitter — jitter exists so that if several jobs hit the same recovering target at once,
/// their retries don't all land in the same instant and repeat the overload that caused the
/// transient failure in the first place.
pub fn backoff_with_jitter(attempt: u32) -> std::time::Duration {
    let base = crate::config::outbound_retry_backoff();
    let shift = attempt.saturating_sub(1).min(10); // cap exponent growth well before overflow
    let multiplier = 2u32.checked_pow(shift).unwrap_or(u32::MAX);
    let exp = base.saturating_mul(multiplier);
    let capped = exp.min(std::time::Duration::from_secs(30));
    let jitter_ceiling_ms = ((capped.as_millis() as u64) / 2).max(1);
    let jitter_ms = rand::rng().random_range(0..=jitter_ceiling_ms);
    capped + std::time::Duration::from_millis(jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_statuses_are_exactly_the_documented_set() {
        for status in [429, 502, 503, 504] {
            assert!(is_transient_status(status), "{status} must be treated as transient");
        }
        for status in [400, 401, 403, 404, 409, 413, 500, 501] {
            assert!(!is_transient_status(status), "{status} must NOT be treated as transient");
        }
    }

    #[test]
    fn backoff_grows_with_attempt_number_and_stays_capped() {
        unsafe {
            std::env::set_var("OUTBOUND_RETRY_BACKOFF_MS", "100");
        }
        let first = backoff_with_jitter(1);
        let second = backoff_with_jitter(2);
        let far_future = backoff_with_jitter(50);

        assert!(first >= std::time::Duration::from_millis(100), "attempt 1 must be at least the base backoff");
        assert!(first < std::time::Duration::from_millis(200), "attempt 1 must not already include a doubling");
        assert!(second >= std::time::Duration::from_millis(200), "attempt 2 must have backed off further than attempt 1's minimum");
        assert!(far_future <= std::time::Duration::from_secs(30) + std::time::Duration::from_secs(15), "backoff must stay bounded even for a very high attempt count");
        unsafe {
            std::env::remove_var("OUTBOUND_RETRY_BACKOFF_MS");
        }
    }
}
