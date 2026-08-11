//! Anti-replay guard: records accepted signatures within the freshness window and refuses
//! repeats.
//!
//! Must not hold freshness/skew policy — that lives in `middleware.rs`, which decides the window
//! length and only calls [`ReplayGuard::check_and_record`] after signature verification has
//! already succeeded (recording an unverified digest would be a pre-insertion DoS vector against
//! the legitimate client).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use uuid::Uuid;

/// A signature is identified by the API key that produced it plus the raw decoded HMAC digest
/// bytes (never the header text, so `sha256=AB…` and `sha256=ab…` cannot double-count).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SignatureId {
    key_id: Uuid,
    digest: Vec<u8>,
}

/// Upper bound on tracked signatures before capacity-triggered sweeps kick in.
const MAX_TRACKED_SIGNATURES: usize = 100_000;

/// In-memory, single-use signature cache keyed on the monotonic clock.
pub struct ReplayGuard {
    seen: Mutex<HashMap<SignatureId, Instant>>,
    window: Duration,
    last_sweep: Mutex<Instant>,
}

impl ReplayGuard {
    /// Builds a guard with the given freshness window, clamped to `[1, 3600]` seconds.
    pub fn new(window_secs: i64) -> Self {
        let clamped = window_secs.clamp(1, 3600) as u64;
        Self {
            seen: Mutex::new(HashMap::new()),
            window: Duration::from_secs(clamped),
            last_sweep: Mutex::new(Instant::now()),
        }
    }

    /// Checks whether `(key_id, digest)` has already been recorded within the window and, if not,
    /// records it. Returns `true` on first use, `false` on replay (or a poisoned lock, which fails
    /// closed by treating the request as a replay).
    pub fn check_and_record(&self, key_id: Uuid, digest: &[u8]) -> bool {
        let now = Instant::now();
        self.prune_if_due(now);
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        let id = SignatureId {
            key_id,
            digest: digest.to_vec(),
        };
        match seen.get(&id) {
            Some(expires_at) if *expires_at > now => false,
            _ => {
                seen.insert(id, now + self.window);
                true
            }
        }
    }

    fn prune_if_due(&self, now: Instant) {
        let routine_interval = self.window / 4;
        let due = match self.last_sweep.lock() {
            Ok(mut last) => {
                if now.duration_since(*last) >= routine_interval {
                    *last = now;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        };
        let over_capacity = self
            .seen
            .lock()
            .map(|seen| seen.len() >= MAX_TRACKED_SIGNATURES)
            .unwrap_or(false);
        if (due || over_capacity) && let Ok(mut seen) = self.seen.lock() {
            // Saturation is never flushed wholesale — clearing would let every currently
            // valid signature replay at once. Only truly expired entries are removed.
            seen.retain(|_, expires_at| *expires_at > now);
        }
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(crate::crypto::MAX_TIMESTAMP_SKEW_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_use_accepted_second_use_rejected() {
        let guard = ReplayGuard::new(300);
        let key_id = Uuid::new_v4();
        let digest = vec![1, 2, 3];
        assert!(guard.check_and_record(key_id, &digest));
        assert!(!guard.check_and_record(key_id, &digest));
    }

    #[tokio::test]
    async fn different_keys_do_not_collide() {
        let guard = ReplayGuard::new(300);
        let digest = vec![1, 2, 3];
        assert!(guard.check_and_record(Uuid::new_v4(), &digest));
        assert!(guard.check_and_record(Uuid::new_v4(), &digest));
    }

    #[tokio::test(start_paused = true)]
    async fn entry_expires_after_window() {
        let guard = ReplayGuard::new(1);
        let key_id = Uuid::new_v4();
        let digest = vec![9, 9, 9];
        assert!(guard.check_and_record(key_id, &digest));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(guard.check_and_record(key_id, &digest));
    }
}
