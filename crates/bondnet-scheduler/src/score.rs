//! Scoring policy: turns [`PathState`](crate::PathState) into a selection weight.
//!
//! Scoring is isolated behind [`PathScorer`] on purpose: the MVP formula in
//! [`DefaultScorer`] can later be replaced by measured-throughput or
//! congestion-aware policies without touching the scheduler mechanics.

use crate::path::{PathHealth, PathState};

/// Selection weight for one path. Larger means "selected more often"; zero
/// means "never selected".
///
/// Implementors must be deterministic: the same [`PathState`] must always
/// produce the same weight, or scheduler tests stop being reproducible.
pub trait PathScorer {
    /// Compute the selection weight for a path. Must not panic on any input.
    fn score(&self, state: &PathState) -> u64;
}

/// Upper bound for any single path weight. Keeps the smooth weighted
/// round-robin accumulators far from overflow no matter how many paths exist.
pub const MAX_WEIGHT: u64 = u64::MAX / 1024;

/// First MVP scorer: multiplicative per-mille factors over bandwidth.
///
/// ```text
/// weight = bandwidth × health × latency × loss × jitter × congestion
/// ```
///
/// Every factor after bandwidth is expressed per-mille (0–1000), the product
/// is computed in `u128`, and the result is scaled back down by `1000^5` and
/// clamped to [`MAX_WEIGHT`]. Multiplicative (not additive) so that one
/// terrible factor — an unhealthy path, a saturated path — can genuinely
/// veto or crush a path instead of being averaged away.
///
/// Factor reasoning:
/// - **bandwidth**: linear in `bandwidth_bps`. No assumed speed ceiling, so
///   no normalization constant to outgrow; `u128` absorbs `u64::MAX`.
/// - **health**: `Healthy = 1000`, `Degraded = 250` (eligible but quartered),
///   `Unhealthy = 0` (hard exclusion — a zero factor zeroes the product).
/// - **latency**: `1000 × 20 / (rtt_ms + 20)`. Decays smoothly; `rtt_ms = 0`
///   ("unknown") scores 1000 instead of dividing by zero.
/// - **loss**: `1_000_000 / (1000 + loss_ppm / 100)`. Zero loss scores 1000;
///   1% loss ≈ 909, 10% ≈ 500, and it can never divide by zero.
/// - **jitter**: same decay shape as loss over `jitter_ms`.
/// - **congestion**: compares `in_flight_bytes` against `capacity_bytes`;
///   at the target the factor is 500, double the target ≈ 333, idle = 1000.
///   `capacity_bytes = 0` ("unknown") disables the penalty.
///
/// Zero bandwidth yields weight zero, hence "never selected" — that is the
/// defined behavior, not a special case.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultScorer;

/// Per-mille denominator shared by every factor after bandwidth.
const PER_MILLE: u128 = 1000;

fn health_factor(health: PathHealth) -> u64 {
    match health {
        PathHealth::Healthy => 1000,
        PathHealth::Degraded => 250,
        PathHealth::Unhealthy => 0,
    }
}

fn latency_factor(rtt_ms: u32) -> u64 {
    // Reference RTT: 20 ms scores 500. Zero RTT ("unknown") scores 1000;
    // the `+ 20` makes division by zero impossible.
    const REF_MS: u64 = 20;
    REF_MS * 1000 / (u64::from(rtt_ms) + REF_MS)
}

fn loss_factor(loss_ppm: u32) -> u64 {
    // loss_ppm / 100 keeps u64 arithmetic; the + 1000 floors the divisor.
    1_000_000 / (1000 + u64::from(loss_ppm) / 100)
}

fn jitter_factor(jitter_ms: u32) -> u64 {
    1_000_000 / (1000 + u64::from(jitter_ms))
}

fn congestion_factor(in_flight_bytes: u64, capacity_bytes: u64) -> u64 {
    if capacity_bytes == 0 {
        return 1000;
    }
    // Load in parts per million, computed in u128 so u64::MAX in-flight
    // bytes cannot overflow. Saturates instead of wrapping.
    let load_ppm = (in_flight_bytes as u128)
        .saturating_mul(1_000_000)
        .checked_div(capacity_bytes as u128)
        .unwrap_or(u128::MAX);
    (1_000_000 / (1000 + load_ppm / 1000)) as u64
}

impl PathScorer for DefaultScorer {
    fn score(&self, state: &PathState) -> u64 {
        let health = u128::from(health_factor(state.health));
        if health == 0 {
            return 0;
        }
        let stats = &state.stats;
        // Five per-mille factors: 1000^5 = 1e15. Even u64::MAX bandwidth
        // (1.8e19) times that product is ~1.2e37, far below u128::MAX
        // (~3.4e38); saturating_mul is belt-and-braces regardless.
        let product = (stats.bandwidth_bps as u128)
            .saturating_mul(health)
            .saturating_mul(u128::from(latency_factor(stats.rtt_ms)))
            .saturating_mul(u128::from(loss_factor(stats.loss_ppm)))
            .saturating_mul(u128::from(jitter_factor(stats.jitter_ms)))
            .saturating_mul(u128::from(congestion_factor(
                stats.in_flight_bytes,
                stats.capacity_bytes,
            )));
        let weight = product / PER_MILLE.pow(5);
        weight.min(u128::from(MAX_WEIGHT)) as u64
    }
}
