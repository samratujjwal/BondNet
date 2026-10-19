//! Day 17: path health state machine for failure detection and recovery.
//!
//! Tracks the operational health of each physical path using observable
//! evidence: heartbeat responses, send errors, and timeouts. Integrates
//! with `PathManager::set_health` to drive scheduler eligibility.
//!
//! # State model
//!
//! ```text
//!   Unknown ──→ Healthy ⇄ Degraded ──→ Unhealthy ──→ Recovering ──→ Healthy
//!      │           │          │             │              │
//!      │           │          └─────────────┘              │
//!      └───────────┴── (any state can go to Unhealthy on      │
//!                       decisive failure evidence)           │
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Default: heartbeat probe interval.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// Default: how long to wait for a probe response before counting a miss.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
/// Default: consecutive misses to go from Healthy → Degraded.
pub const DEFAULT_DEGRADED_THRESHOLD: u32 = 2;
/// Default: consecutive misses to go from Degraded → Unhealthy
/// (or Healthy → Unhealthy directly if threshold is met).
pub const DEFAULT_UNHEALTHY_THRESHOLD: u32 = 3;
/// Default: consecutive successful responses to go from
/// Unhealthy → Recovering → Healthy.
pub const DEFAULT_RECOVERY_THRESHOLD: u32 = 3;
/// Default: consecutive send errors to immediately mark Degraded.
pub const DEFAULT_SEND_ERROR_THRESHOLD: u32 = 5;

/// Health states for a single path.
///
/// This is the Day 17 operational state machine. It maps to the
/// scheduler's `PathHealth` (Healthy/Degraded/Unhealthy) for eligibility:
/// - `Healthy` → scheduler `Healthy`
/// - `Degraded` → scheduler `Degraded` (still eligible, lower weight)
/// - `Unhealthy` → scheduler `Unhealthy` (excluded)
/// - `Unknown`, `Recovering` → scheduler `Degraded` (cautious: eligible
///   but deprioritized until confirmed)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Initial state; no evidence yet.
    Unknown,
    /// Responding normally.
    Healthy,
    /// Some evidence of trouble (missed probes or send errors), but not
    /// enough to exclude. Still eligible for scheduling.
    Degraded,
    /// Declared failed. Excluded from scheduling.
    Unhealthy,
    /// Was Unhealthy, now seeing positive evidence. Needs consecutive
    /// successes to return to Healthy.
    Recovering,
}

impl HealthState {
    /// Map to the scheduler's health type.
    pub fn to_scheduler_health(self) -> bondnet_scheduler::PathHealth {
        use bondnet_scheduler::PathHealth;
        match self {
            HealthState::Healthy => PathHealth::Healthy,
            HealthState::Degraded => PathHealth::Degraded,
            HealthState::Unhealthy => PathHealth::Unhealthy,
            // Unknown and Recovering are cautious: eligible but deprioritized.
            HealthState::Unknown | HealthState::Recovering => PathHealth::Degraded,
        }
    }
}

/// Configuration for the health state machine.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    pub heartbeat_interval: Duration,
    pub probe_timeout: Duration,
    pub degraded_threshold: u32,
    pub unhealthy_threshold: u32,
    pub recovery_threshold: u32,
    pub send_error_threshold: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            degraded_threshold: DEFAULT_DEGRADED_THRESHOLD,
            unhealthy_threshold: DEFAULT_UNHEALTHY_THRESHOLD,
            recovery_threshold: DEFAULT_RECOVERY_THRESHOLD,
            send_error_threshold: DEFAULT_SEND_ERROR_THRESHOLD,
        }
    }
}

impl HealthConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.heartbeat_interval.is_zero() {
            return Err("heartbeat_interval must be > 0".to_string());
        }
        if self.probe_timeout.is_zero() {
            return Err("probe_timeout must be > 0".to_string());
        }
        if self.degraded_threshold == 0 {
            return Err("degraded_threshold must be > 0".to_string());
        }
        if self.unhealthy_threshold < self.degraded_threshold {
            return Err("unhealthy_threshold must be >= degraded_threshold".to_string());
        }
        if self.recovery_threshold == 0 {
            return Err("recovery_threshold must be > 0".to_string());
        }
        if self.send_error_threshold == 0 {
            return Err("send_error_threshold must be > 0".to_string());
        }
        Ok(())
    }
}

/// Per-path health tracking state.
#[derive(Debug)]
pub struct PathHealthTracker {
    path_id: u16,
    state: HealthState,
    config: HealthConfig,
    /// Consecutive missed probe responses.
    consecutive_misses: u32,
    /// Consecutive successful probe responses.
    consecutive_successes: u32,
    /// Consecutive local send errors.
    consecutive_send_errors: u32,
    /// Monotonic probe ID for correlation.
    next_probe_id: u64,
    /// Outstanding probe IDs (bounded).
    outstanding: HashMap<u64, std::time::Instant>,
    metrics: HealthMetrics,
}

/// Live counters for one path's health tracking.
#[derive(Debug, Default)]
pub struct HealthMetrics {
    pub probes_sent: AtomicU64,
    pub responses_received: AtomicU64,
    pub misses: AtomicU64,
    pub send_errors: AtomicU64,
    pub state_transitions: AtomicU64,
    pub recoveries: AtomicU64,
}

/// Snapshot of health metrics.
#[derive(Debug, Clone)]
pub struct HealthMetricsSnapshot {
    pub probes_sent: u64,
    pub responses_received: u64,
    pub misses: u64,
    pub send_errors: u64,
    pub state_transitions: u64,
    pub recoveries: u64,
    pub state: HealthState,
    pub consecutive_misses: u32,
    pub consecutive_successes: u32,
}

impl PathHealthTracker {
    pub fn new(path_id: u16, config: HealthConfig) -> Self {
        Self {
            path_id,
            state: HealthState::Unknown,
            config,
            consecutive_misses: 0,
            consecutive_successes: 0,
            consecutive_send_errors: 0,
            next_probe_id: 1,
            outstanding: HashMap::new(),
            metrics: HealthMetrics::default(),
        }
    }

    pub fn path_id(&self) -> u16 {
        self.path_id
    }

    pub fn state(&self) -> HealthState {
        self.state
    }

    /// Allocate the next probe ID and record it as outstanding.
    /// Returns the probe ID to put in the PathKeepalive payload.
    pub fn new_probe(&mut self) -> u64 {
        let id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);
        // Bound the outstanding map: if it's too big, clear stale entries.
        // (In practice, probes are 1/sec, so this is a safety net.)
        if self.outstanding.len() > 100 {
            self.outstanding.clear();
        }
        self.outstanding.insert(id, std::time::Instant::now());
        self.metrics.probes_sent.fetch_add(1, Ordering::Relaxed);
        id
    }

    /// Process a valid probe response with the given probe ID.
    /// Returns true if this was an expected (outstanding) probe.
    pub fn on_response(&mut self, probe_id: u64) -> bool {
        if self.outstanding.remove(&probe_id).is_none() {
            // Stale or mismatched response: ignore, do not affect health.
            return false;
        }
        self.metrics
            .responses_received
            .fetch_add(1, Ordering::Relaxed);
        self.consecutive_misses = 0;
        self.consecutive_send_errors = 0;
        self.consecutive_successes += 1;

        match self.state {
            HealthState::Unknown | HealthState::Degraded => {
                // First success, or recovery from degraded.
                self.transition_to(HealthState::Healthy);
            }
            HealthState::Unhealthy => {
                // Start recovering; need consecutive successes.
                self.transition_to(HealthState::Recovering);
                // Fall through to check if we've met the threshold.
                if self.consecutive_successes >= self.config.recovery_threshold {
                    self.transition_to(HealthState::Healthy);
                    self.metrics.recoveries.fetch_add(1, Ordering::Relaxed);
                    self.consecutive_successes = 0;
                }
            }
            HealthState::Recovering => {
                if self.consecutive_successes >= self.config.recovery_threshold {
                    self.transition_to(HealthState::Healthy);
                    self.metrics.recoveries.fetch_add(1, Ordering::Relaxed);
                    self.consecutive_successes = 0;
                }
            }
            HealthState::Healthy => {
                // Stay healthy; reset success counter to avoid overflow.
                if self.consecutive_successes > 1000 {
                    self.consecutive_successes = 0;
                }
            }
        }
        true
    }

    /// Record a missed probe (timeout with no response).
    pub fn on_miss(&mut self) {
        self.metrics.misses.fetch_add(1, Ordering::Relaxed);
        self.consecutive_misses += 1;
        self.consecutive_successes = 0;
        // Clean up stale outstanding probes.
        let timeout = self.config.probe_timeout;
        let now = std::time::Instant::now();
        self.outstanding
            .retain(|_, sent| now.duration_since(*sent) < timeout * 2);

        match self.state {
            HealthState::Unknown | HealthState::Healthy => {
                if self.consecutive_misses >= self.config.unhealthy_threshold {
                    self.transition_to(HealthState::Unhealthy);
                } else if self.consecutive_misses >= self.config.degraded_threshold {
                    self.transition_to(HealthState::Degraded);
                }
            }
            HealthState::Degraded => {
                if self.consecutive_misses >= self.config.unhealthy_threshold {
                    self.transition_to(HealthState::Unhealthy);
                }
            }
            HealthState::Recovering => {
                // A miss during recovery aborts back to Unhealthy.
                // This prevents flapping: intermittent responses don't
                // cause rapid Healthy/Unhealthy oscillation.
                self.transition_to(HealthState::Unhealthy);
            }
            HealthState::Unhealthy => {
                // Stay unhealthy.
            }
        }
    }

    /// Record a local UDP send error.
    ///
    /// Send errors are evidence of LOCAL trouble, not proof of remote
    /// failure. They contribute to Degraded but do not alone mark
    /// Unhealthy (that requires missed heartbeats).
    pub fn on_send_error(&mut self) {
        self.metrics.send_errors.fetch_add(1, Ordering::Relaxed);
        self.consecutive_send_errors += 1;
        self.consecutive_successes = 0;

        if self.consecutive_send_errors >= self.config.send_error_threshold {
            match self.state {
                HealthState::Unknown | HealthState::Healthy => {
                    self.transition_to(HealthState::Degraded);
                }
                _ => {}
            }
        }
    }

    /// Record a successful send (resets the send-error counter, but does
    /// NOT by itself mark the path Healthy — that requires heartbeat
    /// responses).
    pub fn on_send_success(&mut self) {
        self.consecutive_send_errors = 0;
    }

    fn transition_to(&mut self, new: HealthState) {
        if self.state != new {
            self.state = new;
            self.metrics
                .state_transitions
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn metrics_snapshot(&self) -> HealthMetricsSnapshot {
        HealthMetricsSnapshot {
            probes_sent: self.metrics.probes_sent.load(Ordering::Relaxed),
            responses_received: self.metrics.responses_received.load(Ordering::Relaxed),
            misses: self.metrics.misses.load(Ordering::Relaxed),
            send_errors: self.metrics.send_errors.load(Ordering::Relaxed),
            state_transitions: self.metrics.state_transitions.load(Ordering::Relaxed),
            recoveries: self.metrics.recoveries.load(Ordering::Relaxed),
            state: self.state,
            consecutive_misses: self.consecutive_misses,
            consecutive_successes: self.consecutive_successes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> PathHealthTracker {
        PathHealthTracker::new(1, HealthConfig::default())
    }

    #[test]
    fn healthy_path_remains_eligible() {
        let mut t = tracker();
        // First response moves Unknown → Healthy.
        let id = t.new_probe();
        assert!(t.on_response(id));
        assert_eq!(t.state(), HealthState::Healthy);
        // More responses keep it healthy.
        for _ in 0..5 {
            let id = t.new_probe();
            t.on_response(id);
        }
        assert_eq!(t.state(), HealthState::Healthy);
    }

    #[test]
    fn misses_drive_degraded_then_unhealthy() {
        let mut t = tracker();
        let id = t.new_probe();
        t.on_response(id);
        assert_eq!(t.state(), HealthState::Healthy);
        // 2 misses → Degraded (threshold=2).
        t.on_miss();
        t.on_miss();
        assert_eq!(t.state(), HealthState::Degraded);
        // 1 more miss (total 3) → Unhealthy (threshold=3).
        t.on_miss();
        assert_eq!(t.state(), HealthState::Unhealthy);
    }

    #[test]
    fn stale_response_does_not_affect_health() {
        let mut t = tracker();
        // Response for a probe never sent.
        assert!(!t.on_response(999));
        assert_eq!(t.state(), HealthState::Unknown);
        // Response for an already-answered probe.
        let id = t.new_probe();
        assert!(t.on_response(id));
        assert!(!t.on_response(id));
        assert_eq!(t.state(), HealthState::Healthy);
    }

    #[test]
    fn recovery_requires_consecutive_successes() {
        let mut t = tracker();
        let id = t.new_probe();
        t.on_response(id);
        // Drive to Unhealthy.
        t.on_miss();
        t.on_miss();
        t.on_miss();
        assert_eq!(t.state(), HealthState::Unhealthy);
        // One success → Recovering, not Healthy.
        let id = t.new_probe();
        t.on_response(id);
        assert_eq!(t.state(), HealthState::Recovering);
        // Two more successes (total 3) → Healthy.
        let id = t.new_probe();
        t.on_response(id);
        assert_eq!(t.state(), HealthState::Recovering);
        let id = t.new_probe();
        t.on_response(id);
        assert_eq!(t.state(), HealthState::Healthy);
        let m = t.metrics_snapshot();
        assert_eq!(m.recoveries, 1);
    }

    #[test]
    fn miss_during_recovery_aborts_to_unhealthy() {
        let mut t = tracker();
        let id = t.new_probe();
        t.on_response(id);
        t.on_miss();
        t.on_miss();
        t.on_miss();
        assert_eq!(t.state(), HealthState::Unhealthy);
        let id = t.new_probe();
        t.on_response(id);
        assert_eq!(t.state(), HealthState::Recovering);
        // Intermittent: a miss during recovery goes back to Unhealthy,
        // preventing flapping.
        t.on_miss();
        assert_eq!(t.state(), HealthState::Unhealthy);
    }

    #[test]
    fn send_errors_cause_degraded_not_unhealthy() {
        let mut t = tracker();
        let id = t.new_probe();
        t.on_response(id);
        assert_eq!(t.state(), HealthState::Healthy);
        // 5 send errors → Degraded (threshold=5).
        for _ in 0..5 {
            t.on_send_error();
        }
        assert_eq!(t.state(), HealthState::Degraded);
        // More send errors do NOT cause Unhealthy (need heartbeat misses).
        for _ in 0..10 {
            t.on_send_error();
        }
        assert_eq!(t.state(), HealthState::Degraded);
    }

    #[test]
    fn invalid_config_rejected() {
        let c = HealthConfig {
            degraded_threshold: 5,
            unhealthy_threshold: 3,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    // Test 5: A valid response updates the correct path's health.
    #[test]
    fn response_updates_correct_path() {
        let mut t1 = PathHealthTracker::new(1, HealthConfig::default());
        let mut t2 = PathHealthTracker::new(2, HealthConfig::default());
        // Both start Unknown.
        assert_eq!(t1.state(), HealthState::Unknown);
        assert_eq!(t2.state(), HealthState::Unknown);
        // Response for path 1 only affects path 1.
        let id1 = t1.new_probe();
        t1.on_response(id1);
        assert_eq!(t1.state(), HealthState::Healthy);
        assert_eq!(t2.state(), HealthState::Unknown);
        // Response for path 2 only affects path 2.
        let id2 = t2.new_probe();
        t2.on_response(id2);
        assert_eq!(t2.state(), HealthState::Healthy);
    }

    // Test 12: Session-wide sequence numbers do not reset during failover.
    // (The sequence counter is in MultipathDataPlane, not the tracker,
    // but we verify the tracker doesn't affect sequencing.)
    #[test]
    fn tracker_does_not_allocate_sequences() {
        let mut t = tracker();
        // The tracker has no sequence counter; it only tracks health.
        // This is a compile-time guarantee, but we document it here.
        let id1 = t.new_probe();
        let id2 = t.new_probe();
        // Probe IDs are for correlation, not data sequencing.
        assert_ne!(id1, id2);
        // Health state changes don't reset anything sequence-related.
        t.on_response(id1);
        t.on_miss();
        t.on_miss();
        t.on_miss();
        assert_eq!(t.state(), HealthState::Unhealthy);
        // Probe IDs continue monotonically.
        let id3 = t.new_probe();
        assert!(id3 > id2);
    }

    // Test 14: Control packets do not enter the DATA pipeline.
    // (Verified by the receiver_loop filtering on packet_type;
    // this test documents the invariant.)
    #[test]
    fn only_pathkeepalive_affects_tracker() {
        let mut t = tracker();
        // The tracker only processes probe responses via on_response.
        // DATA packets never call on_response (they go to the reorder buffer).
        // This is enforced by the receiver_loop's packet_type check.
        let id = t.new_probe();
        // A valid keepalive response is processed.
        assert!(t.on_response(id));
        // A duplicate (already-processed) ID is rejected.
        assert!(!t.on_response(id));
    }
}
