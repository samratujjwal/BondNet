//! Day 17: health diagnostics command.
//!
//! `bondnet-client health-diag` demonstrates the path health state
//! machine with a deterministic simulated scenario. It does not require
//! network access.
//!
//! For live health monitoring, use the `HealthMonitor` API.

use crate::health::{HealthConfig, HealthState, PathHealthTracker};

/// Run the health diagnostics.
pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let verbose = args.iter().any(|a| a == "--verbose");

    println!("=== BondNet Day 17 Health Diagnostics ===\n");

    println!("State machine:");
    println!("  Unknown → Healthy ⇄ Degraded → Unhealthy → Recovering → Healthy");
    println!();
    println!("Default thresholds:");
    let cfg = HealthConfig::default();
    println!("  Heartbeat interval: {:?}", cfg.heartbeat_interval);
    println!("  Probe timeout: {:?}", cfg.probe_timeout);
    println!("  Degraded after {} misses", cfg.degraded_threshold);
    println!("  Unhealthy after {} misses", cfg.unhealthy_threshold);
    println!("  Recovery after {} successes", cfg.recovery_threshold);
    println!("  Degraded after {} send errors", cfg.send_error_threshold);
    println!();

    // Simulated scenario: path goes unhealthy, then recovers.
    println!("--- Simulated scenario: failure then recovery ---");
    let mut tracker = PathHealthTracker::new(1, HealthConfig::default());

    // 1. Path becomes healthy.
    let id = tracker.new_probe();
    tracker.on_response(id);
    println!("After 1 response: {:?}", tracker.state());
    assert_eq!(tracker.state(), HealthState::Healthy);

    // 2. Misses drive it to Degraded, then Unhealthy.
    tracker.on_miss();
    tracker.on_miss();
    println!("After 2 misses: {:?}", tracker.state());
    assert_eq!(tracker.state(), HealthState::Degraded);
    tracker.on_miss();
    println!("After 3 misses: {:?}", tracker.state());
    assert_eq!(tracker.state(), HealthState::Unhealthy);

    // 3. Recovery requires 3 consecutive successes.
    for i in 1..=3 {
        let id = tracker.new_probe();
        tracker.on_response(id);
        println!("After {} recovery response(s): {:?}", i, tracker.state());
    }
    assert_eq!(tracker.state(), HealthState::Healthy);

    let m = tracker.metrics_snapshot();
    println!();
    println!("Metrics:");
    println!("  Probes sent: {}", m.probes_sent);
    println!("  Responses received: {}", m.responses_received);
    println!("  Misses: {}", m.misses);
    println!("  State transitions: {}", m.state_transitions);
    println!("  Recoveries: {}", m.recoveries);

    if verbose {
        println!();
        println!("Scheduler mapping:");
        println!("  Healthy → Healthy (eligible, full weight)");
        println!("  Degraded → Degraded (eligible, reduced weight)");
        println!("  Unhealthy → Unhealthy (excluded from scheduling)");
        println!("  Unknown/Recovering → Degraded (cautious, eligible)");
    }

    println!();
    println!("NOTE: This is a deterministic simulation. Live health");
    println!("monitoring requires a running server that echoes PathKeepalive.");
    Ok(())
}
