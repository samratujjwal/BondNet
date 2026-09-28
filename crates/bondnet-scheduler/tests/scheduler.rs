//! Day 4 scheduler tests: selection behavior, determinism, fairness,
//! health exclusion, and arithmetic edge cases. Everything here exercises
//! only the public API, and every test is fully deterministic — no RNG.

use std::collections::BTreeMap;

use bondnet_scheduler::{
    DefaultScorer, PathHealth, PathId, PathScorer, PathState, PathStats, Scheduler,
};

/// 1% loss = 10_000 ppm, 0.1% = 1_000 ppm.
fn stats(bandwidth_bps: u64, rtt_ms: u32, loss_ppm: u32) -> PathStats {
    PathStats::new(bandwidth_bps, rtt_ms, loss_ppm, 0, 0, 1_000_000)
}

fn healthy(id: u16, bandwidth_bps: u64, rtt_ms: u32, loss_ppm: u32) -> PathState {
    PathState::healthy(id, stats(bandwidth_bps, rtt_ms, loss_ppm))
}

fn count_selections(sched: &mut Scheduler, rounds: usize) -> BTreeMap<PathId, usize> {
    let mut counts: BTreeMap<PathId, usize> = BTreeMap::new();
    for _ in 0..rounds {
        let id = sched.select_path().expect("expected an eligible path");
        *counts.entry(id).or_insert(0) += 1;
    }
    counts
}

#[test]
fn empty_scheduler_selects_none() {
    let mut sched = Scheduler::new();
    assert_eq!(sched.path_count(), 0);
    assert_eq!(sched.select_path(), None);
    assert_eq!(sched.select_path(), None);
}

#[test]
fn single_healthy_path_always_selected() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    for _ in 0..1000 {
        assert_eq!(sched.select_path(), Some(PathId::new(0)));
    }
}

#[test]
fn unhealthy_path_never_selected() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    sched.update_path(PathState::new(
        PathId::new(1),
        PathHealth::Unhealthy,
        stats(1_000_000_000, 1, 0),
    ));
    // Even with far better raw numbers, the unhealthy path must lose.
    for _ in 0..2000 {
        assert_eq!(sched.select_path(), Some(PathId::new(0)));
    }
}

#[test]
fn all_unhealthy_selects_none() {
    let mut sched = Scheduler::new();
    sched.update_path(PathState::new(
        PathId::new(0),
        PathHealth::Unhealthy,
        stats(80_000_000, 30, 10_000),
    ));
    sched.update_path(PathState::new(
        PathId::new(1),
        PathHealth::Unhealthy,
        stats(120_000_000, 10, 2_000),
    ));
    assert_eq!(sched.select_path(), None);
}

#[test]
fn all_degraded_paths_are_eligible() {
    let mut sched = Scheduler::new();
    sched.update_path(PathState::new(
        PathId::new(0),
        PathHealth::Degraded,
        stats(80_000_000, 30, 10_000),
    ));
    sched.update_path(PathState::new(
        PathId::new(1),
        PathHealth::Degraded,
        stats(80_000_000, 30, 10_000),
    ));
    let counts = count_selections(&mut sched, 2000);
    assert_eq!(counts.len(), 2);
    assert!(counts.values().all(|&c| c > 0));
}

#[test]
fn degraded_path_penalized_vs_identical_healthy_path() {
    let mut sched = Scheduler::new();
    sched.update_path(PathState::new(
        PathId::new(0),
        PathHealth::Healthy,
        stats(80_000_000, 30, 10_000),
    ));
    sched.update_path(PathState::new(
        PathId::new(1),
        PathHealth::Degraded,
        stats(80_000_000, 30, 10_000),
    ));
    let counts = count_selections(&mut sched, 5000);
    let h = counts[&PathId::new(0)];
    let d = counts[&PathId::new(1)];
    assert!(h > d, "healthy ({h}) should beat degraded ({d})");
    assert!(d > 0, "degraded path must still get traffic");
}

#[test]
fn weighted_fairness_two_paths() {
    let mut sched = Scheduler::new();
    // Wi-Fi-like vs USB-like: better bandwidth, RTT, and loss.
    sched.update_path(healthy(0, 100_000_000, 10, 2_000));
    sched.update_path(healthy(1, 20_000_000, 70, 20_000));
    let counts = count_selections(&mut sched, 6000);
    let a = counts[&PathId::new(0)];
    let b = counts[&PathId::new(1)];
    assert_eq!(a + b, 6000);
    assert!(a > b, "higher score ({a}) must beat lower score ({b})");
    assert!(b > 0, "lower-score path must not starve");
}

#[test]
fn three_paths_share_by_weight() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 100_000_000, 10, 0));
    sched.update_path(healthy(1, 50_000_000, 10, 0));
    sched.update_path(healthy(2, 25_000_000, 10, 0));
    let counts = count_selections(&mut sched, 7000);
    let (a, b, c) = (
        counts[&PathId::new(0)],
        counts[&PathId::new(1)],
        counts[&PathId::new(2)],
    );
    assert!(
        a > b && b > c,
        "shares must follow weights: {a} > {b} > {c}"
    );
    assert!(c > 0);
}

#[test]
fn remove_path_never_selected_again() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    sched.update_path(healthy(1, 80_000_000, 30, 10_000));
    assert!(sched.remove_path(PathId::new(0)));
    assert_eq!(sched.path_count(), 1);
    for _ in 0..500 {
        assert_eq!(sched.select_path(), Some(PathId::new(1)));
    }
}

#[test]
fn remove_nonexistent_path_is_safe() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    assert!(!sched.remove_path(PathId::new(99)));
    assert_eq!(sched.select_path(), Some(PathId::new(0)));
}

#[test]
fn update_nonexistent_path_adds_it() {
    let mut sched = Scheduler::new();
    assert_eq!(sched.select_path(), None);
    sched.update_path(healthy(7, 80_000_000, 30, 10_000));
    assert_eq!(sched.path_count(), 1);
    assert_eq!(sched.select_path(), Some(PathId::new(7)));
}

#[test]
fn duplicate_path_id_replaces_state() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    sched.update_path(healthy(0, 40_000_000, 30, 10_000));
    assert_eq!(sched.path_count(), 1);
    let state = sched.get(PathId::new(0)).unwrap();
    assert_eq!(state.stats.bandwidth_bps, 40_000_000);
}

#[test]
fn update_changes_future_distribution() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 100_000_000, 10, 0));
    sched.update_path(healthy(1, 20_000_000, 10, 0));
    let before = count_selections(&mut sched, 3000);
    assert!(before[&PathId::new(0)] > before[&PathId::new(1)]);

    // A's bandwidth collapses; no rebuild, just an update.
    sched.update_path(healthy(0, 1_000_000, 10, 0));
    let after = count_selections(&mut sched, 3000);
    assert!(
        after[&PathId::new(1)] > after[&PathId::new(0)],
        "distribution must adapt: {:?}",
        after
    );
    assert!(after[&PathId::new(0)] > 0, "A must not starve entirely");
}

#[test]
fn selection_sequence_is_deterministic() {
    fn build() -> Scheduler {
        let mut s = Scheduler::new();
        s.update_path(healthy(0, 100_000_000, 10, 2_000));
        s.update_path(healthy(1, 20_000_000, 70, 20_000));
        s.update_path(PathState::new(
            PathId::new(2),
            PathHealth::Degraded,
            stats(50_000_000, 40, 5_000),
        ));
        s
    }
    let mut a = build();
    let mut b = build();
    let seq_a: Vec<_> = (0..2000).map(|_| a.select_path()).collect();
    let seq_b: Vec<_> = (0..2000).map(|_| b.select_path()).collect();
    assert_eq!(seq_a, seq_b);
}

#[test]
fn zero_bandwidth_path_is_excluded() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    sched.update_path(healthy(1, 0, 30, 10_000));
    assert_eq!(sched.weight_of(PathId::new(1)), Some(0));
    for _ in 0..500 {
        assert_eq!(sched.select_path(), Some(PathId::new(0)));
    }
    // Alone, a zero-bandwidth path yields no selection — defined, no panic.
    let mut lone = Scheduler::new();
    lone.update_path(healthy(1, 0, 30, 10_000));
    assert_eq!(lone.select_path(), None);
}

#[test]
fn huge_bandwidth_does_not_overflow() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, u64::MAX, 10, 0));
    sched.update_path(healthy(1, 80_000_000, 30, 10_000));
    let w = sched.weight_of(PathId::new(0)).unwrap();
    assert!(w > 0 && w <= bondnet_scheduler::MAX_WEIGHT);
    // Weight ratio here is ~3.4e8:1, so over a finite 2000-round sample the
    // smaller path legitimately gets nothing — smooth WRR is proportional,
    // not a starvation guarantee against absurd ratios. What matters: no
    // overflow, no panic, deterministic, and the big path wins outright.
    let counts = count_selections(&mut sched, 2000);
    assert_eq!(counts[&PathId::new(0)], 2000);
}

#[test]
fn zero_rtt_does_not_divide_by_zero() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 0, 10_000));
    assert!(sched.weight_of(PathId::new(0)).unwrap() > 0);
    for _ in 0..200 {
        assert_eq!(sched.select_path(), Some(PathId::new(0)));
    }
}

#[test]
fn many_paths_all_get_traffic() {
    let mut sched = Scheduler::new();
    for id in 0..8u16 {
        sched.update_path(healthy(id, 10_000_000 * u64::from(id + 1), 10, 0));
    }
    let counts = count_selections(&mut sched, 36_000);
    assert_eq!(counts.len(), 8);
    assert_eq!(counts.values().sum::<usize>(), 36_000);
    assert!(counts.values().all(|&c| c > 0), "{:?}", counts);
}

#[test]
fn path_id_boundaries() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    sched.update_path(healthy(u16::MAX, 80_000_000, 30, 10_000));
    let counts = count_selections(&mut sched, 2000);
    assert!(counts[&PathId::new(0)] > 0);
    assert!(counts[&PathId::new(u16::MAX)] > 0);
    assert!(sched.remove_path(PathId::new(u16::MAX)));
    assert_eq!(sched.select_path(), Some(PathId::new(0)));
}

/// A scorer that rates every path identically. The scheduler must still
/// exclude unhealthy paths: health exclusion is a scheduler invariant,
/// not a scoring-policy detail.
struct ConstantScorer;

impl PathScorer for ConstantScorer {
    fn score(&self, _state: &PathState) -> u64 {
        100
    }
}

#[test]
fn custom_scorer_cannot_select_unhealthy_path() {
    let mut sched: Scheduler<ConstantScorer> = Scheduler::with_scorer(ConstantScorer);
    sched.update_path(PathState::new(
        PathId::new(0),
        PathHealth::Unhealthy,
        stats(80_000_000, 30, 10_000),
    ));
    sched.update_path(PathState::new(
        PathId::new(1),
        PathHealth::Healthy,
        stats(80_000_000, 30, 10_000),
    ));
    for _ in 0..500 {
        assert_eq!(sched.select_path(), Some(PathId::new(1)));
    }
}

#[test]
fn congestion_penalizes_saturated_path() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    let mut saturated = stats(80_000_000, 30, 10_000);
    saturated.in_flight_bytes = 10_000_000; // 10x the capacity target
    sched.update_path(PathState::new(
        PathId::new(1),
        PathHealth::Healthy,
        saturated,
    ));
    let counts = count_selections(&mut sched, 6000);
    let idle = counts[&PathId::new(0)];
    let busy = counts[&PathId::new(1)];
    assert!(idle > busy, "idle ({idle}) must beat saturated ({busy})");
    assert!(busy > 0);
}

#[test]
fn scorer_ordering_matches_intuition() {
    let scorer = DefaultScorer;
    let base = stats(80_000_000, 30, 10_000);
    let healthy = PathState::new(PathId::new(0), PathHealth::Healthy, base);
    let degraded = PathState::new(PathId::new(1), PathHealth::Degraded, base);
    let unhealthy = PathState::new(PathId::new(2), PathHealth::Unhealthy, base);

    assert_eq!(scorer.score(&unhealthy), 0);
    assert!(scorer.score(&healthy) > scorer.score(&degraded));
    assert!(scorer.score(&degraded) > 0);

    // More bandwidth, less RTT, less loss each raise the score alone.
    let faster = PathState::healthy(3, stats(160_000_000, 30, 10_000));
    let snappier = PathState::healthy(4, stats(80_000_000, 5, 10_000));
    let cleaner = PathState::healthy(5, stats(80_000_000, 30, 0));
    let h = scorer.score(&healthy);
    assert!(scorer.score(&faster) > h);
    assert!(scorer.score(&snappier) > h);
    assert!(scorer.score(&cleaner) > h);
}

#[test]
fn loss_ppm_units_behave() {
    let scorer = DefaultScorer;
    let clean = PathState::healthy(0, stats(80_000_000, 30, 0));
    // 1% = 10_000 ppm scores lower than 0.1% = 1_000 ppm.
    let one_pct = PathState::healthy(1, stats(80_000_000, 30, 10_000));
    let tenth_pct = PathState::healthy(2, stats(80_000_000, 30, 1_000));
    assert!(scorer.score(&clean) > scorer.score(&tenth_pct));
    assert!(scorer.score(&tenth_pct) > scorer.score(&one_pct));
}

#[test]
fn weight_of_tracks_updates() {
    let mut sched = Scheduler::new();
    assert_eq!(sched.weight_of(PathId::new(0)), None);
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    let w1 = sched.weight_of(PathId::new(0)).unwrap();
    sched.update_path(healthy(0, 160_000_000, 30, 10_000));
    let w2 = sched.weight_of(PathId::new(0)).unwrap();
    assert!(w2 > w1, "doubling bandwidth must raise the weight");
}

#[test]
fn single_path_survives_removal_of_other() {
    let mut sched = Scheduler::new();
    sched.update_path(healthy(0, 80_000_000, 30, 10_000));
    sched.update_path(healthy(1, 80_000_000, 30, 10_000));
    sched.remove_path(PathId::new(1));
    let counts = count_selections(&mut sched, 1000);
    assert_eq!(counts.len(), 1);
    assert_eq!(counts[&PathId::new(0)], 1000);
}
