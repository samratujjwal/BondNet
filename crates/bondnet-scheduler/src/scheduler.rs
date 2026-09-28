//! Deterministic weighted scheduler: smooth weighted round-robin.
//!
//! Selection never uses randomness. Each eligible path owns an explicit
//! `current` cursor: every round adds the path's weight to its cursor, the
//! path with the largest cursor wins, and the winner's cursor drops by the
//! total eligible weight. Over time each path is selected in exact proportion
//! to its weight, spread smoothly (weights 5:1 yield `A A B A A A`, not
//! `A A A A A B`), and the whole sequence is reproducible from the same
//! updates.

use std::collections::BTreeMap;

use crate::path::{PathHealth, PathId, PathState};
use crate::score::{DefaultScorer, MAX_WEIGHT, PathScorer};

/// One registered path plus its scheduling state.
struct Entry {
    /// Latest caller-supplied state.
    state: PathState,
    /// Cached scorer weight; zero means "never selected".
    weight: u64,
    /// Smooth-WRR cursor. Explicit per-path state is what makes selection
    /// deterministic: no hidden RNG, no wall-clock.
    current: i128,
}

/// Decides which path carries the next packet.
///
/// Generic over the scoring policy so the MVP [`DefaultScorer`] can be
/// swapped later without touching selection mechanics. Paths live in a
/// `BTreeMap`, so iteration order — and therefore tie-breaking — is always
/// by ascending [`PathId`], never by hash or insertion order.
pub struct Scheduler<S: PathScorer = DefaultScorer> {
    scorer: S,
    entries: BTreeMap<PathId, Entry>,
}

impl Scheduler<DefaultScorer> {
    /// Scheduler with the default MVP scoring policy.
    pub fn new() -> Self {
        Self::with_scorer(DefaultScorer)
    }
}

impl Default for Scheduler<DefaultScorer> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: PathScorer> Scheduler<S> {
    /// Scheduler with a custom scoring policy.
    pub fn with_scorer(scorer: S) -> Self {
        Scheduler {
            scorer,
            entries: BTreeMap::new(),
        }
    }

    /// Insert or replace a path's state (upsert). Recomputes its weight and
    /// resets its smooth-WRR cursor, so the selection distribution adapts
    /// immediately with no scheduler rebuild.
    pub fn update_path(&mut self, state: PathState) {
        let weight = self.scorer.score(&state).min(MAX_WEIGHT);
        self.entries.insert(
            state.id,
            Entry {
                state,
                weight,
                current: 0,
            },
        );
    }

    /// Remove a path. Returns `true` if it was present. Removing a path that
    /// was never added is a no-op returning `false`, never a panic.
    pub fn remove_path(&mut self, id: PathId) -> bool {
        self.entries.remove(&id).is_some()
    }

    /// Number of registered paths (including unhealthy ones).
    pub fn path_count(&self) -> usize {
        self.entries.len()
    }

    /// Latest state for a path, if registered.
    pub fn get(&self, id: PathId) -> Option<&PathState> {
        self.entries.get(&id).map(|entry| &entry.state)
    }

    /// Current selection weight for a path, if registered. Zero means the
    /// path is currently never selected.
    pub fn weight_of(&self, id: PathId) -> Option<u64> {
        self.entries.get(&id).map(|entry| entry.weight)
    }

    /// Select the path for the next packet.
    ///
    /// Returns `Some(id)` when at least one path is eligible, `None` when
    /// nothing is (empty table, all unhealthy, or all zero-weight).
    /// `Unhealthy` paths are excluded here even if the scorer scores them
    /// above zero: health exclusion is a scheduler invariant, not a
    /// scoring-policy detail.
    pub fn select_path(&mut self) -> Option<PathId> {
        let total: u128 = self
            .entries
            .values()
            .filter(|entry| Self::eligible(entry))
            .map(|entry| u128::from(entry.weight))
            .fold(0, u128::saturating_add);
        if total == 0 {
            return None;
        }
        // Weights are clamped to MAX_WEIGHT = u64::MAX / 1024, so this
        // saturating conversion is purely defensive.
        let total_cursor = total.min(i128::MAX as u128) as i128;

        let mut best: Option<(PathId, i128)> = None;
        for (id, entry) in self.entries.iter_mut() {
            if !Self::eligible(entry) {
                continue;
            }
            entry.current = entry.current.saturating_add(entry.weight as i128);
            let strictly_better = match best {
                None => true,
                Some((_, cursor)) => entry.current > cursor,
            };
            // Ties keep the earlier (smaller PathId) entry: deterministic.
            if strictly_better {
                best = Some((*id, entry.current));
            }
        }

        let (winner, _) = best.expect("total > 0 implies an eligible path");
        let entry = self
            .entries
            .get_mut(&winner)
            .expect("winner was just selected from the table");
        entry.current = entry.current.saturating_sub(total_cursor);
        Some(winner)
    }

    /// A path is selectable only when it is not `Unhealthy` and its weight
    /// is positive. Checked on every selection round.
    fn eligible(entry: &Entry) -> bool {
        entry.state.health != PathHealth::Unhealthy && entry.weight > 0
    }
}
