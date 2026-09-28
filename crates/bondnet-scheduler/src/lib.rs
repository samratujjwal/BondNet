//! BondNet path scheduler: pure path-selection decisions, no networking.
//!
//! The scheduler answers one question: *which physical path should carry the
//! next tunnel packet?* It works only from caller-supplied [`PathState`]
//! measurements and never touches sockets, platforms, or packet bytes, so it
//! stays unit-testable and usable from both `bondnet-client` and
//! `bondnet-core` without platform coupling.
//!
//! ```text
//! Physical paths
//!       ↓
//! Path statistics (caller-supplied)
//!       ↓
//! Path scoring (PathScorer: replaceable policy)
//!       ↓
//! Weighted deterministic selection (smooth weighted round-robin)
//!       ↓
//! PathId
//! ```
//!
//! Health contract: `Healthy` paths are fully eligible, `Degraded` paths are
//! eligible but penalized, and `Unhealthy` paths are never selected — the
//! scheduler enforces this itself and never trusts a scorer to do it.

pub mod path;
pub mod scheduler;
pub mod score;

pub use path::{PathHealth, PathId, PathState, PathStats};
pub use scheduler::Scheduler;
pub use score::{DefaultScorer, MAX_WEIGHT, PathScorer};
