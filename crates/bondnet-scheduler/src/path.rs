//! Path model: identifiers, health states, and measured statistics.
//!
//! Everything here is caller-supplied data. The scheduler performs no
//! measurement itself; real measurement arrives on later days from the
//! path-health subsystem.

/// Opaque identifier of one physical path (Wi-Fi, Ethernet, USB tether, ...).
///
/// The `u16` width matches `bondnet-protocol`'s `path_id` field, so a
/// scheduler decision can later be stamped directly onto a packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathId(pub u16);

impl PathId {
    /// Build a path identifier from its raw `u16`.
    pub const fn new(id: u16) -> Self {
        PathId(id)
    }

    /// The raw `u16` identifier.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Health of a path as seen by the scheduler.
///
/// ```text
/// Healthy   → eligible
/// Degraded  → eligible but penalized in scoring
/// Unhealthy → never selected
/// ```
///
/// An `Unhealthy` path stays in the scheduler's table so that recovery is a
/// plain `update_path` call — no re-registration, no scheduler rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathHealth {
    /// Fully usable.
    Healthy,
    /// Usable but impaired (flapping, elevated errors, ...): scored lower
    /// than an otherwise identical `Healthy` path.
    Degraded,
    /// Must not carry traffic. The scheduler excludes it from selection
    /// regardless of what any scorer returns.
    Unhealthy,
}

/// Measured characteristics of one path.
///
/// All values are caller-supplied; the scheduler never measures the network
/// itself. Units are part of every field name so call sites stay honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStats {
    /// Estimated path capacity, bytes per second. `u64` on purpose: the
    /// scheduler must not assume a maximum consumer Internet speed.
    pub bandwidth_bps: u64,
    /// Smoothed round-trip time, milliseconds. Zero means "unknown" and is
    /// scored as the best case — it must never cause a divide-by-zero.
    pub rtt_ms: u32,
    /// Packet loss in parts per million: `1% = 10_000 ppm`,
    /// `0.1% = 1_000 ppm`. Integer so scoring stays fully deterministic.
    pub loss_ppm: u32,
    /// RTT variation, milliseconds.
    pub jitter_ms: u32,
    /// Bytes sent on this path but not yet acknowledged.
    pub in_flight_bytes: u64,
    /// In-flight target before the congestion penalty bites. Zero means
    /// "unknown": no congestion penalty is applied.
    pub capacity_bytes: u64,
}

impl PathStats {
    /// Build statistics from explicit measurements.
    pub const fn new(
        bandwidth_bps: u64,
        rtt_ms: u32,
        loss_ppm: u32,
        jitter_ms: u32,
        in_flight_bytes: u64,
        capacity_bytes: u64,
    ) -> Self {
        PathStats {
            bandwidth_bps,
            rtt_ms,
            loss_ppm,
            jitter_ms,
            in_flight_bytes,
            capacity_bytes,
        }
    }
}

impl Default for PathStats {
    /// All measurements unknown/zero. Note: zero bandwidth scores a zero
    /// weight, so a default path is never selected until real stats arrive.
    fn default() -> Self {
        PathStats {
            bandwidth_bps: 0,
            rtt_ms: 0,
            loss_ppm: 0,
            jitter_ms: 0,
            in_flight_bytes: 0,
            capacity_bytes: 0,
        }
    }
}

/// Everything the scheduler knows about one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathState {
    /// Which path this is.
    pub id: PathId,
    /// Current health; see [`PathHealth`].
    pub health: PathHealth,
    /// Latest measurements.
    pub stats: PathStats,
}

impl PathState {
    /// Build a full path state.
    pub const fn new(id: PathId, health: PathHealth, stats: PathStats) -> Self {
        PathState { id, health, stats }
    }

    /// Convenience: a healthy path with the given statistics.
    pub fn healthy(id: u16, stats: PathStats) -> Self {
        PathState::new(PathId::new(id), PathHealth::Healthy, stats)
    }
}
