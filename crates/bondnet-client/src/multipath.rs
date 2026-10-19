//! Day 14: multipath upload data plane.
//!
//! Integrates the Day 4 [`Scheduler`](bondnet_scheduler::Scheduler) with
//! the upload path: each Wintun packet is validated, the scheduler picks
//! one eligible path, the packet is encoded as `PacketType::Data` with the
//! selected `path_id`, and sent through that path's own `UdpPath` (own
//! socket, own sequence counter).
//!
//! ```text
//! Wintun packet
//!     ↓
//! validate (non-empty, ≤ max_wintun_len)
//!     ↓
//! sync scheduler with manager (eligible = initialized + healthy)
//!     ↓
//! scheduler.select_path() → Option<PathId>
//!     ↓
//! encode DATA with selected path_id (that path's sequence counter)
//!     ↓
//! send via that path's UdpPath
//!     ↓
//! per-path metrics updated
//! ```
//!
//! Policies (Day 14):
//! - Send errors increment metrics only; they do NOT mark a path
//!   unhealthy. Health is operator-controlled via
//!   [`MultipathDataPlane::set_path_health`]. No automatic failover.
//! - No eligible path → the packet is dropped and `no_eligible_path` is
//!   counted. The caller decides whether to retry.
//! - Per-path sequence counters are independent; there is NO global
//!   ordering guarantee. Packets on different paths may arrive out of
//!   order — the Day 5 reorder buffer is not integrated here.
//! - The 36-byte protocol header is untouched.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bondnet_protocol::{HEADER_LEN, PacketType};
use bondnet_scheduler::{PathHealth, Scheduler};
use tokio::sync::Mutex;

use crate::data_plane::{DataPlaneError, MAX_WINTUN_PACKET_LEN};
use crate::path_manager::PathManager;
use crate::transport::UdpPath;

/// Counters for the multipath upload plane.
#[derive(Debug, Default)]
pub struct MultipathMetrics {
    /// Packets successfully handed to a path's UDP socket.
    pub packets_sent: AtomicU64,
    /// Bytes sent (BondNet header + payload), across all paths.
    pub bytes_sent: AtomicU64,
    /// Packets dropped because no path was eligible.
    pub no_eligible_path: AtomicU64,
    /// Send failures (socket errors). The path stays eligible; only the
    /// operator (or a future health subsystem) changes health.
    pub send_errors: AtomicU64,
    /// Empty packets dropped before scheduling.
    pub invalid_dropped: AtomicU64,
    /// Oversized packets dropped before scheduling.
    pub oversized_dropped: AtomicU64,
}

/// Snapshot of [`MultipathMetrics`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipathMetricsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub no_eligible_path: u64,
    pub send_errors: u64,
    pub invalid_dropped: u64,
    pub oversized_dropped: u64,
}

impl MultipathMetrics {
    pub fn snapshot(&self) -> MultipathMetricsSnapshot {
        MultipathMetricsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            no_eligible_path: self.no_eligible_path.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            invalid_dropped: self.invalid_dropped.load(Ordering::Relaxed),
            oversized_dropped: self.oversized_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Error from [`MultipathDataPlane::send_wintun_packet`].
#[derive(Debug)]
pub enum MultipathError {
    /// Packet failed the pre-send validation (empty/oversized).
    Invalid(DataPlaneError),
    /// No path was eligible (none initialized, all unhealthy, or all
    /// zero-weight). The packet was dropped and counted.
    NoEligiblePath,
    /// The selected path's socket failed. Counted; the path remains
    /// eligible (see module docs).
    SendFailed {
        path_id: u16,
        source: crate::error::TransportError,
    },
}

impl std::fmt::Display for MultipathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultipathError::Invalid(e) => write!(f, "invalid packet: {e}"),
            MultipathError::NoEligiblePath => write!(f, "no eligible path"),
            MultipathError::SendFailed { path_id, source } => {
                write!(f, "send failed on path {path_id}: {source}")
            }
        }
    }
}

impl std::error::Error for MultipathError {}

/// Upload data plane that schedules packets across the manager's paths.
///
/// The manager is shared (`Arc<Mutex<>>`) so diagnostics and the data
/// plane see the same paths. The scheduler is internal; it is re-synced
/// from the manager before every send, so path removal, re-init, or
/// health changes never leave stale entries.
use crate::health::PathHealthTracker;

/// Type alias for the shared health tracker map.
pub type HealthTrackerMap =
    Arc<std::sync::Mutex<std::collections::HashMap<u16, PathHealthTracker>>>;

pub struct MultipathDataPlane {
    manager: Arc<Mutex<PathManager>>,
    scheduler: Mutex<Scheduler>,
    metrics: MultipathMetrics,
    max_wintun_len: usize,
    session_id: u64,
    /// Day 15: session-wide logical sequence counter. Allocated BEFORE
    /// path selection, so the ordering is independent of which physical
    /// path carries the packet. Each path's `UdpPath` only carries the
    /// sequence; it never allocates it.
    upload_sequence: AtomicU64,
    /// Day 17: optional health trackers for reporting send errors.
    /// When set, send errors/successes are reported to the tracker,
    /// which drives the health state machine.
    health_trackers: std::sync::Mutex<Option<HealthTrackerMap>>,
    /// Day 18: optional secure session for authenticated encryption.
    /// When set, DATA payloads are encrypted before sending.
    secure_session: std::sync::Mutex<Option<Arc<bondnet_crypto::SecureSession>>>,
}

impl MultipathDataPlane {
    /// Create the plane. The manager must already be initialized (or not —
    /// sends will just report `NoEligiblePath` until paths appear).
    pub fn new(manager: Arc<Mutex<PathManager>>, session_id: u64, max_wintun_len: usize) -> Self {
        Self {
            manager,
            scheduler: Mutex::new(Scheduler::new()),
            metrics: MultipathMetrics::default(),
            max_wintun_len,
            session_id,
            upload_sequence: AtomicU64::new(1),
            health_trackers: std::sync::Mutex::new(None),
            secure_session: std::sync::Mutex::new(None),
        }
    }

    /// Day 18: attach a secure session for authenticated encryption.
    /// When attached, DATA payloads are encrypted before sending.
    pub fn set_secure_session(&self, session: Arc<bondnet_crypto::SecureSession>) {
        *self.secure_session.lock().expect("secure lock poisoned") = Some(session);
    }

    /// Day 17: attach health trackers for automatic failure reporting.
    /// When attached, send errors and successes are reported to the
    /// tracker for the path, driving the health state machine.
    pub fn set_health_trackers(&self, trackers: HealthTrackerMap) {
        *self.health_trackers.lock().expect("health lock poisoned") = Some(trackers);
    }

    /// Create with the default 1500-byte inner limit.
    pub fn with_defaults(manager: Arc<Mutex<PathManager>>, session_id: u64) -> Self {
        Self::new(manager, session_id, MAX_WINTUN_PACKET_LEN)
    }

    /// Operator-controlled health. Returns false for an unknown path ID.
    pub async fn set_path_health(&self, path_id: u16, health: PathHealth) -> bool {
        self.manager.lock().await.set_health(path_id, health)
    }

    /// Reconcile the scheduler with the manager's current state.
    ///
    /// Initialized paths are (re-)registered with their current health;
    /// paths that disappeared or were shut down are removed. Called
    /// before every send, so the scheduler never holds a stale entry.
    ///
    /// The scheduler's `update_path` resets the smooth-WRR cursor, so we
    /// only call it when the path's state actually changed — otherwise
    /// the cursor would never accumulate and weighted distribution would
    /// break.
    async fn sync_scheduler(&self) {
        let states = self.manager.lock().await.scheduler_states();
        let mut scheduler = self.scheduler.lock().await;
        for (state, initialized) in states {
            if initialized {
                let needs_update = match scheduler.get(state.id) {
                    Some(existing) => existing != &state,
                    None => true,
                };
                if needs_update {
                    scheduler.update_path(state);
                }
            } else {
                scheduler.remove_path(state.id);
            }
        }
    }

    /// Validate, schedule, encode, and send one Wintun packet.
    ///
    /// Returns the `(path_id, sequence)` stamped on the packet. The
    /// `path_id` always matches the socket the packet was sent through;
    /// each path's sequence counter is independent.
    ///
    /// No lock is held across the socket send: the scheduler lock is
    /// released after selection, and the manager lock after cloning the
    /// `Arc<UdpPath>`.
    pub async fn send_wintun_packet(&self, packet: &[u8]) -> Result<(u16, u64), MultipathError> {
        if packet.is_empty() {
            self.metrics.invalid_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(MultipathError::Invalid(DataPlaneError::EmptyPacket));
        }
        if packet.len() > self.max_wintun_len {
            self.metrics
                .oversized_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(MultipathError::Invalid(DataPlaneError::PacketTooLarge {
                len: packet.len(),
                max: self.max_wintun_len,
            }));
        }

        // Day 15: allocate the session-wide logical sequence BEFORE path
        // selection, so ordering is independent of which physical path
        // carries the packet.
        let sequence = self.upload_sequence.fetch_add(1, Ordering::SeqCst);

        self.sync_scheduler().await;
        let selected = self.scheduler.lock().await.select_path();
        let path_id = match selected {
            Some(id) => id.get(),
            None => {
                self.metrics
                    .no_eligible_path
                    .fetch_add(1, Ordering::Relaxed);
                return Err(MultipathError::NoEligiblePath);
            }
        };

        // Clone the Arc under the manager lock, then release before I/O.
        let path: Arc<UdpPath> = {
            let manager = self.manager.lock().await;
            match manager.get(path_id) {
                Some(p) => p,
                None => {
                    // Raced with a shutdown between sync and select; treat
                    // as no eligible path rather than panicking.
                    drop(manager);
                    self.metrics
                        .no_eligible_path
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(MultipathError::NoEligiblePath);
                }
            }
        };
        debug_assert_eq!(path.path_id(), path_id);
        debug_assert_eq!(path.session_id(), self.session_id);

        match path
            .send_new(PacketType::Data, packet.to_vec(), sequence)
            .await
        {
            Ok(_) => {
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add((HEADER_LEN + packet.len()) as u64, Ordering::Relaxed);
                // Day 17: report success to health tracker (resets send-error
                // counter, but does NOT mark Healthy by itself).
                self.report_send_success(path_id).await;
                Ok((path_id, sequence))
            }
            Err(error) => {
                self.metrics.send_errors.fetch_add(1, Ordering::Relaxed);
                // Day 17: report error to health tracker. This contributes
                // to Degraded but does not alone mark Unhealthy.
                self.report_send_error(path_id).await;
                Err(MultipathError::SendFailed {
                    path_id,
                    source: error,
                })
            }
        }
    }

    /// Day 17: report a successful send to the health tracker.
    async fn report_send_success(&self, path_id: u16) {
        let trackers_opt = self
            .health_trackers
            .lock()
            .expect("health lock poisoned")
            .clone();
        if let Some(trackers) = trackers_opt {
            let health = {
                let mut map = trackers.lock().expect("trackers lock poisoned");
                match map.get_mut(&path_id) {
                    Some(t) => {
                        t.on_send_success();
                        t.state().to_scheduler_health()
                    }
                    None => return,
                }
            };
            // Sync the scheduler health immediately.
            self.manager.lock().await.set_health(path_id, health);
        }
    }

    /// Day 17: report a send error to the health tracker.
    async fn report_send_error(&self, path_id: u16) {
        let trackers_opt = self
            .health_trackers
            .lock()
            .expect("health lock poisoned")
            .clone();
        if let Some(trackers) = trackers_opt {
            let health = {
                let mut map = trackers.lock().expect("trackers lock poisoned");
                match map.get_mut(&path_id) {
                    Some(t) => {
                        t.on_send_error();
                        t.state().to_scheduler_health()
                    }
                    None => return,
                }
            };
            // Sync the scheduler health immediately for fast failover.
            self.manager.lock().await.set_health(path_id, health);
        }
    }

    /// Read-only metrics snapshot.
    pub fn metrics(&self) -> MultipathMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// The next session-wide sequence that will be allocated. Test-only;
    /// the production path always goes through `send_wintun_packet`.
    #[cfg(test)]
    fn peek_next_sequence(&self) -> u64 {
        self.upload_sequence.load(Ordering::SeqCst)
    }

    /// Session ID this plane sends with.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_BANDWIDTH_BPS;
    use crate::config::PhysicalPathConfig;

    fn path(name: &str, id: u16, bandwidth_bps: u64) -> PhysicalPathConfig {
        PhysicalPathConfig {
            name: name.to_string(),
            path_id: id,
            local_addr: "127.0.0.1:0".parse().unwrap(),
            remote_addr: "127.0.0.1:51820".parse().unwrap(),
            bandwidth_bps,
            enabled: true,
        }
    }

    /// Extract the selected path ID from a send result, whether the send
    /// succeeded or failed. Used by tests to verify the SCHEDULING
    /// decision independent of sandbox UDP restrictions.
    async fn selected_path_id(plane: &MultipathDataPlane, packet: &[u8]) -> u16 {
        match plane.send_wintun_packet(packet).await {
            Ok((path_id, _)) => path_id,
            Err(MultipathError::SendFailed { path_id, .. }) => path_id,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    async fn two_path_plane() -> (Arc<Mutex<PathManager>>, MultipathDataPlane) {
        let mut manager = PathManager::new(vec![
            path("a", 1, DEFAULT_BANDWIDTH_BPS),
            path("b", 2, DEFAULT_BANDWIDTH_BPS),
        ])
        .unwrap();
        manager.initialize(1001).await;
        let manager = Arc::new(Mutex::new(manager));
        let plane = MultipathDataPlane::with_defaults(Arc::clone(&manager), 1001);
        (manager, plane)
    }

    #[tokio::test]
    async fn single_path_gets_every_packet() {
        let mut manager = PathManager::new(vec![path("a", 1, DEFAULT_BANDWIDTH_BPS)]).unwrap();
        manager.initialize(1001).await;
        let manager = Arc::new(Mutex::new(manager));
        let plane = MultipathDataPlane::with_defaults(manager, 1001);
        for _ in 0..5 {
            let path_id = selected_path_id(&plane, &[0x45u8; 20]).await;
            assert_eq!(path_id, 1);
        }
    }

    #[tokio::test]
    async fn two_equal_paths_share_packets() {
        let (_manager, plane) = two_path_plane().await;
        let mut counts = [0u64; 3];
        for _ in 0..10 {
            let path_id = selected_path_id(&plane, &[0x45u8; 20]).await;
            counts[path_id as usize] += 1;
        }
        // Equal weights → smooth round-robin splits 5/5.
        assert_eq!(counts[1], 5, "path 1 should carry 5 of 10");
        assert_eq!(counts[2], 5, "path 2 should carry 5 of 10");
    }

    #[tokio::test]
    async fn weighted_paths_follow_weights() {
        let mut manager =
            PathManager::new(vec![path("a", 1, 3_000_000), path("b", 2, 1_000_000)]).unwrap();
        manager.initialize(1001).await;
        let manager = Arc::new(Mutex::new(manager));
        let plane = MultipathDataPlane::with_defaults(manager, 1001);
        let mut counts = [0u64; 3];
        for _ in 0..40 {
            let path_id = selected_path_id(&plane, &[0x45u8; 20]).await;
            counts[path_id as usize] += 1;
        }
        // 3:1 weights → 30/10 over 40 packets.
        assert_eq!(counts[1], 30);
        assert_eq!(counts[2], 10);
    }

    #[tokio::test]
    async fn ineligible_path_gets_no_packets() {
        let (manager, plane) = two_path_plane().await;
        plane.set_path_health(2, PathHealth::Unhealthy).await;
        for _ in 0..6 {
            let path_id = selected_path_id(&plane, &[0x45u8; 20]).await;
            assert_eq!(path_id, 1, "unhealthy path 2 must never be selected");
        }
        // Recovery is a plain health update — no rebuild needed.
        plane.set_path_health(2, PathHealth::Healthy).await;
        let mut saw_two = false;
        for _ in 0..10 {
            let path_id = selected_path_id(&plane, &[0x45u8; 20]).await;
            if path_id == 2 {
                saw_two = true;
            }
        }
        assert!(saw_two, "path 2 should be selected again after recovery");
        let _ = manager;
    }

    #[tokio::test]
    async fn no_eligible_path_is_counted() {
        let (manager, plane) = two_path_plane().await;
        plane.set_path_health(1, PathHealth::Unhealthy).await;
        plane.set_path_health(2, PathHealth::Unhealthy).await;
        let err = plane.send_wintun_packet(&[0x45u8; 20]).await.unwrap_err();
        assert!(matches!(err, MultipathError::NoEligiblePath));
        assert_eq!(plane.metrics().no_eligible_path, 1);
        assert_eq!(plane.metrics().packets_sent, 0);
        let _ = manager;
    }

    #[tokio::test]
    async fn shutdown_path_is_not_selected() {
        let (manager, plane) = two_path_plane().await;
        manager.lock().await.shutdown_path(2);
        for _ in 0..4 {
            let path_id = selected_path_id(&plane, &[0x45u8; 20]).await;
            assert_eq!(path_id, 1, "shut-down path 2 must not be selected");
        }
        // Re-init restores eligibility without duplicate entries.
        manager.lock().await.initialize(1001).await;
        let mut saw_two = false;
        for _ in 0..10 {
            let path_id = selected_path_id(&plane, &[0x45u8; 20]).await;
            if path_id == 2 {
                saw_two = true;
            }
        }
        assert!(saw_two);
    }

    #[tokio::test]
    async fn session_wide_sequences_are_shared_across_paths() {
        let (_manager, plane) = two_path_plane().await;
        // Day 15: the sequence is session-wide, allocated before path
        // selection. Force 3 packets onto path 1, then 2 onto path 2;
        // the counter must advance 1..5 with no duplicates and no
        // per-path reset, regardless of which path carried each packet.
        // (Sends may fail in the sandbox; the ALLOCATION is what we test.)
        assert_eq!(plane.peek_next_sequence(), 1);
        plane.set_path_health(2, PathHealth::Unhealthy).await;
        for _ in 0..3 {
            let _ = plane.send_wintun_packet(&[0x45u8; 20]).await;
        }
        assert_eq!(plane.peek_next_sequence(), 4);
        plane.set_path_health(2, PathHealth::Healthy).await;
        plane.set_path_health(1, PathHealth::Unhealthy).await;
        for _ in 0..2 {
            let _ = plane.send_wintun_packet(&[0x45u8; 20]).await;
        }
        assert_eq!(plane.peek_next_sequence(), 6);
    }

    #[tokio::test]
    async fn empty_and_oversized_rejected_before_scheduling() {
        let (_manager, plane) = two_path_plane().await;
        assert!(matches!(
            plane.send_wintun_packet(&[]).await.unwrap_err(),
            MultipathError::Invalid(_)
        ));
        assert!(matches!(
            plane
                .send_wintun_packet(&vec![0u8; MAX_WINTUN_PACKET_LEN + 1])
                .await
                .unwrap_err(),
            MultipathError::Invalid(_)
        ));
        let m = plane.metrics();
        assert_eq!(m.invalid_dropped, 1);
        assert_eq!(m.oversized_dropped, 1);
        assert_eq!(m.packets_sent, 0);
    }

    #[tokio::test]
    async fn concurrent_allocation_produces_no_duplicates() {
        // Day 15: the session-wide counter is an AtomicU64; concurrent
        // sends must never allocate the same sequence twice.
        let (_manager, plane) = two_path_plane().await;
        let plane = std::sync::Arc::new(plane);
        let mut handles = Vec::new();
        for _ in 0..10 {
            let p = std::sync::Arc::clone(&plane);
            handles.push(tokio::spawn(async move {
                let _ = p.send_wintun_packet(&[0x45u8; 20]).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // 10 sends → counter advanced from 1 to 11, no duplicates.
        assert_eq!(plane.peek_next_sequence(), 11);
    }

    // Test 6: An unhealthy path is excluded from new DATA scheduling.
    #[tokio::test]
    async fn unhealthy_path_excluded_from_scheduling() {
        let (_manager, plane) = two_path_plane().await;
        // Mark path 1 as unhealthy via the operator API (simulates the
        // health monitor's decision).
        plane.set_path_health(1, PathHealth::Unhealthy).await;
        // All traffic should go to path 2.
        for _ in 0..5 {
            let pid = selected_path_id(&plane, &[0x45, 0, 0, 20]).await;
            assert_eq!(pid, 2, "unhealthy path 1 must not be selected");
        }
    }

    // Test 7: Traffic continues on a remaining healthy path.
    #[tokio::test]
    async fn traffic_continues_on_healthy_path() {
        let (_manager, plane) = two_path_plane().await;
        // Path 1 unhealthy, path 2 healthy.
        plane.set_path_health(1, PathHealth::Unhealthy).await;
        plane.set_path_health(2, PathHealth::Healthy).await;
        // Sends succeed (or fail at UDP, but are scheduled to path 2).
        let mut count = 0;
        for _ in 0..10 {
            let pid = selected_path_id(&plane, &[0x45, 0, 0, 20]).await;
            assert_eq!(pid, 2);
            count += 1;
        }
        assert_eq!(count, 10);
    }

    // Test 8: All paths unhealthy → explicit NoEligiblePath error.
    #[tokio::test]
    async fn all_unhealthy_returns_no_eligible_path() {
        let (_manager, plane) = two_path_plane().await;
        plane.set_path_health(1, PathHealth::Unhealthy).await;
        plane.set_path_health(2, PathHealth::Unhealthy).await;
        match plane.send_wintun_packet(&[0x45, 0, 0, 20]).await {
            Err(MultipathError::NoEligiblePath) => {}
            other => panic!("expected NoEligiblePath, got {other:?}"),
        }
        // The metric is counted.
        let m = plane.metrics();
        assert!(m.no_eligible_path >= 1);
    }

    // Test 12: Sequence numbers do not reset or duplicate during failover.
    #[tokio::test]
    async fn sequences_stable_across_failover() {
        let (_manager, plane) = two_path_plane().await;
        // Send 5 packets (sequences 1-5).
        for _ in 0..5 {
            let _ = selected_path_id(&plane, &[0x45, 0, 0, 20]).await;
        }
        assert_eq!(plane.peek_next_sequence(), 6);
        // Fail over: mark path 1 unhealthy.
        plane.set_path_health(1, PathHealth::Unhealthy).await;
        // Send 5 more (sequences 6-10), all on path 2.
        for _ in 0..5 {
            let pid = selected_path_id(&plane, &[0x45, 0, 0, 20]).await;
            assert_eq!(pid, 2);
        }
        // Counter continued monotonically; no reset, no duplicates.
        assert_eq!(plane.peek_next_sequence(), 11);
    }
}
