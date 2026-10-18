//! Day 13: minimal manager for independent physical UDP paths.
//!
//! The manager holds the configured paths, binds each enabled one to its
//! own UDP socket (via [`UdpPath`]), and reports per-path status. It does
//! NOT schedule traffic, reorder packets, or fail over — those are later
//! milestones. Its only job is independent lifecycle: a failed path is
//! recorded and never takes down the others, and closing one path never
//! closes another.
//!
//! Each [`UdpPath`] owns its socket; dropping the manager's `Arc` for one
//! path does not affect the others.

use std::sync::Arc;

use crate::config::{PhysicalPathConfig, validate_path_configs};
use crate::transport::UdpPath;

/// One configured path and its runtime state.
pub struct ManagedPath {
    /// The validated configuration (name, IDs, addresses, enabled flag).
    pub config: PhysicalPathConfig,
    /// The bound transport, if this path is enabled and binding succeeded.
    /// Each path owns its `UdpPath` (and therefore its UDP socket)
    /// independently — dropping one never closes another.
    pub path: Option<Arc<UdpPath>>,
    /// Why binding failed, if it did. `None` means "not attempted" or
    /// "succeeded"; check `path` to distinguish.
    pub init_error: Option<String>,
}

/// Read-only snapshot of one path's status, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathStatus {
    pub name: String,
    pub path_id: u16,
    pub enabled: bool,
    pub initialized: bool,
    pub local_addr: Option<std::net::SocketAddr>,
    pub remote_addr: std::net::SocketAddr,
    pub init_error: Option<String>,
}

/// Holds the configured paths and their independent transports.
///
/// Construction validates the configuration (duplicate path IDs, invalid
/// endpoints). [`PathManager::initialize`] then binds each enabled path;
/// failures are recorded per path and never abort the others.
pub struct PathManager {
    paths: Vec<ManagedPath>,
}

impl PathManager {
    /// Validate and store the path configurations. No sockets are bound
    /// here — call [`PathManager::initialize`] for that.
    pub fn new(configs: Vec<PhysicalPathConfig>) -> Result<Self, String> {
        validate_path_configs(&configs)?;
        Ok(Self {
            paths: configs
                .into_iter()
                .map(|config| ManagedPath {
                    config,
                    path: None,
                    init_error: None,
                })
                .collect(),
        })
    }

    /// Bind every enabled path to its own UDP socket.
    ///
    /// Each path is independent: if one fails (bad local address, port in
    /// use, …), the error is recorded on that path and the rest continue.
    /// All paths share the given `session_id`; each keeps its configured
    /// `path_id` and starts its outbound sequence at 1.
    pub async fn initialize(&mut self, session_id: u64) {
        for managed in &mut self.paths {
            if !managed.config.enabled {
                continue;
            }
            if managed.path.is_some() {
                continue;
            }
            let udp_config = managed.config.to_udp_path_config(session_id, 1);
            match UdpPath::bind(udp_config).await {
                Ok(path) => {
                    managed.path = Some(Arc::new(path));
                    managed.init_error = None;
                }
                Err(error) => {
                    managed.path = None;
                    managed.init_error = Some(error.to_string());
                }
            }
        }
    }

    /// Read-only status of every configured path, in configuration order.
    pub fn status(&self) -> Vec<PathStatus> {
        self.paths
            .iter()
            .map(|managed| PathStatus {
                name: managed.config.name.clone(),
                path_id: managed.config.path_id,
                enabled: managed.config.enabled,
                initialized: managed.path.is_some(),
                local_addr: managed.path.as_ref().and_then(|p| p.local_addr().ok()),
                remote_addr: managed.config.remote_addr,
                init_error: managed.init_error.clone(),
            })
            .collect()
    }

    /// Get the bound transport for a path ID, if it initialized.
    pub fn get(&self, path_id: u16) -> Option<Arc<UdpPath>> {
        self.paths
            .iter()
            .find(|m| m.config.path_id == path_id)
            .and_then(|m| m.path.clone())
    }

    /// Drop one path's transport without touching the others.
    ///
    /// After this, [`PathManager::get`] returns `None` for the ID until
    /// [`PathManager::initialize`] is called again. Other paths keep
    /// working — their sockets are independent.
    pub fn shutdown_path(&mut self, path_id: u16) {
        if let Some(managed) = self.paths.iter_mut().find(|m| m.config.path_id == path_id) {
            managed.path = None;
        }
    }

    /// Drop every path's transport. Idempotent.
    pub fn shutdown_all(&mut self) {
        for managed in &mut self.paths {
            managed.path = None;
        }
    }

    /// Number of configured paths (enabled or not).
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// True when no paths are configured.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PhysicalPathConfig;

    fn path(name: &str, id: u16, enabled: bool) -> PhysicalPathConfig {
        PhysicalPathConfig {
            name: name.to_string(),
            path_id: id,
            local_addr: "127.0.0.1:0".parse().unwrap(),
            remote_addr: "127.0.0.1:51820".parse().unwrap(),
            enabled,
        }
    }

    #[tokio::test]
    async fn two_paths_initialize_independently() {
        let mut manager = PathManager::new(vec![path("a", 1, true), path("b", 2, true)]).unwrap();
        manager.initialize(1001).await;
        let status = manager.status();
        assert_eq!(status.len(), 2);
        assert!(status[0].initialized);
        assert!(status[1].initialized);
        assert!(status[0].local_addr.is_some());
        assert!(status[1].local_addr.is_some());
        // Distinct sockets: different local ports.
        assert_ne!(status[0].local_addr, status[1].local_addr);
        // Both share the session, keep their path IDs.
        let pa = manager.get(1).unwrap();
        let pb = manager.get(2).unwrap();
        assert_eq!(pa.session_id(), 1001);
        assert_eq!(pb.session_id(), 1001);
        assert_eq!(pa.path_id(), 1);
        assert_eq!(pb.path_id(), 2);
    }

    #[tokio::test]
    async fn disabled_path_is_not_bound() {
        let mut manager = PathManager::new(vec![path("a", 1, true), path("b", 2, false)]).unwrap();
        manager.initialize(1001).await;
        let status = manager.status();
        assert!(status[0].initialized);
        assert!(!status[1].initialized);
        assert!(manager.get(2).is_none());
    }

    #[tokio::test]
    async fn one_path_failure_does_not_stop_the_other() {
        // 192.0.2.1 is TEST-NET-1: unroutable, bind fails on most systems.
        // If it unexpectedly succeeds, the test still passes — the point
        // is that path "b" initializes regardless of what "a" does.
        let mut bad = path("a", 1, true);
        bad.local_addr = "192.0.2.1:0".parse().unwrap();
        let mut manager = PathManager::new(vec![bad, path("b", 2, true)]).unwrap();
        manager.initialize(1001).await;
        assert!(
            manager.get(2).is_some(),
            "path b must initialize even if path a fails"
        );
    }

    #[tokio::test]
    async fn second_path_failure_does_not_stop_the_first() {
        let mut bad = path("b", 2, true);
        bad.local_addr = "192.0.2.1:0".parse().unwrap();
        let mut manager = PathManager::new(vec![path("a", 1, true), bad]).unwrap();
        manager.initialize(1001).await;
        assert!(
            manager.get(1).is_some(),
            "path a must initialize even if path b fails"
        );
    }

    #[tokio::test]
    async fn per_path_metrics_are_independent() {
        use bondnet_protocol::PacketType;
        let mut manager = PathManager::new(vec![path("a", 1, true), path("b", 2, true)]).unwrap();
        manager.initialize(1001).await;
        let pa = manager.get(1).unwrap();
        let pb = manager.get(2).unwrap();
        // next_packet is pure (no I/O): it stamps the next sequence from
        // each path's independent counter. Send 3 on A, 1 on B.
        let mut last_a = 0;
        for _ in 0..3 {
            last_a = pa
                .next_packet(PacketType::PathHello, Vec::new())
                .header
                .sequence;
        }
        let last_b = pb
            .next_packet(PacketType::PathHello, Vec::new())
            .header
            .sequence;
        // Independent counters: A is at 3, B is at 1. Neither affects the
        // other, and both carry the right path IDs.
        assert_eq!(last_a, 3);
        assert_eq!(last_b, 1);
        let pa2 = pa.next_packet(PacketType::PathHello, Vec::new());
        let pb2 = pb.next_packet(PacketType::PathHello, Vec::new());
        assert_eq!(pa2.header.sequence, 4);
        assert_eq!(pb2.header.sequence, 2);
        assert_eq!(pa2.header.path_id, 1);
        assert_eq!(pb2.header.path_id, 2);
        assert_eq!(pa2.header.session_id, 1001);
        assert_eq!(pb2.header.session_id, 1001);
    }

    #[tokio::test]
    async fn shutdown_one_path_leaves_the_other() {
        let mut manager = PathManager::new(vec![path("a", 1, true), path("b", 2, true)]).unwrap();
        manager.initialize(1001).await;
        assert!(manager.get(1).is_some());
        manager.shutdown_path(1);
        assert!(manager.get(1).is_none());
        assert!(
            manager.get(2).is_some(),
            "shutting down path 1 must not close path 2"
        );
        // Re-initialize brings it back.
        manager.initialize(1001).await;
        assert!(manager.get(1).is_some());
    }

    #[tokio::test]
    async fn shutdown_all_is_idempotent() {
        let mut manager = PathManager::new(vec![path("a", 1, true), path("b", 2, true)]).unwrap();
        manager.initialize(1001).await;
        manager.shutdown_all();
        manager.shutdown_all();
        assert!(manager.get(1).is_none());
        assert!(manager.get(2).is_none());
    }

    #[test]
    fn duplicate_ids_rejected_at_construction() {
        let result = PathManager::new(vec![path("a", 1, true), path("b", 1, true)]);
        assert!(result.is_err());
    }

    #[test]
    fn manager_len_and_empty() {
        let manager = PathManager::new(vec![path("a", 1, true), path("b", 2, true)]).unwrap();
        assert_eq!(manager.len(), 2);
        assert!(!manager.is_empty());
        assert!(PathManager::new(vec![]).unwrap().is_empty());
    }
}
