//! Day 17: active health monitoring task.
//!
//! The `HealthMonitor` periodically sends `PathKeepalive` probes on each
//! configured path and tracks responses to drive the `PathHealthTracker`
//! state machine. It integrates with `PathManager` to update scheduler
//! eligibility via `set_health`.
//!
//! Design:
//! - One UDP socket for all probes (bound to an ephemeral port).
//! - Probes are `PathKeepalive` with probe ID (u64) in the payload.
//! - Server echoes the probe; the monitor correlates by probe ID.
//! - Responses are demultiplexed by `path_id` in the header.
//! - The DATA socket is never used for probes (avoids interference).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use bondnet_protocol::{PROTOCOL_VERSION, Packet, PacketHeader, PacketType};

use crate::health::{HealthConfig, HealthState, PathHealthTracker};
use crate::path_manager::PathManager;

/// Commands for the health monitor task.
#[derive(Debug)]
enum MonitorCommand {
    Shutdown,
}

/// A running health monitor.
pub struct HealthMonitor {
    manager: Arc<Mutex<PathManager>>,
    session_id: u64,
    config: HealthConfig,
    trackers: Arc<Mutex<HashMap<u16, PathHealthTracker>>>,
    cmd_tx: Option<mpsc::Sender<MonitorCommand>>,
    task: Option<JoinHandle<()>>,
}

impl HealthMonitor {
    /// Create a new monitor (not yet running).
    pub fn new(
        manager: Arc<Mutex<PathManager>>,
        session_id: u64,
        config: HealthConfig,
    ) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            manager,
            session_id,
            config,
            trackers: Arc::new(Mutex::new(HashMap::new())),
            cmd_tx: None,
            task: None,
        })
    }

    /// Start the background monitoring task.
    pub fn start(&mut self) -> Result<(), String> {
        if self.task.is_some() {
            return Err("monitor already running".to_string());
        }

        // Initialize trackers for all enabled paths.
        {
            let manager = self.manager.lock().expect("manager lock poisoned");
            let mut trackers = self.trackers.lock().expect("trackers lock poisoned");
            // Get path IDs from manager status.
            for status in manager.status() {
                if status.enabled {
                    trackers.entry(status.path_id).or_insert_with(|| {
                        PathHealthTracker::new(status.path_id, self.config.clone())
                    });
                }
            }
        }

        let (cmd_tx, cmd_rx) = mpsc::channel::<MonitorCommand>(16);
        let manager = Arc::clone(&self.manager);
        let session_id = self.session_id;
        let config = self.config.clone();
        let trackers = Arc::clone(&self.trackers);

        let task = tokio::spawn(async move {
            monitor_loop(manager, session_id, config, trackers, cmd_rx).await;
        });

        self.cmd_tx = Some(cmd_tx);
        self.task = Some(task);
        Ok(())
    }

    /// Stop the monitor and wait for the task to finish.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.cmd_tx.take() {
            let _ = tx.send(MonitorCommand::Shutdown).await;
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Get a snapshot of all path health states.
    pub fn health_snapshot(&self) -> Vec<(u16, HealthState)> {
        let trackers = self.trackers.lock().expect("trackers lock poisoned");
        trackers.iter().map(|(id, t)| (*id, t.state())).collect()
    }
}

/// The main monitoring loop.
async fn monitor_loop(
    manager: Arc<Mutex<PathManager>>,
    session_id: u64,
    config: HealthConfig,
    trackers: Arc<Mutex<HashMap<u16, PathHealthTracker>>>,
    mut cmd_rx: mpsc::Receiver<MonitorCommand>,
) {
    // Bind a single UDP socket for all health probes.
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("HealthMonitor: failed to bind socket: {e}");
            return;
        }
    };

    // Spawn the receiver task.
    let recv_socket = Arc::clone(&socket);
    let recv_trackers = Arc::clone(&trackers);
    let recv_manager = Arc::clone(&manager);
    let recv_session = session_id;
    let receiver = tokio::spawn(async move {
        receiver_loop(recv_socket, recv_session, recv_trackers, recv_manager).await;
    });

    let mut interval = tokio::time::interval(config.heartbeat_interval);
    // Skip the first immediate tick.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Send probes on all enabled paths.
                send_probes(&manager, &socket, session_id, &trackers).await;
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(MonitorCommand::Shutdown) | None => {
                        break;
                    }
                }
            }
        }
    }

    // Shutdown: abort the receiver task.
    receiver.abort();
    let _ = receiver.await;
}

/// Receives PathKeepalive responses and updates trackers.
async fn receiver_loop(
    socket: Arc<UdpSocket>,
    session_id: u64,
    trackers: Arc<Mutex<HashMap<u16, PathHealthTracker>>>,
    manager: Arc<Mutex<PathManager>>,
) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, _remote) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let packet = match Packet::decode(&buf[..len]) {
            Ok(p) => p,
            Err(_) => continue, // Malformed: ignore.
        };

        // Only process PathKeepalive responses for our session.
        if packet.header.packet_type != PacketType::PathKeepalive {
            continue;
        }
        if packet.header.session_id != session_id {
            continue;
        }
        // Payload must be exactly 8 bytes (the probe ID).
        if packet.payload.len() != 8 {
            continue;
        }

        let probe_id = u64::from_be_bytes([
            packet.payload[0],
            packet.payload[1],
            packet.payload[2],
            packet.payload[3],
            packet.payload[4],
            packet.payload[5],
            packet.payload[6],
            packet.payload[7],
        ]);
        let path_id = packet.header.path_id;

        // Update the tracker for this path.
        let valid = {
            let mut trk = trackers.lock().expect("trackers lock poisoned");
            match trk.get_mut(&path_id) {
                Some(t) => t.on_response(probe_id),
                None => false,
            }
        };

        if valid {
            update_manager_health(&manager, &trackers, path_id);
        }
        // Stale/mismatched responses are ignored (on_response returns false).
    }
}

/// Send a PathKeepalive probe on each enabled path.
async fn send_probes(
    manager: &Arc<Mutex<PathManager>>,
    socket: &Arc<UdpSocket>,
    session_id: u64,
    trackers: &Arc<Mutex<HashMap<u16, PathHealthTracker>>>,
) {
    // Get the list of enabled paths and their remote addresses.
    let paths: Vec<(u16, SocketAddr)> = {
        let mgr = manager.lock().expect("manager lock poisoned");
        mgr.status()
            .into_iter()
            .filter(|s| s.enabled && s.initialized)
            .map(|s| (s.path_id, s.remote_addr))
            .collect()
    };

    for (path_id, remote) in paths {
        let probe_id = {
            let mut trk = trackers.lock().expect("trackers lock poisoned");
            match trk.get_mut(&path_id) {
                Some(t) => t.new_probe(),
                None => continue,
            }
        };

        // Build the PathKeepalive probe.
        let payload = probe_id.to_be_bytes().to_vec();
        let packet = Packet {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                flags: 0,
                session_id,
                sequence: 0, // Control packets don't use ordered sequence.
                path_id,
                packet_type: PacketType::PathKeepalive,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
            payload,
        };

        let bytes = match packet.encode() {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Send the probe. A send error is recorded but does not
        // prove remote failure.
        if socket.send_to(&bytes, remote).await.is_err() {
            let mut trk = trackers.lock().expect("trackers lock poisoned");
            if let Some(t) = trk.get_mut(&path_id) {
                t.on_send_error();
            }
        } else {
            let mut trk = trackers.lock().expect("trackers lock poisoned");
            if let Some(t) = trk.get_mut(&path_id) {
                t.on_send_success();
            }
        }

        // Update the manager's scheduler health based on tracker state.
        update_manager_health(manager, trackers, path_id);
    }
}

/// Update the PathManager's scheduler health from the tracker state.
fn update_manager_health(
    manager: &Arc<Mutex<PathManager>>,
    trackers: &Arc<Mutex<HashMap<u16, PathHealthTracker>>>,
    path_id: u16,
) {
    let state = {
        let trk = trackers.lock().expect("trackers lock poisoned");
        match trk.get(&path_id) {
            Some(t) => t.state(),
            None => return,
        }
    };
    let scheduler_health = state.to_scheduler_health();
    let mut mgr = manager.lock().expect("manager lock poisoned");
    mgr.set_health(path_id, scheduler_health);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PhysicalPathConfig;
    use std::time::Duration;

    fn test_manager() -> Arc<Mutex<PathManager>> {
        let configs = vec![PhysicalPathConfig {
            name: "test".to_string(),
            path_id: 1,
            local_addr: "127.0.0.1:0".parse().unwrap(),
            remote_addr: "127.0.0.1:51820".parse().unwrap(),
            bandwidth_bps: 1_000_000,
            enabled: true,
        }];
        let manager = PathManager::new(configs).unwrap();
        // Note: initialize is async; we don't call it here because the
        // test is sync. The manager is usable for health tracking without
        // initialization (paths will be marked as not initialized).
        Arc::new(Mutex::new(manager))
    }

    // Test 17: Shutdown cancels health-check tasks cleanly.
    #[tokio::test]
    async fn shutdown_cancels_tasks_cleanly() {
        let manager = test_manager();
        let mut monitor =
            HealthMonitor::new(Arc::clone(&manager), 1001, HealthConfig::default()).unwrap();
        monitor.start().unwrap();
        // Let it run briefly.
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Shutdown should complete without hanging.
        tokio::time::timeout(Duration::from_secs(5), monitor.shutdown())
            .await
            .expect("shutdown timed out");
        // After shutdown, the task is gone.
        assert!(monitor.task.is_none());
    }

    // Test 18: Repeated initialization and shutdown do not leak.
    #[tokio::test]
    async fn repeated_start_shutdown_no_leak() {
        let manager = test_manager();
        for _ in 0..3 {
            let mut monitor =
                HealthMonitor::new(Arc::clone(&manager), 1001, HealthConfig::default()).unwrap();
            monitor.start().unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            tokio::time::timeout(Duration::from_secs(5), monitor.shutdown())
                .await
                .expect("shutdown timed out");
        }
        // If we get here without hanging or panicking, no leak.
    }

    // Test: starting twice is an error (not a silent leak).
    #[tokio::test]
    async fn double_start_is_error() {
        let manager = test_manager();
        let mut monitor =
            HealthMonitor::new(Arc::clone(&manager), 1001, HealthConfig::default()).unwrap();
        monitor.start().unwrap();
        assert!(monitor.start().is_err());
        monitor.shutdown().await;
    }
}
