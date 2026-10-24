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

/// Wire size of an encrypted keepalive payload: 8-byte nonce counter +
/// (8-byte probe ID + 16-byte Poly1305 tag).
const ENCRYPTED_KEEPALIVE_PAYLOAD_LEN: usize = 32;

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
    /// Day 20: optional secure session for keepalive authentication.
    /// When set, probes are encrypted (UploadControl) and responses are
    /// authenticated (ReturnControl).
    secure_session: Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>>,
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
            secure_session: Arc::new(Mutex::new(None)),
        })
    }

    /// Day 20: attach a secure session for keepalive authentication.
    /// Probes are encrypted with the UploadControl domain; responses are
    /// verified with the ReturnControl domain. Without a session,
    /// keepalives stay plaintext (backward compatible).
    pub fn set_secure_session(&self, session: Arc<bondnet_crypto::SecureSession>) {
        *self.secure_session.lock().expect("secure lock poisoned") = Some(session);
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
        let secure = Arc::clone(&self.secure_session);

        let task = tokio::spawn(async move {
            monitor_loop(manager, session_id, config, trackers, secure, cmd_rx).await;
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
    secure_session: Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>>,
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
    let recv_secure = Arc::clone(&secure_session);
    let recv_session = session_id;
    let receiver = tokio::spawn(async move {
        receiver_loop(
            recv_socket,
            recv_session,
            recv_trackers,
            recv_manager,
            recv_secure,
        )
        .await;
    });

    let mut interval = tokio::time::interval(config.heartbeat_interval);
    // Skip the first immediate tick.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Send probes on all enabled paths.
                send_probes(&manager, &socket, session_id, &trackers, &secure_session).await;
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
///
/// Day 20: when a secure session is attached, responses are
/// authenticated (ReturnControl domain, nonce counter in the payload).
/// Unauthenticated or undecryptable responses are ignored and never
/// affect path health.
async fn receiver_loop(
    socket: Arc<UdpSocket>,
    session_id: u64,
    trackers: Arc<Mutex<HashMap<u16, PathHealthTracker>>>,
    manager: Arc<Mutex<PathManager>>,
    secure_session: Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>>,
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

        let probe_id = match authenticated_probe_id(&packet, &buf[..len], &secure_session) {
            Some(id) => id,
            None => continue, // Wrong shape or failed authentication: ignore.
        };
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

/// Extract the probe ID from a keepalive response, authenticating it
/// when a secure session is attached.
///
/// Plaintext mode: payload must be exactly 8 bytes (the probe ID).
/// Encrypted mode: payload is `counter(8) || ciphertext`; the counter
/// selects the ReturnControl nonce, and decryption must yield exactly
/// 8 bytes. Returns `None` on any mismatch or authentication failure.
fn authenticated_probe_id(
    packet: &Packet,
    datagram: &[u8],
    secure_session: &Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>>,
) -> Option<u64> {
    let session_opt = secure_session.lock().expect("secure lock poisoned").clone();
    match session_opt {
        None => {
            if packet.payload.len() != 8 {
                return None;
            }
            Some(u64::from_be_bytes(packet.payload[..8].try_into().ok()?))
        }
        Some(session) => {
            if packet.payload.len() != ENCRYPTED_KEEPALIVE_PAYLOAD_LEN || datagram.len() < 36 {
                return None;
            }
            let counter = u64::from_be_bytes(packet.payload[..8].try_into().ok()?);
            let mut aad = [0u8; 36];
            aad.copy_from_slice(&datagram[..36]);
            let plaintext = session
                .decrypt(
                    bondnet_crypto::KeyDomain::ReturnControl,
                    counter,
                    &aad,
                    &packet.payload[8..],
                )
                .ok()?;
            if plaintext.len() != 8 {
                return None;
            }
            Some(u64::from_be_bytes(plaintext[..8].try_into().ok()?))
        }
    }
}

/// Send a PathKeepalive probe on each enabled path.
///
/// Day 20: when a secure session is attached, the probe payload is
/// encrypted with the UploadControl domain. The wire payload is
/// `counter(8) || ciphertext`; the counter selects the nonce on the
/// server side. The 36-byte header is AAD (payload_len = 32).
async fn send_probes(
    manager: &Arc<Mutex<PathManager>>,
    socket: &Arc<UdpSocket>,
    session_id: u64,
    trackers: &Arc<Mutex<HashMap<u16, PathHealthTracker>>>,
    secure_session: &Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>>,
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

        let header = PacketHeader {
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
        };
        let payload = match keepalive_probe_payload(&header, probe_id, secure_session) {
            Some(p) => p,
            None => continue, // Encryption failed: skip this probe, keep the schedule.
        };

        // Build the PathKeepalive probe.
        let packet = Packet { header, payload };

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

/// Build a keepalive probe payload.
///
/// Plaintext mode: the 8-byte probe ID. Encrypted mode: `counter(8) ||
/// ciphertext` where the ciphertext is the probe ID encrypted with the
/// UploadControl domain. The header is AAD; its payload_len field must
/// equal the wire payload length, so the AAD is derived from a dummy
/// packet with the known final size (32 bytes encrypted, 8 plaintext).
/// Returns `None` when encryption fails — the caller skips the probe.
fn keepalive_probe_payload(
    header: &PacketHeader,
    probe_id: u64,
    secure_session: &Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>>,
) -> Option<Vec<u8>> {
    let session_opt = secure_session.lock().expect("secure lock poisoned").clone();
    match session_opt {
        None => Some(probe_id.to_be_bytes().to_vec()),
        Some(session) => {
            // The AAD is the 36-byte header as it will appear on the wire
            // (payload_len = 32). Encode a dummy packet to capture it.
            let dummy = Packet {
                header: header.clone(),
                payload: vec![0u8; ENCRYPTED_KEEPALIVE_PAYLOAD_LEN],
            };
            let aad: [u8; 36] = dummy.encode().ok()?.as_slice()[..36].try_into().ok()?;
            let (counter, ct) = session
                .encrypt(
                    bondnet_crypto::KeyDomain::UploadControl,
                    &aad,
                    &probe_id.to_be_bytes(),
                )
                .ok()?;
            let mut wire = Vec::with_capacity(ENCRYPTED_KEEPALIVE_PAYLOAD_LEN);
            wire.extend_from_slice(&counter.to_be_bytes());
            wire.extend_from_slice(&ct);
            debug_assert_eq!(wire.len(), ENCRYPTED_KEEPALIVE_PAYLOAD_LEN);
            Some(wire)
        }
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

    // Day 20: keepalive authentication tests.

    fn test_session() -> Arc<bondnet_crypto::SecureSession> {
        let psk = bondnet_crypto::CryptoKey::from_slice(&[0x77; 32]).unwrap();
        Arc::new(bondnet_crypto::SecureSession::new(&psk, 1001, [0x55; 32]).unwrap())
    }

    fn secure_holder(
        session: Arc<bondnet_crypto::SecureSession>,
    ) -> Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>> {
        Arc::new(Mutex::new(Some(session)))
    }

    fn probe_header() -> PacketHeader {
        PacketHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            session_id: 1001,
            sequence: 0,
            path_id: 1,
            packet_type: PacketType::PathKeepalive,
            timestamp: 1_700_000_000,
        }
    }

    /// Simulate the server side: decrypt the probe (UploadControl) and
    /// build the encrypted echo (ReturnControl), like
    /// `Server::keepalive_echo_payload` does.
    fn server_echo(
        session: &bondnet_crypto::SecureSession,
        probe_datagram: &[u8],
    ) -> Option<Vec<u8>> {
        let packet = Packet::decode(probe_datagram).ok()?;
        if packet.payload.len() != ENCRYPTED_KEEPALIVE_PAYLOAD_LEN {
            return None;
        }
        let counter = u64::from_be_bytes(packet.payload[..8].try_into().ok()?);
        let mut aad = [0u8; 36];
        aad.copy_from_slice(&probe_datagram[..36]);
        let probe_id = session
            .decrypt(
                bondnet_crypto::KeyDomain::UploadControl,
                counter,
                &aad,
                &packet.payload[8..],
            )
            .ok()?;
        // Response header mirrors the request.
        let resp_header = PacketHeader {
            timestamp: packet.header.timestamp,
            ..probe_header()
        };
        let dummy = Packet {
            header: resp_header.clone(),
            payload: vec![0u8; ENCRYPTED_KEEPALIVE_PAYLOAD_LEN],
        };
        let bytes = dummy.encode().ok()?;
        let mut resp_aad = [0u8; 36];
        resp_aad.copy_from_slice(&bytes[..36]);
        let (resp_counter, ct) = session
            .encrypt(
                bondnet_crypto::KeyDomain::ReturnControl,
                &resp_aad,
                &probe_id,
            )
            .ok()?;
        let mut wire = resp_counter.to_be_bytes().to_vec();
        wire.extend_from_slice(&ct);
        Packet {
            header: resp_header,
            payload: wire,
        }
        .encode()
        .ok()
    }

    #[test]
    fn encrypted_probe_response_round_trip() {
        let session = test_session();
        let holder = secure_holder(Arc::clone(&session));
        let header = probe_header();
        let probe_id = 12345u64;
        let payload =
            keepalive_probe_payload(&header, probe_id, &holder).expect("probe must encrypt");
        assert_eq!(payload.len(), ENCRYPTED_KEEPALIVE_PAYLOAD_LEN);
        let datagram = Packet { header, payload }.encode().unwrap();
        // Server echoes.
        let echo_datagram = server_echo(&session, &datagram).expect("server must echo");
        let echo_packet = Packet::decode(&echo_datagram).unwrap();
        // Client authenticates the response.
        let got = authenticated_probe_id(&echo_packet, &echo_datagram, &holder)
            .expect("response must authenticate");
        assert_eq!(got, probe_id);
    }

    #[test]
    fn tampered_probe_response_rejected() {
        let session = test_session();
        let holder = secure_holder(Arc::clone(&session));
        let header = probe_header();
        let payload = keepalive_probe_payload(&header, 99, &holder).unwrap();
        let datagram = Packet { header, payload }.encode().unwrap();
        let mut echo_datagram = server_echo(&session, &datagram).unwrap();
        // Flip a byte in the response ciphertext.
        let pos = 36 + 8 + 3;
        echo_datagram[pos] ^= 0xFF;
        let echo_packet = Packet::decode(&echo_datagram).unwrap();
        assert!(
            authenticated_probe_id(&echo_packet, &echo_datagram, &holder).is_none(),
            "tampered response must be rejected"
        );
    }

    #[test]
    fn wrong_key_probe_response_rejected() {
        let session = test_session();
        let holder = secure_holder(Arc::clone(&session));
        // Attacker encrypts the *response* with a different key.
        let evil_psk = bondnet_crypto::CryptoKey::from_slice(&[0x99; 32]).unwrap();
        let evil = bondnet_crypto::SecureSession::new(&evil_psk, 1001, [0x55; 32]).unwrap();
        let resp_header = probe_header();
        let dummy = Packet {
            header: resp_header.clone(),
            payload: vec![0u8; ENCRYPTED_KEEPALIVE_PAYLOAD_LEN],
        };
        let bytes = dummy.encode().unwrap();
        let mut aad = [0u8; 36];
        aad.copy_from_slice(&bytes[..36]);
        let (counter, ct) = evil
            .encrypt(
                bondnet_crypto::KeyDomain::ReturnControl,
                &aad,
                &7u64.to_be_bytes(),
            )
            .unwrap();
        let mut wire = counter.to_be_bytes().to_vec();
        wire.extend_from_slice(&ct);
        let datagram = Packet {
            header: resp_header,
            payload: wire,
        }
        .encode()
        .unwrap();
        let packet = Packet::decode(&datagram).unwrap();
        assert!(
            authenticated_probe_id(&packet, &datagram, &holder).is_none(),
            "wrong-key response must be rejected"
        );
    }

    #[test]
    fn plaintext_probe_response_still_works() {
        // No session attached: legacy 8-byte plaintext behavior.
        let holder: Arc<Mutex<Option<Arc<bondnet_crypto::SecureSession>>>> =
            Arc::new(Mutex::new(None));
        let header = probe_header();
        let payload = keepalive_probe_payload(&header, 777, &holder).unwrap();
        assert_eq!(payload.len(), 8);
        let datagram = Packet { header, payload }.encode().unwrap();
        let packet = Packet::decode(&datagram).unwrap();
        let got = authenticated_probe_id(&packet, &datagram, &holder).expect("plaintext works");
        assert_eq!(got, 777);
    }

    #[test]
    fn short_payload_rejected_in_encrypted_mode() {
        let session = test_session();
        let holder = secure_holder(session);
        // Encrypted mode but truncated payload: must be rejected, not panic.
        let header = probe_header();
        let datagram = Packet {
            header,
            payload: vec![0u8; 10],
        }
        .encode()
        .unwrap();
        let packet = Packet::decode(&datagram).unwrap();
        assert!(
            authenticated_probe_id(&packet, &datagram, &holder).is_none(),
            "short payload must be rejected"
        );
    }

    #[test]
    fn monitor_accepts_secure_session() {
        let manager = test_manager();
        let monitor =
            HealthMonitor::new(Arc::clone(&manager), 1001, HealthConfig::default()).unwrap();
        monitor.set_secure_session(test_session());
        let attached = monitor
            .secure_session
            .lock()
            .expect("secure lock poisoned")
            .is_some();
        assert!(attached, "session must be attached");
    }
}
