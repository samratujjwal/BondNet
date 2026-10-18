//! Day 7 path configuration: which local address, which remote, which IDs.
//!
//! The local address is how a physical interface is selected today:
//! binding `192.168.0.170:0` makes the OS route this socket's traffic
//! through the adapter that owns `192.168.0.170`. This is address-based
//! path selection, not interface-name selection — the two are related but
//! not identical, and the docs say so explicitly.

use std::net::SocketAddr;

/// Configuration for one physical UDP path.
#[derive(Debug, Clone)]
pub struct UdpPathConfig {
    /// BondNet logical path identifier. Opaque; never derived from the
    /// port, interface index, or IP address.
    pub path_id: u16,
    /// BondNet tunnel session identifier. Explicit for Day 7; no session
    /// negotiation exists yet.
    pub session_id: u64,
    /// Local address to bind. Must be an IPv4 address owned by the
    /// intended physical interface, e.g. `192.168.0.170:0`. Port 0 means
    /// "allocate an ephemeral port".
    pub local_addr: SocketAddr,
    /// VPS endpoint, e.g. `203.0.113.10:51820` (documentation IP — the
    /// real one comes from the operator).
    pub remote_addr: SocketAddr,
    /// First outbound BondNet tunnel sequence number. Explicit so tests
    /// are deterministic.
    pub initial_sequence: u64,
}

/// Day 13: configuration for one physical path, without session identity.
///
/// The session ID is supplied separately when the path is built into a
/// `UdpPath` (via [`PhysicalPathConfig::to_udp_path_config`]), keeping
/// path configuration independent of session identity. Two paths in the
/// same manager share the session but must have different path IDs.
#[derive(Debug, Clone)]
pub struct PhysicalPathConfig {
    /// Descriptive name for logs and diagnostics, e.g. "primary-wifi".
    pub name: String,
    /// BondNet logical path identifier. Must be unique within a manager,
    /// even if the local addresses differ.
    pub path_id: u16,
    /// Local address to bind. Must be an IPv4 address owned by the
    /// intended physical interface, e.g. `192.168.0.170:0`. Port 0 means
    /// "allocate an ephemeral port".
    pub local_addr: SocketAddr,
    /// VPS endpoint, e.g. `203.0.113.10:51820`. Port 0 is rejected for
    /// an enabled path (there is nothing to talk to).
    pub remote_addr: SocketAddr,
    /// Disabled paths are validated but never bound.
    pub enabled: bool,
}

impl PhysicalPathConfig {
    /// Attach the session identity to produce the `UdpPathConfig` that
    /// `UdpPath::bind` expects. The caller chooses the initial sequence
    /// (1 for production, explicit values for deterministic tests).
    pub fn to_udp_path_config(&self, session_id: u64, initial_sequence: u64) -> UdpPathConfig {
        UdpPathConfig {
            path_id: self.path_id,
            session_id,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            initial_sequence,
        }
    }
}

/// Validate a set of physical path configurations.
///
/// Rejects:
/// - duplicate path IDs, even when the local addresses differ;
/// - an enabled path whose remote port is 0 (nothing to talk to);
/// - non-IPv4 local or remote addresses (consistent with Day 7);
/// - an empty path name.
///
/// Disabled paths are still validated (a typo should fail fast, not
/// silently at enable time). Does not bind any socket.
pub fn validate_path_configs(paths: &[PhysicalPathConfig]) -> Result<(), String> {
    use std::collections::HashSet;
    let mut seen_ids = HashSet::new();
    for (index, path) in paths.iter().enumerate() {
        if path.name.trim().is_empty() {
            return Err(format!("path at index {index} has an empty name"));
        }
        if !seen_ids.insert(path.path_id) {
            return Err(format!(
                "duplicate path_id {} (path \"{}\"): path IDs must be unique \
                 even when local addresses differ",
                path.path_id, path.name,
            ));
        }
        if !path.local_addr.ip().is_ipv4() {
            return Err(format!(
                "path \"{}\" binds a non-IPv4 local address: {}",
                path.name, path.local_addr,
            ));
        }
        if !path.remote_addr.ip().is_ipv4() {
            return Err(format!(
                "path \"{}\" has a non-IPv4 remote address: {}",
                path.name, path.remote_addr,
            ));
        }
        if path.enabled && path.remote_addr.port() == 0 {
            return Err(format!(
                "path \"{}\" is enabled but its remote port is 0",
                path.name,
            ));
        }
    }
    Ok(())
}

/// Parse a minimal dev CLI:
///
/// `bondnet-client --local 192.168.0.170:0 --remote VPS:51820
///  --path-id 1 --session-id 1001 --count 5 [--verbose]`
///
/// Takes the full `std::env::args()` vector (including argv[0]) so the
/// parsing stays unit-testable without touching the process args.
pub fn parse_args(args: &[String]) -> Result<(UdpPathConfig, u64, bool), String> {
    let mut local: Option<SocketAddr> = None;
    let mut remote: Option<SocketAddr> = None;
    let mut path_id: Option<u16> = None;
    let mut session_id: Option<u64> = None;
    let mut count: u64 = 5;
    let mut verbose = false;

    let mut rest = args.iter().skip(1);
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--local" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--local requires an address".to_string())?;
                local = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --local address: {v}"))?,
                );
            }
            "--remote" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--remote requires an address".to_string())?;
                remote = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --remote address: {v}"))?,
                );
            }
            "--path-id" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--path-id requires a number".to_string())?;
                path_id = Some(v.parse().map_err(|_| format!("invalid --path-id: {v}"))?);
            }
            "--session-id" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--session-id requires a number".to_string())?;
                session_id = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --session-id: {v}"))?,
                );
            }
            "--count" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--count requires a number".to_string())?;
                count = v.parse().map_err(|_| format!("invalid --count: {v}"))?;
                if count == 0 {
                    return Err("--count must be at least 1".to_string());
                }
            }
            "--verbose" => verbose = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let local_addr = local.ok_or_else(|| "--local is required".to_string())?;
    if !local_addr.ip().is_ipv4() {
        return Err(format!(
            "Day 7 binds an explicit local IPv4 address; got {local_addr}"
        ));
    }
    let config = UdpPathConfig {
        path_id: path_id.ok_or_else(|| "--path-id is required".to_string())?,
        session_id: session_id.ok_or_else(|| "--session-id is required".to_string())?,
        local_addr,
        remote_addr: remote.ok_or_else(|| "--remote is required".to_string())?,
        initial_sequence: 1,
    };
    Ok((config, count, verbose))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn full() -> Vec<String> {
        args(&[
            "bondnet-client",
            "--local",
            "192.168.0.170:0",
            "--remote",
            "203.0.113.10:51820",
            "--path-id",
            "1",
            "--session-id",
            "1001",
        ])
    }

    #[test]
    fn full_cli_parses() {
        let (config, count, verbose) = parse_args(&full()).unwrap();
        assert_eq!(config.path_id, 1);
        assert_eq!(config.session_id, 1001);
        assert_eq!(config.local_addr.to_string(), "192.168.0.170:0");
        assert_eq!(config.remote_addr.to_string(), "203.0.113.10:51820");
        assert_eq!(config.initial_sequence, 1);
        assert_eq!(count, 5);
        assert!(!verbose);
    }

    #[test]
    fn missing_required_args_rejected() {
        assert!(parse_args(&args(&["bondnet-client"])).is_err());
        assert!(
            parse_args(&args(&[
                "bondnet-client",
                "--local",
                "192.168.0.170:0",
                "--remote",
                "203.0.113.10:51820",
            ]))
            .is_err()
        );
    }

    #[test]
    fn non_ipv4_local_rejected() {
        let mut a = full();
        a[2] = "[::1]:0".to_string();
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn zero_count_rejected() {
        let mut a = full();
        a.extend(["--count".to_string(), "0".to_string()]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn unknown_argument_rejected() {
        let mut a = full();
        a.push("--nope".to_string());
        assert!(parse_args(&a).is_err());
    }

    // Day 13: PhysicalPathConfig validation.

    fn path(name: &str, id: u16, local: &str, remote: &str, enabled: bool) -> PhysicalPathConfig {
        PhysicalPathConfig {
            name: name.to_string(),
            path_id: id,
            local_addr: local.parse().unwrap(),
            remote_addr: remote.parse().unwrap(),
            enabled,
        }
    }

    fn two_valid_paths() -> Vec<PhysicalPathConfig> {
        vec![
            path("primary", 1, "127.0.0.1:0", "127.0.0.1:51820", true),
            path("secondary", 2, "127.0.0.1:0", "127.0.0.1:51820", true),
        ]
    }

    #[test]
    fn two_distinct_paths_validate() {
        assert!(validate_path_configs(&two_valid_paths()).is_ok());
    }

    #[test]
    fn duplicate_path_ids_rejected_even_with_different_locals() {
        let mut paths = two_valid_paths();
        paths[1].path_id = 1;
        paths[1].local_addr = "127.0.0.2:0".parse().unwrap();
        let err = validate_path_configs(&paths).unwrap_err();
        assert!(err.contains("duplicate path_id 1"), "got: {err}");
    }

    #[test]
    fn enabled_path_with_zero_remote_port_rejected() {
        let mut paths = two_valid_paths();
        paths[0].remote_addr = "127.0.0.1:0".parse().unwrap();
        let err = validate_path_configs(&paths).unwrap_err();
        assert!(err.contains("remote port is 0"), "got: {err}");
    }

    #[test]
    fn disabled_path_with_zero_remote_port_ok() {
        let mut paths = two_valid_paths();
        paths[1].enabled = false;
        paths[1].remote_addr = "127.0.0.1:0".parse().unwrap();
        assert!(validate_path_configs(&paths).is_ok());
    }

    #[test]
    fn empty_name_rejected() {
        let mut paths = two_valid_paths();
        paths[0].name = "   ".to_string();
        assert!(validate_path_configs(&paths).is_err());
    }

    #[test]
    fn physical_path_non_ipv4_local_rejected() {
        let mut paths = two_valid_paths();
        paths[0].local_addr = "[::1]:0".parse().unwrap();
        assert!(validate_path_configs(&paths).is_err());
    }

    #[test]
    fn to_udp_path_config_attaches_session() {
        let p = path("primary", 1, "127.0.0.1:0", "127.0.0.1:51820", true);
        let udp = p.to_udp_path_config(1001, 42);
        assert_eq!(udp.path_id, 1);
        assert_eq!(udp.session_id, 1001);
        assert_eq!(udp.initial_sequence, 42);
        assert_eq!(udp.local_addr.to_string(), "127.0.0.1:0");
    }
}
