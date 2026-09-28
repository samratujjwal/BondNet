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
}
