//! Server configuration: bind address plus a verbose flag.
//!
//! Deliberately tiny. No config-file framework, no environment-variable
//! framework: one optional CLI argument is all Day 6 needs.

use std::net::SocketAddr;

/// Runtime configuration for the Day 6 UDP server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Local address to bind the UDP socket to.
    pub bind_addr: SocketAddr,
    /// When true, log one line per received packet. Off by default so the
    /// server stays quiet enough to benchmark later.
    pub verbose: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:51820"
                .parse()
                .expect("default bind address is a valid SocketAddr"),
            verbose: false,
        }
    }
}

/// Parse a minimal CLI: `bondnet-server [--bind ADDR:PORT] [--verbose]`.
///
/// Takes the full `std::env::args()` vector (including argv[0]) so the
/// parsing stays unit-testable without touching the process args.
pub fn parse_args(args: &[String]) -> Result<ServerConfig, String> {
    let mut config = ServerConfig::default();
    let mut rest = args.iter().skip(1);
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--bind" => {
                let value = rest.next().ok_or_else(|| {
                    "--bind requires an address, e.g. --bind 0.0.0.0:51820".to_string()
                })?;
                config.bind_addr = value
                    .parse()
                    .map_err(|_| format!("invalid --bind address: {value}"))?;
            }
            "--verbose" => config.verbose = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_bind_is_wildcard_51820() {
        let config = parse_args(&args(&["bondnet-server"])).unwrap();
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:51820");
        assert!(!config.verbose);
    }

    #[test]
    fn bind_and_verbose_flags_parse() {
        let config = parse_args(&args(&[
            "bondnet-server",
            "--bind",
            "127.0.0.1:9999",
            "--verbose",
        ]))
        .unwrap();
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:9999");
        assert!(config.verbose);
    }

    #[test]
    fn unknown_argument_is_rejected() {
        assert!(parse_args(&args(&["bondnet-server", "--nope"])).is_err());
    }

    #[test]
    fn bind_without_value_is_rejected() {
        assert!(parse_args(&args(&["bondnet-server", "--bind"])).is_err());
    }

    #[test]
    fn invalid_bind_address_is_rejected() {
        assert!(parse_args(&args(&["bondnet-server", "--bind", "not-an-addr"])).is_err());
    }
}
