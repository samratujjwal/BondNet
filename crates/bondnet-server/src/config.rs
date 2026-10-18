//! Server configuration: bind address, verbosity, and the opt-in Day 10
//! TUN/NAT settings.
//!
//! Still hand-rolled CLI parsing (no config framework): a handful of
//! optional arguments is all the server needs. TUN is strictly opt-in —
//! without `--tun-name` the server behaves exactly like Day 6/9.

use std::net::{Ipv4Addr, SocketAddr};

use crate::tun::TunConfig;

/// Runtime configuration for the UDP server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Local address to bind the UDP socket to.
    pub bind_addr: SocketAddr,
    /// When true, log one line per received packet. Off by default so the
    /// server stays quiet enough to benchmark later.
    pub verbose: bool,
    /// Day 10: TUN interface name (e.g. `bondtun0`). `None` disables TUN
    /// forwarding entirely (Day 6/9 behavior).
    pub tun_name: Option<String>,
    /// Day 10: the TUN device's own IPv4 address. Required with
    /// `--tun-name`.
    pub tun_addr: Option<Ipv4Addr>,
    /// Day 10: prefix length for the TUN address. Required with
    /// `--tun-name`.
    pub tun_prefix: Option<u8>,
    /// Day 10: Internet-facing interface name (e.g. `eth0`). Used by
    /// `--print-setup` and a startup sanity check; never assumed.
    pub wan_interface: Option<String>,
    /// Print the administrator setup commands and exit without binding.
    pub print_setup: bool,
    /// Day 11: session ID that TUN return traffic belongs to. `None`
    /// disables the return path (upload-only, Day 10 behavior). Requires
    /// `--tun-name`.
    pub tun_return_session: Option<u64>,
    /// Day 11: path ID that TUN return traffic belongs to. Required with
    /// `--tun-return-session`.
    pub tun_return_path: Option<u16>,
    /// Day 11: a `(session, path)` endpoint association older than this
    /// is treated as expired and return packets are dropped. Seconds.
    pub tun_return_max_age_secs: u64,
}

/// Default staleness bound for the return-path endpoint association.
pub const DEFAULT_RETURN_MAX_AGE_SECS: u64 = 300;

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:51820"
                .parse()
                .expect("default bind address is a valid SocketAddr"),
            verbose: false,
            tun_name: None,
            tun_addr: None,
            tun_prefix: None,
            wan_interface: None,
            print_setup: false,
            tun_return_session: None,
            tun_return_path: None,
            tun_return_max_age_secs: DEFAULT_RETURN_MAX_AGE_SECS,
        }
    }
}

impl ServerConfig {
    /// Build the validated [`TunConfig`], or `None` when TUN is disabled.
    ///
    /// Pure: validates flags, never touches the OS.
    pub fn tun_config(&self) -> Result<Option<TunConfig>, String> {
        let name = match &self.tun_name {
            Some(name) => name,
            None => {
                if self.tun_addr.is_some() {
                    return Err("--tun-addr requires --tun-name".to_string());
                }
                if self.tun_prefix.is_some() {
                    return Err("--tun-prefix requires --tun-name".to_string());
                }
                return Ok(None);
            }
        };
        let address = self
            .tun_addr
            .ok_or_else(|| "--tun-addr is required when --tun-name is given".to_string())?;
        let prefix = self
            .tun_prefix
            .ok_or_else(|| "--tun-prefix is required when --tun-name is given".to_string())?;
        TunConfig::new(name, address, prefix)
            .map(Some)
            .map_err(|e| format!("invalid TUN configuration: {e}"))
    }

    /// Build the validated Day 11 return-path association, or `None` when
    /// the return path is disabled.
    ///
    /// Pure: validates flags, never touches the OS. The return path needs
    /// a TUN device to read from, so it requires `--tun-name`.
    pub fn return_config(&self) -> Result<Option<(u64, u16)>, String> {
        let session = match self.tun_return_session {
            Some(session) => session,
            None => {
                if self.tun_return_path.is_some() {
                    return Err("--tun-return-path requires --tun-return-session".to_string());
                }
                return Ok(None);
            }
        };
        let path = self.tun_return_path.ok_or_else(|| {
            "--tun-return-path is required when --tun-return-session is given".to_string()
        })?;
        if self.tun_name.is_none() {
            return Err("--tun-return-session requires --tun-name (the return path reads from the TUN device)".to_string());
        }
        Ok(Some((session, path)))
    }
}

/// Parse the CLI.
///
/// `bondnet-server [--bind ADDR:PORT] [--verbose] [--tun-name NAME
/// --tun-addr IP --tun-prefix N] [--wan-iface NAME] [--print-setup]`
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
            "--tun-name" => {
                let value = rest.next().ok_or_else(|| {
                    "--tun-name requires an interface name, e.g. --tun-name bondtun0".to_string()
                })?;
                config.tun_name = Some(value.clone());
            }
            "--tun-addr" => {
                let value = rest.next().ok_or_else(|| {
                    "--tun-addr requires an IPv4 address, e.g. --tun-addr 10.200.0.1".to_string()
                })?;
                config.tun_addr = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --tun-addr IPv4 address: {value}"))?,
                );
            }
            "--tun-prefix" => {
                let value = rest.next().ok_or_else(|| {
                    "--tun-prefix requires a prefix length, e.g. --tun-prefix 24".to_string()
                })?;
                config.tun_prefix = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --tun-prefix (1-32): {value}"))?,
                );
            }
            "--wan-iface" => {
                let value = rest.next().ok_or_else(|| {
                    "--wan-iface requires an interface name, e.g. --wan-iface eth0".to_string()
                })?;
                config.wan_interface = Some(value.clone());
            }
            "--print-setup" => config.print_setup = true,
            "--tun-return-session" => {
                let value = rest.next().ok_or_else(|| {
                    "--tun-return-session requires a session id, e.g. --tun-return-session 1001"
                        .to_string()
                })?;
                config.tun_return_session = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --tun-return-session: {value}"))?,
                );
            }
            "--tun-return-path" => {
                let value = rest.next().ok_or_else(|| {
                    "--tun-return-path requires a path id, e.g. --tun-return-path 1".to_string()
                })?;
                config.tun_return_path = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --tun-return-path: {value}"))?,
                );
            }
            "--tun-return-max-age-secs" => {
                let value = rest.next().ok_or_else(|| {
                    "--tun-return-max-age-secs requires seconds, e.g. --tun-return-max-age-secs 300"
                        .to_string()
                })?;
                config.tun_return_max_age_secs = value
                    .parse()
                    .map_err(|_| format!("invalid --tun-return-max-age-secs: {value}"))?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    // Fail fast on inconsistent flag combinations instead of silently
    // ignoring half a TUN configuration.
    config.tun_config().map(|_| ())?;
    config.return_config().map(|_| ())?;
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
        assert!(config.tun_name.is_none());
        assert!(!config.print_setup);
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
    fn tun_flags_parse() {
        let config = parse_args(&args(&[
            "bondnet-server",
            "--tun-name",
            "bondtun0",
            "--tun-addr",
            "10.200.0.1",
            "--tun-prefix",
            "24",
            "--wan-iface",
            "eth0",
        ]))
        .unwrap();
        let tun = config.tun_config().unwrap().expect("TUN should be enabled");
        assert_eq!(tun.name, "bondtun0");
        assert_eq!(tun.address.to_string(), "10.200.0.1");
        assert_eq!(tun.prefix, 24);
        assert_eq!(tun.subnet_cidr(), "10.200.0.0/24");
        assert_eq!(config.wan_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn tun_name_without_addr_is_rejected() {
        assert!(parse_args(&args(&["bondnet-server", "--tun-name", "bondtun0"])).is_err());
    }

    #[test]
    fn tun_name_without_prefix_is_rejected() {
        assert!(
            parse_args(&args(&[
                "bondnet-server",
                "--tun-name",
                "bondtun0",
                "--tun-addr",
                "10.200.0.1",
            ]))
            .is_err()
        );
    }

    #[test]
    fn tun_addr_without_name_is_rejected() {
        assert!(parse_args(&args(&["bondnet-server", "--tun-addr", "10.200.0.1",])).is_err());
    }

    #[test]
    fn tun_prefix_without_name_is_rejected() {
        assert!(parse_args(&args(&["bondnet-server", "--tun-prefix", "24",])).is_err());
    }

    #[test]
    fn invalid_tun_addr_is_rejected() {
        assert!(
            parse_args(&args(&[
                "bondnet-server",
                "--tun-name",
                "bondtun0",
                "--tun-addr",
                "not-an-ip",
                "--tun-prefix",
                "24",
            ]))
            .is_err()
        );
    }

    #[test]
    fn invalid_tun_prefix_value_is_rejected() {
        // Prefix 33 parses as u8 but fails TunConfig validation.
        assert!(
            parse_args(&args(&[
                "bondnet-server",
                "--tun-name",
                "bondtun0",
                "--tun-addr",
                "10.200.0.1",
                "--tun-prefix",
                "33",
            ]))
            .is_err()
        );
    }

    #[test]
    fn print_setup_flag_parses() {
        let config = parse_args(&args(&["bondnet-server", "--print-setup"])).unwrap();
        assert!(config.print_setup);
    }

    #[test]
    fn return_flags_parse() {
        let config = parse_args(&args(&[
            "bondnet-server",
            "--tun-name",
            "bondtun0",
            "--tun-addr",
            "10.200.0.1",
            "--tun-prefix",
            "24",
            "--tun-return-session",
            "1001",
            "--tun-return-path",
            "1",
        ]))
        .unwrap();
        assert_eq!(config.return_config().unwrap(), Some((1001, 1)));
        assert_eq!(config.tun_return_max_age_secs, DEFAULT_RETURN_MAX_AGE_SECS);
    }

    #[test]
    fn return_max_age_flag_parses() {
        let config = parse_args(&args(&[
            "bondnet-server",
            "--tun-name",
            "bondtun0",
            "--tun-addr",
            "10.200.0.1",
            "--tun-prefix",
            "24",
            "--tun-return-session",
            "1001",
            "--tun-return-path",
            "1",
            "--tun-return-max-age-secs",
            "60",
        ]))
        .unwrap();
        assert_eq!(config.tun_return_max_age_secs, 60);
    }

    #[test]
    fn return_path_without_session_rejected() {
        assert!(
            parse_args(&args(&[
                "bondnet-server",
                "--tun-name",
                "bondtun0",
                "--tun-addr",
                "10.200.0.1",
                "--tun-prefix",
                "24",
                "--tun-return-path",
                "1",
            ]))
            .is_err()
        );
    }

    #[test]
    fn return_session_without_path_rejected() {
        assert!(
            parse_args(&args(&[
                "bondnet-server",
                "--tun-name",
                "bondtun0",
                "--tun-addr",
                "10.200.0.1",
                "--tun-prefix",
                "24",
                "--tun-return-session",
                "1001",
            ]))
            .is_err()
        );
    }

    #[test]
    fn return_session_without_tun_rejected() {
        assert!(
            parse_args(&args(&[
                "bondnet-server",
                "--tun-return-session",
                "1001",
                "--tun-return-path",
                "1",
            ]))
            .is_err()
        );
    }

    #[test]
    fn no_return_flags_disables_return_path() {
        let config = parse_args(&args(&["bondnet-server"])).unwrap();
        assert_eq!(config.return_config().unwrap(), None);
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
