//! Day 10: Linux TUN device support for the VPS forward path.
//!
//! Architecture:
//!
//! ```text
//! BondNet DATA payload (a raw IP packet)
//!   → validate_ip_packet()          (pure, portable, no privileges needed)
//!   → bounded mpsc queue (1024)     (backpressure: drop newest, counted)
//!   → dedicated writer thread       (never blocks the Tokio executor)
//!   → TunDevice::write_packet()     (one write(2) per packet, IFF_TUN | IFF_NO_PI)
//!   → Linux kernel routing → NAT → Internet
//! ```
//!
//! Only packets that arrived as `PacketType::Data`, decoded by
//! `bondnet-protocol`, and passed IP validation ever reach the TUN device.
//! Arbitrary UDP datagrams can never become TUN traffic.
//!
//! # Privileges
//!
//! Creating a TUN device needs `CAP_NET_ADMIN` (or root). Without it,
//! [`TunDevice::create`] fails with [`TunError::PermissionDenied`] and a
//! message that says exactly what is missing. There is intentionally NO
//! silent fallback to a fake device.
//!
//! # Lifecycle
//!
//! The device is created WITHOUT `IFF_PERSIST`, so the kernel destroys it
//! automatically when the last file descriptor closes. The server closes it
//! on shutdown (writer thread joins after the queue drains).
//!
//! Address assignment (`ip addr add …/24 dev …`) and `ip link set … up` are
//! deliberately NOT done here: they are explicit administrator commands,
//! documented in `docs/vps-day10-setup.md` and printed by
//! `--print-setup`. This crate never runs shell commands and never
//! rewrites host networking on its own.

#[cfg(target_os = "linux")]
mod linux;

mod device;

use std::fmt;
use std::net::Ipv4Addr;

pub use device::TunDevice;

/// Validated TUN interface configuration.
///
/// The address/prefix are the TUN device's own address (e.g. `10.200.0.1`
/// with prefix `24`, i.e. subnet `10.200.0.0/24`). The subnet should be a
/// private range that does not collide with networks the VPS already uses;
/// see `docs/vps-day10-setup.md` for how to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Interface name, e.g. `bondtun0`. Kernel limit: 15 bytes.
    pub name: String,
    /// The TUN device's own IPv4 address.
    pub address: Ipv4Addr,
    /// Prefix length, 1..=32.
    pub prefix: u8,
}

/// Why a [`TunConfig`] was rejected. Pure validation, no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunConfigError {
    /// Interface name is empty.
    EmptyName,
    /// Interface name longer than 15 bytes (kernel `IFNAMSIZ - 1`).
    NameTooLong,
    /// Interface name contains characters outside `[A-Za-z0-9_-]`.
    BadNameChar(char),
    /// Prefix length outside 1..=32.
    BadPrefix(u8),
}

impl fmt::Display for TunConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunConfigError::EmptyName => write!(f, "TUN interface name is empty"),
            TunConfigError::NameTooLong => {
                write!(f, "TUN interface name exceeds 15 bytes (kernel IFNAMSIZ-1)")
            }
            TunConfigError::BadNameChar(c) => write!(
                f,
                "TUN interface name contains invalid character {c:?} (allowed: A-Z a-z 0-9 _ -)"
            ),
            TunConfigError::BadPrefix(p) => {
                write!(f, "TUN prefix length {p} is outside 1..=32")
            }
        }
    }
}

impl std::error::Error for TunConfigError {}

impl TunConfig {
    /// Build and validate a TUN configuration. Never touches the OS.
    pub fn new(name: &str, address: Ipv4Addr, prefix: u8) -> Result<Self, TunConfigError> {
        if name.is_empty() {
            return Err(TunConfigError::EmptyName);
        }
        if name.len() > 15 {
            return Err(TunConfigError::NameTooLong);
        }
        if let Some(c) = name
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && *c != '_' && *c != '-')
        {
            return Err(TunConfigError::BadNameChar(c));
        }
        if !(1..=32).contains(&prefix) {
            return Err(TunConfigError::BadPrefix(prefix));
        }
        Ok(Self {
            name: name.to_string(),
            address,
            prefix,
        })
    }

    /// The subnet in CIDR notation, e.g. `10.200.0.0/24`, for NAT rules.
    pub fn subnet_cidr(&self) -> String {
        let bits = u32::from(self.address);
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        let network = Ipv4Addr::from(bits & mask);
        format!("{network}/{}", self.prefix)
    }
}

/// Every way creating or using a TUN device can fail.
#[derive(Debug)]
pub enum TunError {
    /// `/dev/net/tun` exists but the process may not create devices.
    /// Message names the missing capability (`CAP_NET_ADMIN`).
    PermissionDenied(String),
    /// `/dev/net/tun` (or the platform TUN control node) does not exist.
    NotFound(String),
    /// `open`/`ioctl` failed for another reason. Never a placeholder.
    CreateFailed(String),
    /// Called on a platform without a TUN backend (anything but Linux).
    UnsupportedPlatform(&'static str),
    /// A `write(2)` would have blocked. The packet is dropped and counted;
    /// see the module docs for the backpressure policy.
    WouldBlock,
    /// A `read(2)`/`write(2)` I/O error.
    Io(std::io::Error),
}

impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunError::PermissionDenied(msg) => write!(f, "TUN permission denied: {msg}"),
            TunError::NotFound(msg) => write!(f, "TUN device node not found: {msg}"),
            TunError::CreateFailed(msg) => write!(f, "TUN creation failed: {msg}"),
            TunError::UnsupportedPlatform(msg) => write!(f, "TUN unsupported: {msg}"),
            TunError::WouldBlock => write!(f, "TUN write would block; packet dropped"),
            TunError::Io(e) => write!(f, "TUN I/O error: {e}"),
        }
    }
}

impl std::error::Error for TunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TunError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Day 11: the structural IP gate moved to `bondnet-protocol::ip` so the
/// Windows client return path can use the identical validation. Re-exported
/// here so existing `bondnet_server::tun::{...}` imports keep compiling.
pub use bondnet_protocol::{IpRejectReason, IpVersion, validate_ip_packet};

/// Print the explicit administrator commands for this server's TUN/NAT
/// setup. Pure output: prints values from the configuration, runs nothing.
pub fn print_setup_guide(
    tun: Option<&TunConfig>,
    wan_interface: Option<&str>,
    out: &mut dyn fmt::Write,
) -> fmt::Result {
    let (name, cidr, addr) = match tun {
        Some(t) => (t.name.clone(), t.subnet_cidr(), t.address.to_string()),
        None => (
            "bondtun0".to_string(),
            "10.200.0.0/24".to_string(),
            "10.200.0.1".to_string(),
        ),
    };
    let wan = wan_interface.unwrap_or("<wan-interface>");
    if tun.is_none() {
        writeln!(
            out,
            "# NOTE: no --tun-name was given, so TUN values below are examples."
        )?;
        writeln!(
            out,
            "# Run with --tun-name/--tun-addr/--tun-prefix to fill them in."
        )?;
        writeln!(out)?;
    }
    writeln!(
        out,
        "# BondNet Day 10 VPS setup — explicit administrator commands."
    )?;
    writeln!(out, "# Nothing here is executed by bondnet-server itself.")?;
    writeln!(out)?;
    writeln!(out, "# 1. Enable IPv4 forwarding (persist across reboots):")?;
    writeln!(out, "sudo sysctl -w net.ipv4.ip_forward=1")?;
    writeln!(
        out,
        "echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-bondnet.conf"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "# 2. bondnet-server creates /dev/{name} at startup (needs CAP_NET_ADMIN)."
    )?;
    writeln!(out, "#    Then assign its address and bring it up:")?;
    writeln!(
        out,
        "sudo ip addr add {addr}/{prefix} dev {name}",
        prefix = cidr.split('/').nth(1).unwrap_or("24")
    )?;
    writeln!(out, "sudo ip link set {name} up")?;
    writeln!(
        out,
        "ip route show {cidr}   # expect: {cidr} dev {name} scope link"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "# 3. Find the Internet-facing interface — NEVER assume eth0:"
    )?;
    writeln!(
        out,
        "ip route get 1.1.1.1   # 'dev <name>' in the output is the WAN interface"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "# 4. NAT/masquerade the TUN subnet out the WAN interface:"
    )?;
    writeln!(
        out,
        "sudo iptables -t nat -A POSTROUTING -s {cidr} -o {wan} -j MASQUERADE"
    )?;
    writeln!(
        out,
        "# Inspect (read-only): sudo iptables -t nat -S POSTROUTING"
    )?;
    writeln!(out, "# nftables equivalent:")?;
    writeln!(
        out,
        "sudo nft add rule ip nat POSTROUTING ip saddr {cidr} oifname \"{wan}\" masquerade"
    )?;
    writeln!(
        out,
        "# NEVER run: iptables -F | iptables -t nat -F  (destroys existing rules)"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "# 5. FORWARD chain — only needed if its default policy is DROP"
    )?;
    writeln!(out, "#    (check: sudo iptables -S FORWARD):")?;
    writeln!(
        out,
        "sudo iptables -A FORWARD -i {name} -o {wan} -s {cidr} -j ACCEPT"
    )?;
    writeln!(
        out,
        "sudo iptables -A FORWARD -i {wan} -o {name} -d {cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )?;
    writeln!(out)?;
    writeln!(out, "# 6. Reverse-path filtering: do NOT disable globally.")?;
    writeln!(
        out,
        "#    Only if return traffic misbehaves, scope it to the TUN device:"
    )?;
    writeln!(out, "sudo sysctl -w net.ipv4.conf.{name}.rp_filter=2")?;
    writeln!(out)?;
    writeln!(out, "# 7. Verify a forwarded packet leaves the VPS:")?;
    writeln!(
        out,
        "ip -s link show {name}   # RX counters grow per TUN_TX log line (writes into the fd arrive as received packets)"
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: IP validation tests moved with the gate to
    // `bondnet-protocol/src/ip.rs` (Day 11).

    #[test]
    fn tun_config_valid() {
        let c = TunConfig::new("bondtun0", "10.200.0.1".parse().unwrap(), 24).unwrap();
        assert_eq!(c.name, "bondtun0");
        assert_eq!(c.subnet_cidr(), "10.200.0.0/24");
    }

    #[test]
    fn tun_config_rejects_empty_name() {
        assert_eq!(
            TunConfig::new("", "10.200.0.1".parse().unwrap(), 24),
            Err(TunConfigError::EmptyName)
        );
    }

    #[test]
    fn tun_config_rejects_long_name() {
        assert_eq!(
            TunConfig::new("0123456789abcdef", "10.200.0.1".parse().unwrap(), 24),
            Err(TunConfigError::NameTooLong)
        );
    }

    #[test]
    fn tun_config_rejects_bad_name_char() {
        assert_eq!(
            TunConfig::new("tun/0", "10.200.0.1".parse().unwrap(), 24),
            Err(TunConfigError::BadNameChar('/'))
        );
    }

    #[test]
    fn tun_config_rejects_bad_prefix() {
        assert_eq!(
            TunConfig::new("bondtun0", "10.200.0.1".parse().unwrap(), 0),
            Err(TunConfigError::BadPrefix(0))
        );
        assert_eq!(
            TunConfig::new("bondtun0", "10.200.0.1".parse().unwrap(), 33),
            Err(TunConfigError::BadPrefix(33))
        );
    }

    #[test]
    fn tun_config_allows_15_byte_name() {
        let c = TunConfig::new("123456789012345", "10.200.0.1".parse().unwrap(), 24).unwrap();
        assert_eq!(c.name.len(), 15);
    }

    #[test]
    fn subnet_cidr_masks_host_bits() {
        let c = TunConfig::new("t0", "10.200.0.99".parse().unwrap(), 24).unwrap();
        assert_eq!(c.subnet_cidr(), "10.200.0.0/24");
    }

    #[test]
    fn setup_guide_mentions_configured_values() {
        let c = TunConfig::new("bondtun0", "10.200.0.1".parse().unwrap(), 24).unwrap();
        let mut out = String::new();
        print_setup_guide(Some(&c), Some("eth0"), &mut out).unwrap();
        assert!(out.contains("bondtun0"));
        assert!(out.contains("10.200.0.1/24"));
        assert!(out.contains("10.200.0.0/24"));
        assert!(out.contains("-o eth0"));
        // The guide must warn against flushing, never instruct it.
        assert!(out.contains("NEVER run"));
    }

    #[test]
    fn setup_guide_without_tun_says_values_are_examples() {
        let mut out = String::new();
        print_setup_guide(None, None, &mut out).unwrap();
        assert!(out.contains("are examples"));
        assert!(out.contains("<wan-interface>"));
    }
}
