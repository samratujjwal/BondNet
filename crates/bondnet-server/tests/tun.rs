//! Day 10 TUN integration tests (public API surface).
//!
//! Pure-logic tests (IP validation, config validation, setup-guide text)
//! live as unit tests in `tun/mod.rs`. This file covers the platform
//! boundary: real device creation is privileged, so it is opt-in with a
//! clear reason instead of failing on machines without the capability.

use std::net::Ipv4Addr;

#[cfg(not(target_os = "linux"))]
use bondnet_server::TunError;
use bondnet_server::{IpVersion, TunConfig, TunDevice, validate_ip_packet};

#[test]
fn public_api_validates_ip_without_privileges() {
    let mut valid = vec![0u8; 20];
    valid[0] = 0x45; // version 4, IHL 5
    valid[2..4].copy_from_slice(&20u16.to_be_bytes());
    assert_eq!(validate_ip_packet(&valid), Ok(IpVersion::V4));
    assert!(validate_ip_packet(&[]).is_err());
    assert!(validate_ip_packet(&[0u8; 20]).is_err());
}

#[test]
fn public_api_builds_tun_config() {
    let config = TunConfig::new("bondtun0", Ipv4Addr::new(10, 200, 0, 1), 24).unwrap();
    assert_eq!(config.subnet_cidr(), "10.200.0.0/24");
}

/// Real TUN creation: needs `/dev/net/tun` AND `CAP_NET_ADMIN`.
///
/// Run explicitly, never in CI:
///
/// ```sh
/// cargo test -p bondnet-server --test tun -- --ignored
/// ```
#[test]
#[ignore = "requires /dev/net/tun and CAP_NET_ADMIN (root); run explicitly"]
#[cfg(target_os = "linux")]
fn real_tun_device_creates_and_writes() {
    let config = TunConfig::new("bndt_test0", Ipv4Addr::new(10, 200, 0, 1), 24).unwrap();
    let device = TunDevice::create(&config).expect("needs /dev/net/tun and CAP_NET_ADMIN to run");
    assert_eq!(device.name(), "bndt_test0");
    assert!(std::path::Path::new("/sys/class/net/bndt_test0").exists());

    // A DOWN interface rejects writes with EIO; bring it up first.
    // (This is an administrator step in production — see
    // docs/vps-day10-setup.md. The test only needs the link flag.)
    let up = std::process::Command::new("ip")
        .args(["link", "set", "bndt_test0", "up"])
        .status()
        .expect("`ip` must exist in the test environment");
    assert!(up.success(), "`ip link set bndt_test0 up` must succeed");

    // A minimal structurally-valid IPv4 packet. The kernel accepts the
    // write into its routing path (it may drop it there for lack of a
    // route — acceptance is what this test proves).
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    device
        .write_packet(&packet)
        .expect("TUN write must succeed");

    // Drop closes the fd; the non-persistent device must vanish.
    drop(device);
    assert!(!std::path::Path::new("/sys/class/net/bndt_test0").exists());
}

#[test]
#[cfg(not(target_os = "linux"))]
fn tun_create_fails_cleanly_off_linux() {
    let config = TunConfig::new("bondtun0", Ipv4Addr::new(10, 200, 0, 1), 24).unwrap();
    match TunDevice::create(&config) {
        Err(TunError::UnsupportedPlatform(_)) => {}
        other => panic!("expected UnsupportedPlatform, got {other:?}"),
    }
}
