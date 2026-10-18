//! Structural IP packet validation, shared by both tunnel ends.
//!
//! Day 10 introduced this gate on the VPS (`bondnet-server::tun`); Day 11
//! needs the identical gate on the Windows client return path, so it
//! lives here in `bondnet-protocol` — the single shared truth about what
//! a `PacketType::Data` payload may contain.
//!
//! This is a gate, not a stack: after validation the kernel (VPS TUN) or
//! the Windows IP stack (Wintun) does the real work. Checks are
//! structural only (version nibble, header bounds, declared length vs.
//! buffer) and never panic on any input. No checksums are verified.

use std::fmt;

/// IP version of a validated packet payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Why a payload was refused as an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRejectReason {
    /// Zero-length payload.
    Empty,
    /// First nibble is neither 4 nor 6.
    UnknownVersion(u8),
    /// Fewer bytes than the minimum header (20 for v4, 40 for v6).
    TruncatedHeader,
    /// IPv4 IHL field < 5 (header shorter than the minimum).
    BadIhl(u8),
    /// Declared length is inconsistent (v4: total < header; v6: overflow).
    BadTotalLength,
    /// Declared length exceeds the actual buffer (truncated on the wire).
    TruncatedPayload,
    /// Buffer holds more bytes than the declared length. Rejected instead
    /// of silently forwarding a packet with trailing garbage: each read
    /// hands us exactly one IP packet, so trailing bytes mean corruption.
    TrailingBytes,
}

impl fmt::Display for IpRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpRejectReason::Empty => write!(f, "empty payload"),
            IpRejectReason::UnknownVersion(v) => write!(f, "unknown IP version {v}"),
            IpRejectReason::TruncatedHeader => write!(f, "truncated IP header"),
            IpRejectReason::BadIhl(ihl) => write!(f, "IPv4 IHL {ihl} < 5"),
            IpRejectReason::BadTotalLength => write!(f, "inconsistent IP length fields"),
            IpRejectReason::TruncatedPayload => {
                write!(f, "declared length exceeds buffer (truncated packet)")
            }
            IpRejectReason::TrailingBytes => write!(f, "trailing bytes after IP packet"),
        }
    }
}

impl std::error::Error for IpRejectReason {}

/// Validate that `packet` is exactly one well-formed IPv4 or IPv6 packet.
///
/// Never panics on any input.
pub fn validate_ip_packet(packet: &[u8]) -> Result<IpVersion, IpRejectReason> {
    let first = packet.first().ok_or(IpRejectReason::Empty)?;
    match first >> 4 {
        4 => validate_ipv4(packet),
        6 => validate_ipv6(packet),
        version => Err(IpRejectReason::UnknownVersion(version)),
    }
}

fn validate_ipv4(packet: &[u8]) -> Result<IpVersion, IpRejectReason> {
    if packet.len() < 20 {
        return Err(IpRejectReason::TruncatedHeader);
    }
    let ihl = packet[0] & 0x0f;
    if ihl < 5 {
        return Err(IpRejectReason::BadIhl(ihl));
    }
    let header_len = ihl as usize * 4;
    if packet.len() < header_len {
        return Err(IpRejectReason::TruncatedHeader);
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len {
        return Err(IpRejectReason::BadTotalLength);
    }
    if total_len > packet.len() {
        return Err(IpRejectReason::TruncatedPayload);
    }
    if total_len < packet.len() {
        return Err(IpRejectReason::TrailingBytes);
    }
    Ok(IpVersion::V4)
}

fn validate_ipv6(packet: &[u8]) -> Result<IpVersion, IpRejectReason> {
    if packet.len() < 40 {
        return Err(IpRejectReason::TruncatedHeader);
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = 40usize
        .checked_add(payload_len)
        .ok_or(IpRejectReason::BadTotalLength)?;
    if total_len > packet.len() {
        return Err(IpRejectReason::TruncatedPayload);
    }
    if total_len < packet.len() {
        return Err(IpRejectReason::TrailingBytes);
    }
    Ok(IpVersion::V6)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_header(total_len: u16, ihl: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x40 | (ihl & 0x0f);
        p[2..4].copy_from_slice(&total_len.to_be_bytes());
        p
    }

    #[test]
    fn empty_payload_rejected() {
        assert_eq!(validate_ip_packet(&[]), Err(IpRejectReason::Empty));
    }

    #[test]
    fn valid_minimum_ipv4_accepted() {
        assert_eq!(validate_ip_packet(&ipv4_header(20, 5)), Ok(IpVersion::V4));
    }

    #[test]
    fn valid_ipv4_with_options_accepted() {
        let mut q = ipv4_header(32, 6);
        q.extend_from_slice(&[9u8; 12]);
        assert_eq!(validate_ip_packet(&q), Ok(IpVersion::V4));
    }

    #[test]
    fn ipv4_unknown_version_rejected() {
        let mut p = ipv4_header(20, 5);
        p[0] = 0x50;
        assert_eq!(
            validate_ip_packet(&p),
            Err(IpRejectReason::UnknownVersion(5))
        );
    }

    #[test]
    fn ipv4_short_ihl_rejected() {
        assert_eq!(
            validate_ip_packet(&ipv4_header(20, 4)),
            Err(IpRejectReason::BadIhl(4))
        );
    }

    #[test]
    fn ipv4_truncated_header_rejected() {
        assert_eq!(
            validate_ip_packet(&[0x45u8; 10]),
            Err(IpRejectReason::TruncatedHeader)
        );
    }

    #[test]
    fn ipv4_ihl_beyond_buffer_rejected() {
        assert_eq!(
            validate_ip_packet(&ipv4_header(60, 15)),
            Err(IpRejectReason::TruncatedHeader)
        );
    }

    #[test]
    fn ipv4_total_shorter_than_header_rejected() {
        assert_eq!(
            validate_ip_packet(&ipv4_header(10, 5)),
            Err(IpRejectReason::BadTotalLength)
        );
    }

    #[test]
    fn ipv4_total_longer_than_buffer_rejected() {
        assert_eq!(
            validate_ip_packet(&ipv4_header(100, 5)),
            Err(IpRejectReason::TruncatedPayload)
        );
    }

    #[test]
    fn ipv4_trailing_bytes_rejected() {
        let mut p = ipv4_header(20, 5);
        p.push(0xff);
        assert_eq!(validate_ip_packet(&p), Err(IpRejectReason::TrailingBytes));
    }

    #[test]
    fn all_zero_bytes_rejected_as_unknown_version() {
        assert_eq!(
            validate_ip_packet(&[0u8; 20]),
            Err(IpRejectReason::UnknownVersion(0))
        );
    }

    fn ipv6_header(payload_len: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&payload_len.to_be_bytes());
        p
    }

    #[test]
    fn valid_minimum_ipv6_accepted() {
        assert_eq!(validate_ip_packet(&ipv6_header(0)), Ok(IpVersion::V6));
    }

    #[test]
    fn valid_ipv6_with_payload_accepted() {
        let mut p = ipv6_header(32);
        p.extend_from_slice(&[7u8; 32]);
        assert_eq!(validate_ip_packet(&p), Ok(IpVersion::V6));
    }

    #[test]
    fn ipv6_truncated_header_rejected() {
        assert_eq!(
            validate_ip_packet(&[0x60u8; 30]),
            Err(IpRejectReason::TruncatedHeader)
        );
    }

    #[test]
    fn ipv6_bad_version_rejected() {
        let mut p = ipv6_header(0);
        p[0] = 0x70;
        assert_eq!(
            validate_ip_packet(&p),
            Err(IpRejectReason::UnknownVersion(7))
        );
    }

    #[test]
    fn ipv6_payload_longer_than_buffer_rejected() {
        assert_eq!(
            validate_ip_packet(&ipv6_header(64)),
            Err(IpRejectReason::TruncatedPayload)
        );
    }

    #[test]
    fn ipv6_trailing_bytes_rejected() {
        let mut p = ipv6_header(0);
        p.push(0xaa);
        assert_eq!(validate_ip_packet(&p), Err(IpRejectReason::TrailingBytes));
    }
}
