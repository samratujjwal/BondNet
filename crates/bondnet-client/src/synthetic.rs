//! Development-only synthetic Layer-3 test fixture.
//!
//! Builds a deterministic, minimal-but-valid IPv4/UDP packet used to
//! prove the Day 9 data plane without involving a real Wintun adapter:
//! Mode A of `tunnel-smoke` and the `data_plane` integration tests feed
//! these packets through `DataPlane` exactly as if Wintun had produced
//! them.
//!
//! Addresses are TEST-NET-1 (`192.0.2.0/24`, RFC 5737): guaranteed
//! unroutable, so the fixture is never a candidate for real traffic.
//! This packet is test input only — it is never sent to the Internet.

/// Build a deterministic IPv4/UDP packet carrying `payload`.
///
/// Layout: 20-byte IPv4 header (valid checksum) + 8-byte UDP header +
/// `payload`. Total length is `28 + payload.len()` bytes.
pub fn ipv4_udp_test_packet(payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45; // version 4, IHL 5
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes()); // identification
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: DF
    packet[8] = 64; // TTL
    packet[9] = 17; // protocol: UDP
    packet[12..16].copy_from_slice(&[192, 0, 2, 10]); // src: TEST-NET-1
    packet[16..20].copy_from_slice(&[192, 0, 2, 20]); // dst: TEST-NET-1
    let checksum = ip_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&40000u16.to_be_bytes()); // src port
    packet[22..24].copy_from_slice(&5001u16.to_be_bytes()); // dst port
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes()); // UDP len
    // UDP checksum left zero (optional for IPv4).
    packet[28..].copy_from_slice(payload);
    packet
}

/// Check the IPv4 header checksum of `packet`. Returns false for anything
/// shorter than a 20-byte header or with a bad checksum.
pub fn ipv4_checksum_valid(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    ip_checksum(&packet[..20]) == 0
}

/// RFC 1071 Internet checksum. Over a correct header this returns 0.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_has_valid_ipv4_header() {
        let packet = ipv4_udp_test_packet(b"bondnet-day9");
        assert_eq!(packet[0] >> 4, 4, "must be IPv4");
        assert_eq!(packet[9], 17, "must be UDP");
        let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        assert_eq!(total, packet.len(), "total-length field must match");
        assert!(ipv4_checksum_valid(&packet), "checksum must verify");
        assert_eq!(&packet[28..], b"bondnet-day9");
    }

    #[test]
    fn checksum_detects_corruption() {
        let mut packet = ipv4_udp_test_packet(b"bondnet-day9");
        packet[12] ^= 0xff; // corrupt the source address
        assert!(!ipv4_checksum_valid(&packet), "checksum must catch corruption");
    }

    #[test]
    fn empty_payload_gives_28_byte_packet() {
        assert_eq!(ipv4_udp_test_packet(&[]).len(), 28);
    }
}
