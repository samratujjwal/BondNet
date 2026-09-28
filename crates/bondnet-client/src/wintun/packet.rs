//! Safe packet wrapper for Wintun Layer-3 packets.
//!
//! Wintun hands out IPv4 or IPv6 packets — never Ethernet frames. Day 8
//! treats them as opaque bytes: no parsing, no modification, no coupling
//! to the BondNet protocol header or crypto.

use super::WintunError;

/// Maximum sendable Layer-3 packet size: 65535 bytes.
pub const MAX_IP_PACKET_SIZE: usize = 65535;

/// Validate a send length without touching any Windows API.
///
/// Contract: 0-byte packets are rejected (there is no reason to inject an
/// empty IP packet), 1–65535 are accepted, anything larger is rejected.
pub fn validate_send_len(len: usize) -> Result<(), WintunError> {
    if len == 0 || len > MAX_IP_PACKET_SIZE {
        Err(WintunError::InvalidPacketSize(len))
    } else {
        Ok(())
    }
}

/// An owned Wintun packet. The bytes live in Rust memory; no raw Wintun
/// pointer is stored or exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WintunPacket {
    data: Vec<u8>,
}

impl WintunPacket {
    /// Wrap already-owned bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Borrow the packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Packet length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the packet is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Consume into the owned byte vector.
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_sizes_follow_contract() {
        assert!(validate_send_len(0).is_err());
        assert!(validate_send_len(1).is_ok());
        assert!(validate_send_len(1500).is_ok());
        assert!(validate_send_len(65535).is_ok());
    }

    #[test]
    fn oversized_packets_rejected() {
        assert!(matches!(
            validate_send_len(65536),
            Err(WintunError::InvalidPacketSize(65536))
        ));
        assert!(validate_send_len(usize::MAX).is_err());
    }

    #[test]
    fn wrapper_owns_its_bytes() {
        let original = vec![0x45u8, 0x00, 0xde, 0xad];
        let packet = WintunPacket::new(original.clone());
        assert_eq!(packet.as_bytes(), original.as_slice());
        assert_eq!(packet.len(), 4);
        assert!(!packet.is_empty());
        assert_eq!(packet.into_vec(), original);
    }

    #[test]
    fn wrapper_exposes_no_raw_pointers() {
        // Compile-time property, asserted structurally: the only public
        // accessors return `&[u8]`, `usize`, `bool` and `Vec<u8>`.
        let packet = WintunPacket::new(vec![1, 2, 3]);
        let bytes: &[u8] = packet.as_bytes();
        assert_eq!(bytes.len(), packet.len());
    }
}
