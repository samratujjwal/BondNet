//! Packet types and the public packet model.

use crate::error::ProtocolError;

/// BondNet packet type.
///
/// The numeric values are part of the wire protocol and must stay stable.
/// Never rely on declaration order; always use the explicit discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    /// Carries tunneled payload (e.g. an IP packet).
    Data = 1,
    /// Acknowledgement for a received packet.
    Ack = 2,
    /// Path discovery / handshake initiation.
    PathHello = 3,
    /// Path liveness heartbeat.
    PathKeepalive = 4,
    /// Path measurement report (RTT, loss, throughput).
    PathStats = 5,
    /// Session teardown.
    Close = 6,
}

impl PacketType {
    /// The stable wire value for this packet type.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Every defined packet type, for exhaustive testing.
    pub fn all() -> [PacketType; 6] {
        [
            PacketType::Data,
            PacketType::Ack,
            PacketType::PathHello,
            PacketType::PathKeepalive,
            PacketType::PathStats,
            PacketType::Close,
        ]
    }
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::Data),
            2 => Ok(PacketType::Ack),
            3 => Ok(PacketType::PathHello),
            4 => Ok(PacketType::PathKeepalive),
            5 => Ok(PacketType::PathStats),
            6 => Ok(PacketType::Close),
            _ => Err(ProtocolError::UnknownPacketType { found: value }),
        }
    }
}

/// Decoded BondNet packet header.
///
/// Length fields are derived during encoding/decoding, not stored here, so
/// the header can never disagree with itself about its own size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Protocol version. Encoders only emit [`crate::PROTOCOL_VERSION`].
    pub version: u8,
    /// Flag bits. Version 1 defines no flags; must be zero.
    pub flags: u8,
    /// BondNet tunnel session identifier.
    pub session_id: u64,
    /// BondNet tunnel sequence number. This is NOT a TCP sequence number;
    /// it belongs to the tunnel layer and drives future ordering logic.
    pub sequence: u64,
    /// Physical path identifier. Opaque number; the scheduler assigns meaning.
    pub path_id: u16,
    /// What kind of packet this is.
    pub packet_type: PacketType,
    /// Milliseconds since Unix epoch. Caller-supplied; the protocol only
    /// transports the value and never reads a clock.
    pub timestamp: u64,
}

/// A complete BondNet packet: header plus owned payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}
