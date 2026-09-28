//! Manual big-endian encoding and decoding.
//!
//! No serialization frameworks are used here: the wire format must stay
//! explicit, stable, and reviewable byte by byte.

use crate::constants::{HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN, PROTOCOL_VERSION};
use crate::error::ProtocolError;
use crate::packet::{Packet, PacketType};

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

impl Packet {
    /// Serialize this packet to its exact wire representation.
    ///
    /// Fails if the header claims an unsupported version, sets unknown flag
    /// bits, or if the payload exceeds [`MAX_PAYLOAD_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.header.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                found: self.header.version,
            });
        }
        if self.header.flags != 0 {
            return Err(ProtocolError::InvalidFlags {
                found: self.header.flags,
            });
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::PayloadTooLarge {
                len: self.payload.len(),
            });
        }

        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.header.version);
        out.push(self.header.flags);
        out.extend_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        out.extend_from_slice(&self.header.session_id.to_be_bytes());
        out.extend_from_slice(&self.header.sequence.to_be_bytes());
        out.extend_from_slice(&self.header.path_id.to_be_bytes());
        out.push(self.header.packet_type.as_u8());
        out.push(0); // reserved: always zero on the wire
        out.extend_from_slice(&self.header.timestamp.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        debug_assert_eq!(out.len(), HEADER_LEN + self.payload.len());
        Ok(out)
    }

    /// Parse and strictly validate a packet from raw bytes.
    ///
    /// Never panics on untrusted input: every malformed shape maps to a
    /// [`ProtocolError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtocolError::PacketTooShort { len: bytes.len() });
        }
        if bytes[0] != MAGIC[0] || bytes[1] != MAGIC[1] {
            return Err(ProtocolError::InvalidMagic);
        }
        let version = bytes[2];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion { found: version });
        }
        let flags = bytes[3];
        if flags != 0 {
            return Err(ProtocolError::InvalidFlags { found: flags });
        }
        let header_len = read_u16(bytes, 4);
        if header_len as usize != HEADER_LEN {
            return Err(ProtocolError::InvalidHeaderLength { found: header_len });
        }
        let packet_type = PacketType::try_from(bytes[24])?;
        let reserved = bytes[25];
        if reserved != 0 {
            return Err(ProtocolError::InvalidReservedField { found: reserved });
        }
        let payload_len = read_u16(bytes, 34) as usize;
        if bytes.len() != HEADER_LEN + payload_len {
            return Err(ProtocolError::PayloadLengthMismatch {
                declared: payload_len,
                actual: bytes.len() - HEADER_LEN,
            });
        }

        Ok(Packet {
            header: crate::packet::PacketHeader {
                version,
                flags,
                session_id: read_u64(bytes, 6),
                sequence: read_u64(bytes, 14),
                path_id: read_u16(bytes, 22),
                packet_type,
                timestamp: read_u64(bytes, 26),
            },
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }
}
