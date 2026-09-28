//! Transport errors: small, readable, with the underlying cause preserved.
//!
//! Production networking paths never panic; every failure surfaces as a
//! `TransportError` with its source chained via `std::error::Error`.

use std::fmt;
use std::io;

use bondnet_protocol::ProtocolError;

/// Everything that can go wrong in the Day 7 client transport.
#[derive(Debug)]
pub enum TransportError {
    /// The configured local address was not a usable IPv4 socket address.
    InvalidLocalAddress(String),
    /// `bind(local_addr)` failed.
    BindFailed(io::Error),
    /// `connect(remote_addr)` failed.
    ConnectFailed(io::Error),
    /// Sending a datagram failed.
    SendFailed(io::Error),
    /// Receiving a datagram failed.
    ReceiveFailed(io::Error),
    /// `Packet::encode` rejected the packet.
    EncodeFailed(ProtocolError),
    /// `Packet::decode` rejected a received datagram.
    DecodeFailed(ProtocolError),
    /// The system clock could not supply a timestamp.
    ClockUnavailable,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLocalAddress(addr) => {
                write!(f, "invalid local address for a physical path: {addr}")
            }
            Self::BindFailed(_) => write!(f, "failed to bind UDP socket to local address"),
            Self::ConnectFailed(_) => write!(f, "failed to connect UDP socket to remote address"),
            Self::SendFailed(_) => write!(f, "failed to send UDP datagram"),
            Self::ReceiveFailed(_) => write!(f, "failed to receive UDP datagram"),
            Self::EncodeFailed(_) => write!(f, "failed to encode BondNet packet"),
            Self::DecodeFailed(_) => write!(f, "received datagram is not a valid BondNet packet"),
            Self::ClockUnavailable => write!(f, "system clock unavailable for packet timestamp"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BindFailed(e)
            | Self::ConnectFailed(e)
            | Self::SendFailed(e)
            | Self::ReceiveFailed(e) => Some(e),
            Self::EncodeFailed(e) | Self::DecodeFailed(e) => Some(e),
            Self::InvalidLocalAddress(_) | Self::ClockUnavailable => None,
        }
    }
}
