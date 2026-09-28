//! Day 2 protocol tests: round trips, strict validation, boundaries,
//! and exact wire bytes. Everything here exercises only the public API.

use bondnet_protocol::{
    HEADER_LEN, MAX_PAYLOAD_LEN, PROTOCOL_VERSION, Packet, PacketHeader, PacketType, ProtocolError,
};

fn sample_header() -> PacketHeader {
    PacketHeader {
        version: PROTOCOL_VERSION,
        flags: 0,
        session_id: 0x0102030405060708,
        sequence: 0x1112131415161718,
        path_id: 0x2122,
        packet_type: PacketType::Data,
        timestamp: 0x3132333435363738,
    }
}

fn sample_packet() -> Packet {
    Packet {
        header: sample_header(),
        payload: vec![0xAA, 0xBB],
    }
}

#[test]
fn header_size_is_36() {
    // magic(2) + version(1) + flags(1) + header_len(2) + session_id(8)
    // + sequence(8) + path_id(2) + packet_type(1) + reserved(1)
    // + timestamp(8) + payload_len(2)
    assert_eq!(HEADER_LEN, 2 + 1 + 1 + 2 + 8 + 8 + 2 + 1 + 1 + 8 + 2);
}

#[test]
fn round_trip_basic() {
    let packet = sample_packet();
    let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn empty_payload_round_trip() {
    let packet = Packet {
        header: sample_header(),
        payload: Vec::new(),
    };
    let bytes = packet.encode().unwrap();
    assert_eq!(bytes.len(), HEADER_LEN);
    let decoded = Packet::decode(&bytes).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn binary_payload_preserved() {
    let payload = vec![0x00, 0xFF, 0x01, 0x80, 0x00, 0xFF];
    let packet = Packet {
        header: sample_header(),
        payload: payload.clone(),
    };
    let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
    assert_eq!(decoded.payload, payload);
}

#[test]
fn max_payload_round_trip() {
    let packet = Packet {
        header: sample_header(),
        payload: vec![0xAB; MAX_PAYLOAD_LEN],
    };
    let bytes = packet.encode().unwrap();
    assert_eq!(bytes.len(), HEADER_LEN + MAX_PAYLOAD_LEN);
    let decoded = Packet::decode(&bytes).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn rejects_invalid_magic() {
    let mut bytes = sample_packet().encode().unwrap();
    bytes[0] = 0x00;
    assert_eq!(Packet::decode(&bytes), Err(ProtocolError::InvalidMagic));
    let mut bytes = sample_packet().encode().unwrap();
    bytes[1] = 0x00;
    assert_eq!(Packet::decode(&bytes), Err(ProtocolError::InvalidMagic));
}

#[test]
fn rejects_unsupported_version() {
    let mut bytes = sample_packet().encode().unwrap();
    bytes[2] = 0x02;
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::UnsupportedVersion { found: 0x02 })
    );
}

#[test]
fn rejects_invalid_header_length() {
    let mut bytes = sample_packet().encode().unwrap();
    bytes[4..6].copy_from_slice(&35u16.to_be_bytes());
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::InvalidHeaderLength { found: 35 })
    );
    let mut bytes = sample_packet().encode().unwrap();
    bytes[4..6].copy_from_slice(&37u16.to_be_bytes());
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::InvalidHeaderLength { found: 37 })
    );
}

#[test]
fn rejects_nonzero_flags() {
    let mut bytes = sample_packet().encode().unwrap();
    bytes[3] = 0x01;
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::InvalidFlags { found: 0x01 })
    );
}

#[test]
fn rejects_nonzero_reserved() {
    let mut bytes = sample_packet().encode().unwrap();
    bytes[25] = 0x01;
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::InvalidReservedField { found: 0x01 })
    );
}

#[test]
fn rejects_unknown_packet_type() {
    for raw in [0x00, 0x07, 0xFF] {
        let mut bytes = sample_packet().encode().unwrap();
        bytes[24] = raw;
        assert_eq!(
            Packet::decode(&bytes),
            Err(ProtocolError::UnknownPacketType { found: raw }),
            "packet type byte {raw:#04x} must be rejected"
        );
    }
}

#[test]
fn rejects_truncated_input_without_panic() {
    for len in [0usize, 1, 10, 35] {
        let bytes = vec![0u8; len];
        assert_eq!(
            Packet::decode(&bytes),
            Err(ProtocolError::PacketTooShort { len }),
            "length {len} must be rejected, not panic"
        );
    }
}

#[test]
fn rejects_payload_length_mismatch() {
    // Declared longer than actual: valid 10-byte payload, last 5 bytes cut.
    let mut bytes = Packet {
        header: sample_header(),
        payload: vec![0xCC; 10],
    }
    .encode()
    .unwrap();
    bytes.truncate(bytes.len() - 5);
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::PayloadLengthMismatch {
            declared: 10,
            actual: 5
        })
    );

    // Declared shorter than actual: header claims 7, payload really is 10.
    let mut bytes = Packet {
        header: sample_header(),
        payload: vec![0xCC; 10],
    }
    .encode()
    .unwrap();
    bytes[34..36].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::PayloadLengthMismatch {
            declared: 7,
            actual: 10
        })
    );
}

#[test]
fn rejects_trailing_bytes() {
    let mut bytes = sample_packet().encode().unwrap();
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE]);
    assert_eq!(
        Packet::decode(&bytes),
        Err(ProtocolError::PayloadLengthMismatch {
            declared: 2,
            actual: 5
        })
    );
}

#[test]
fn sequence_boundaries() {
    for seq in [0u64, 1, u64::MAX] {
        let mut header = sample_header();
        header.sequence = seq;
        let packet = Packet {
            header,
            payload: vec![0x01],
        };
        let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded.header.sequence, seq);
    }
}

#[test]
fn session_id_boundaries() {
    for session_id in [0u64, u64::MAX] {
        let mut header = sample_header();
        header.session_id = session_id;
        let packet = Packet {
            header,
            payload: vec![0x01],
        };
        let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded.header.session_id, session_id);
    }
}

#[test]
fn path_id_boundaries() {
    for path_id in [0u16, u16::MAX] {
        let mut header = sample_header();
        header.path_id = path_id;
        let packet = Packet {
            header,
            payload: vec![0x01],
        };
        let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded.header.path_id, path_id);
    }
}

#[test]
fn timestamp_boundaries() {
    for timestamp in [0u64, u64::MAX] {
        let mut header = sample_header();
        header.timestamp = timestamp;
        let packet = Packet {
            header,
            payload: vec![0x01],
        };
        let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded.header.timestamp, timestamp);
    }
}

#[test]
fn every_packet_type_round_trips() {
    for packet_type in PacketType::all() {
        let mut header = sample_header();
        header.packet_type = packet_type;
        let packet = Packet {
            header,
            payload: vec![0x01, 0x02],
        };
        let decoded = Packet::decode(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded.header.packet_type, packet_type);
        assert_eq!(decoded.header.packet_type.as_u8(), packet_type as u8);
    }
}

#[test]
fn packet_type_wire_values_are_stable() {
    assert_eq!(PacketType::Data.as_u8(), 1);
    assert_eq!(PacketType::Ack.as_u8(), 2);
    assert_eq!(PacketType::PathHello.as_u8(), 3);
    assert_eq!(PacketType::PathKeepalive.as_u8(), 4);
    assert_eq!(PacketType::PathStats.as_u8(), 5);
    assert_eq!(PacketType::Close.as_u8(), 6);
}

#[test]
fn exact_wire_bytes() {
    let bytes = sample_packet().encode().unwrap();
    // Byte-for-byte layout of the sample packet:
    // magic "BN", version 1, flags 0, header_len 36,
    // session_id 0102030405060708, sequence 1112131415161718,
    // path_id 2122, type Data(1), reserved 0,
    // timestamp 3132333435363738, payload_len 2, payload AA BB.
    #[rustfmt::skip]
    let expected: [u8; 38] = [
        0x42, 0x4E,
        0x01,
        0x00,
        0x00, 0x24,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22,
        0x01,
        0x00,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x00, 0x02,
        0xAA, 0xBB,
    ];
    assert_eq!(bytes.as_slice(), &expected);
}

#[test]
fn fields_are_big_endian() {
    let bytes = sample_packet().encode().unwrap();
    // Most significant byte first: 0x0102... must start with 0x01, not 0x08.
    assert_eq!(
        &bytes[6..14],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(
        &bytes[14..22],
        &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
    );
    assert_eq!(&bytes[22..24], &[0x21, 0x22]);
    assert_eq!(&bytes[34..36], &[0x00, 0x02]);
}

#[test]
fn encode_rejects_unsupported_version() {
    let mut packet = sample_packet();
    packet.header.version = 2;
    assert_eq!(
        packet.encode(),
        Err(ProtocolError::UnsupportedVersion { found: 2 })
    );
}

#[test]
fn encode_rejects_nonzero_flags() {
    let mut packet = sample_packet();
    packet.header.flags = 0x80;
    assert_eq!(
        packet.encode(),
        Err(ProtocolError::InvalidFlags { found: 0x80 })
    );
}

#[test]
fn encode_rejects_oversized_payload() {
    let packet = Packet {
        header: sample_header(),
        payload: vec![0x00; MAX_PAYLOAD_LEN + 1],
    };
    assert_eq!(
        packet.encode(),
        Err(ProtocolError::PayloadTooLarge {
            len: MAX_PAYLOAD_LEN + 1
        })
    );
}
