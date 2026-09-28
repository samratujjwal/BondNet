//! Day 8 Wintun tests.
//!
//! Everything here runs on any platform: only pure-Rust logic is tested
//! (validation, error formatting, symbol resolution, the packet wrapper).
//! The real data plane — `wintun.dll`, the driver, adapter, session — is
//! proven by the manual Windows smoke test (`wintun-smoke`), never faked
//! here.

#[cfg(not(windows))]
use bondnet_client::wintun::WintunLibrary;
use bondnet_client::wintun::{
    DEFAULT_RING_CAPACITY, MAX_IP_PACKET_SIZE, MAX_RING_CAPACITY, MIN_RING_CAPACITY, WintunError,
    WintunPacket, validate_adapter_name, validate_ring_capacity, validate_send_len,
};

// Test 1: invalid ring capacity below minimum is rejected.
#[test]
fn ring_capacity_below_minimum_rejected() {
    assert!(validate_ring_capacity(MIN_RING_CAPACITY - 1).is_err());
    assert!(validate_ring_capacity(1).is_err());
    assert!(validate_ring_capacity(0).is_err());
}

// Test 2: invalid ring capacity above maximum is rejected.
#[test]
fn ring_capacity_above_maximum_rejected() {
    assert!(validate_ring_capacity(MAX_RING_CAPACITY + 1).is_err());
    assert!(validate_ring_capacity(u32::MAX).is_err());
}

// Test 3: non-power-of-two ring capacity is rejected.
#[test]
fn ring_capacity_non_power_of_two_rejected() {
    for bad in [192 * 1024u32, 3 * 1024 * 1024, 48 * 1024 * 1024, 1000] {
        assert!(
            validate_ring_capacity(bad).is_err(),
            "{bad} must be rejected"
        );
    }
}

// Test 4: the brief's valid capacities are accepted.
#[test]
fn ring_capacity_valid_set_accepted() {
    for good in [131072u32, 262144, 524288, 1048576, 4194304, 67108864] {
        assert!(
            validate_ring_capacity(good).is_ok(),
            "{good} must be accepted"
        );
    }
    assert_eq!(DEFAULT_RING_CAPACITY, 4 * 1024 * 1024);
}

// Test 5: packet sizes handled per the API contract.
#[test]
fn packet_sizes_follow_contract() {
    assert!(validate_send_len(0).is_err());
    assert!(validate_send_len(1).is_ok());
    assert!(validate_send_len(1500).is_ok());
    assert!(validate_send_len(65535).is_ok());
    assert_eq!(MAX_IP_PACKET_SIZE, 65535);
}

// Test 6: packet size above 65535 is rejected.
#[test]
fn packet_size_above_max_rejected() {
    assert!(matches!(
        validate_send_len(65536),
        Err(WintunError::InvalidPacketSize(65536))
    ));
}

// Test 7 is covered by unit tests in `wintun::loader` (fake symbol table,
// every required symbol removed one at a time -> `SymbolMissing(name)`).

// Test 8: error conversion preserves Windows error codes.
#[test]
fn error_display_preserves_windows_codes() {
    let cases = [
        (WintunError::AdapterOpenFailed(2), "2"),
        (WintunError::AdapterCreateFailed(5), "5"),
        (WintunError::SessionStartFailed(8), "8"),
        (WintunError::ReceiveFailed(6), "6"),
        (WintunError::SendFailed(122), "122"),
        (WintunError::WaitFailed(258), "258"),
    ];
    for (error, code) in cases {
        let text = error.to_string();
        assert!(
            text.contains(code),
            "error text {text:?} must contain code {code}"
        );
    }
    assert!(matches!(
        WintunError::SymbolMissing("WintunStartSession").to_string(),
        s if s.contains("WintunStartSession")
    ));
    assert!(matches!(
        WintunError::SendBufferFull.to_string(),
        s if s.contains("full")
    ));
}

// Test 9: safe packet wrapper owns its bytes and exposes no raw pointers.
#[test]
fn packet_wrapper_owns_bytes() {
    let bytes = vec![0x45u8, 0x00, 0x00, 0x3c];
    let packet = WintunPacket::new(bytes.clone());
    assert_eq!(packet.as_bytes(), bytes.as_slice());
    assert_eq!(packet.len(), bytes.len());
    assert!(!packet.is_empty());
    // Owned: the original can be dropped/mutated freely.
    drop(bytes);
    assert_eq!(packet.as_bytes(), &[0x45, 0x00, 0x00, 0x3c]);
    assert_eq!(packet.into_vec(), vec![0x45, 0x00, 0x00, 0x3c]);
}

// Test 10: adapter/session configuration validated without Windows APIs.
#[test]
fn adapter_name_validated_without_windows() {
    assert!(validate_adapter_name("BondNet").is_ok());
    assert!(validate_adapter_name("").is_err());
    assert!(validate_adapter_name(&"x".repeat(129)).is_err());
    assert!(validate_adapter_name(&"x".repeat(128)).is_ok());
}

// The loader is honestly platform-gated: off Windows it fails cleanly
// instead of pretending Wintun exists.
#[cfg(not(windows))]
#[test]
fn library_load_fails_cleanly_off_windows() {
    match WintunLibrary::load() {
        Err(WintunError::DllNotFound(_)) => {}
        other => panic!("expected DllNotFound, got {other:?}"),
    }
}
