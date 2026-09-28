//! Safe wrapper around a Wintun session handle.
//!
//! The receive ring capacity is validated in pure Rust before anything
//! reaches Wintun: 128 KiB – 64 MiB and a power of two, default 4 MiB.
//!
//! # Receive memory rule (§9)
//!
//! `WintunReceivePacket` returns a pointer OWNED BY THE SESSION. The bytes
//! are copied into a `Vec<u8>` first and `WintunReleaseReceivePacket` runs
//! immediately after — never before the copy, never skipped, and the raw
//! pointer never leaves this module.

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use super::ffi::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
#[cfg(windows)]
use super::packet::validate_send_len;
use super::{WintunAdapter, WintunError};

/// Minimum session ring capacity: 128 KiB.
pub const MIN_RING_CAPACITY: u32 = 128 * 1024;
/// Maximum session ring capacity: 64 MiB.
pub const MAX_RING_CAPACITY: u32 = 64 * 1024 * 1024;
/// Default session ring capacity: 4 MiB (`0x400000`).
pub const DEFAULT_RING_CAPACITY: u32 = 4 * 1024 * 1024;

/// Validate a ring capacity without touching any Windows API.
pub fn validate_ring_capacity(capacity: u32) -> Result<(), WintunError> {
    if !(MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&capacity) || !capacity.is_power_of_two() {
        Err(WintunError::InvalidRingCapacity(capacity))
    } else {
        Ok(())
    }
}

/// An active Wintun packet session.
///
/// Borrows the adapter, so the adapter cannot be closed while the session
/// is alive. `Drop` ends the session.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct WintunSession<'a> {
    adapter: &'a WintunAdapter,
    #[cfg(windows)]
    handle: *mut c_void,
}

// # Safety: the handle is opaque and only passed back to Wintun; the
// borrowed adapter (and its `Arc<WintunLibrary>`) keeps the DLL mapped.
// `Sync` is deliberately NOT implemented — Day 8 is single-threaded by
// design (`recv_packet`/`send_packet` take `&mut self`).
#[cfg(windows)]
unsafe impl Send for WintunSession<'_> {}

#[cfg(windows)]
impl<'a> WintunSession<'a> {
    /// Start a session on `adapter` with the given ring capacity.
    pub fn start(adapter: &'a WintunAdapter, capacity: u32) -> Result<Self, WintunError> {
        validate_ring_capacity(capacity)?;
        // SAFETY: capacity is validated; on success the session handle is
        // owned by us and tied to `adapter`'s lifetime.
        let handle = unsafe { (adapter.library().api().start_session)(adapter.handle(), capacity) };
        if handle.is_null() {
            return Err(WintunError::SessionStartFailed(super::last_error()));
        }
        Ok(Self { adapter, handle })
    }

    /// Receive one Layer-3 packet (IPv4 or IPv6, never Ethernet).
    ///
    /// - `Ok(Some(bytes))` — a packet; bytes are already copied into owned
    ///   memory and the Wintun buffer released.
    /// - `Ok(None)` — ring currently empty (`ERROR_NO_MORE_ITEMS`); wait
    ///   on the read event instead of busy-looping.
    pub fn recv_packet(&mut self) -> Result<Option<Vec<u8>>, WintunError> {
        let mut size: u32 = 0;
        // SAFETY: `size` is a valid out-pointer for the call.
        let packet =
            unsafe { (self.adapter.library().api().receive_packet)(self.handle, &mut size) };
        if packet.is_null() {
            let code = super::last_error();
            if code == ERROR_NO_MORE_ITEMS {
                return Ok(None);
            }
            return Err(WintunError::ReceiveFailed(code));
        }
        // CRITICAL ORDER: copy first, release second. The pointer is owned
        // by the session and dies at release; nothing may observe it after.
        let bytes = unsafe { std::slice::from_raw_parts(packet, size as usize) }.to_vec();
        // SAFETY: `packet` came from `receive_packet` on this session and
        // has not been released yet — exactly one release, right here.
        unsafe {
            (self.adapter.library().api().release_receive_packet)(self.handle, packet);
        }
        Ok(Some(bytes))
    }

    /// Block until a packet is available or `timeout` elapses.
    ///
    /// Returns `Ok(true)` when the read event was signaled (retry
    /// `recv_packet`), `Ok(false)` on timeout.
    pub fn wait_for_packet(&self, timeout: Duration) -> Result<bool, WintunError> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        // SAFETY: resolved at startup; the `Arc` chain keeps the DLL mapped.
        let event = unsafe { (self.adapter.library().api().get_read_wait_event)(self.handle) };
        if event.is_null() {
            return Err(WintunError::WaitFailed(super::last_error()));
        }
        let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY: `event` is a valid waitable handle from Wintun.
        let status = unsafe { WaitForSingleObject(event, millis) };
        match status {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(WintunError::WaitFailed(super::last_error())),
        }
    }

    /// Send one Layer-3 packet (IPv4 or IPv6, never Ethernet).
    ///
    /// The packet is validated (`1..=65535` bytes), copied into a
    /// Wintun-allocated send buffer, and handed to Wintun — ownership of
    /// the buffer transfers to Wintun at `WintunSendPacket` and is never
    /// freed by us. A full send ring surfaces as `SendBufferFull`, never a
    /// panic and never a leaked allocation.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), WintunError> {
        validate_send_len(packet.len())?;
        // SAFETY: length is validated to fit `u32`.
        let buffer = unsafe {
            (self.adapter.library().api().allocate_send_packet)(self.handle, packet.len() as u32)
        };
        if buffer.is_null() {
            let code = super::last_error();
            if code == ERROR_INSUFFICIENT_BUFFER {
                return Err(WintunError::SendBufferFull);
            }
            return Err(WintunError::SendFailed(code));
        }
        // SAFETY: `buffer` is a Wintun-owned region of exactly
        // `packet.len()` writable bytes; the copy cannot overrun it.
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
        }
        // SAFETY: `buffer` came from `allocate_send_packet` on this session
        // and has not been sent yet — ownership transfers to Wintun here.
        unsafe {
            (self.adapter.library().api().send_packet)(self.handle, buffer);
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WintunSession<'_> {
    fn drop(&mut self) {
        // SAFETY: the session handle is valid until now, and the borrowed
        // adapter (plus its `Arc<WintunLibrary>`) keeps the DLL mapped for
        // this final call.
        unsafe {
            (self.adapter.library().api().end_session)(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_minimum_rejected() {
        assert!(matches!(
            validate_ring_capacity(MIN_RING_CAPACITY - 1),
            Err(WintunError::InvalidRingCapacity(_))
        ));
        assert!(validate_ring_capacity(0).is_err());
    }

    #[test]
    fn above_maximum_rejected() {
        assert!(matches!(
            validate_ring_capacity(MAX_RING_CAPACITY + 1),
            Err(WintunError::InvalidRingCapacity(_))
        ));
        assert!(validate_ring_capacity(u32::MAX).is_err());
    }

    #[test]
    fn non_power_of_two_rejected() {
        for bad in [
            128 * 1024 + 1,
            192 * 1024,
            3 * 1024 * 1024,
            48 * 1024 * 1024,
        ] {
            assert!(
                validate_ring_capacity(bad).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn valid_capacities_accepted() {
        for good in [
            131072u32,
            262144,
            524288,
            1048576,
            4194304,
            67108864,
            MIN_RING_CAPACITY,
            MAX_RING_CAPACITY,
            DEFAULT_RING_CAPACITY,
        ] {
            assert!(
                validate_ring_capacity(good).is_ok(),
                "{good} should be accepted"
            );
        }
    }

    #[test]
    fn default_capacity_is_sane() {
        assert_eq!(DEFAULT_RING_CAPACITY, 0x400000);
        assert!(validate_ring_capacity(DEFAULT_RING_CAPACITY).is_ok());
    }
}
