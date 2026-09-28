//! Safe Wintun bindings for the BondNet Windows client.
//!
//! Wintun is a Layer-3 virtual adapter: what comes out of the receive ring
//! is a raw IPv4 or IPv6 packet — never an Ethernet frame. Day 8 treats
//! those bytes as opaque; no IP parsing, no route/DNS/MTU configuration,
//! no Internet access through BondNet yet.
//!
//! # Safety boundary
//!
//! All `unsafe` lives behind this module's API. Safe code works only with
//! [`WintunAdapter`], [`WintunSession`], [`WintunPacket`] and [`Vec<u8>`];
//! no raw Wintun pointer ever escapes. Ownership is enforced by Rust:
//! a session borrows its adapter (it cannot outlive it) and the adapter
//! holds the DLL (it cannot be unloaded while in use).
//!
//! # Platform
//!
//! The data plane is Windows-only. On other targets the types compile but
//! [`WintunLibrary::load`] fails cleanly with [`WintunError::DllNotFound`],
//! so `cargo check`/`cargo test` stay green on Linux while the real proof
//! happens on Windows.

mod adapter;
pub mod ffi;
mod loader;
pub mod packet;
mod session;

pub use adapter::{
    DEFAULT_ADAPTER_NAME, DEFAULT_TUNNEL_TYPE, MAX_ADAPTER_NAME_LEN, WintunAdapter,
    is_adapter_missing, validate_adapter_name,
};
pub use ffi::{
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND,
};
pub use loader::WintunLibrary;
pub use packet::{MAX_IP_PACKET_SIZE, WintunPacket, validate_send_len};
pub use session::{
    DEFAULT_RING_CAPACITY, MAX_RING_CAPACITY, MIN_RING_CAPACITY, WintunSession,
    validate_ring_capacity,
};

use std::fmt;

/// Everything that can go wrong in the Day 8 Wintun layer.
#[derive(Debug)]
pub enum WintunError {
    /// `wintun.dll` could not be loaded (missing, wrong architecture, …).
    /// Carries a human-readable detail string, never a secret.
    DllNotFound(String),
    /// A required export was missing from the DLL. The DLL is unloaded and
    /// initialization fails instead of continuing half-initialized.
    SymbolMissing(&'static str),
    /// Adapter name was empty or longer than 128 characters.
    InvalidAdapterName,
    /// Ring capacity was < 128 KiB, > 64 MiB, or not a power of two.
    InvalidRingCapacity(u32),
    /// `WintunOpenAdapter` failed. Carries the raw `GetLastError()` code.
    AdapterOpenFailed(u32),
    /// `WintunCreateAdapter` failed. Carries the raw `GetLastError()` code.
    AdapterCreateFailed(u32),
    /// `WintunStartSession` failed. Carries the raw `GetLastError()` code.
    SessionStartFailed(u32),
    /// `WintunReceivePacket` failed. Carries the raw `GetLastError()` code.
    ReceiveFailed(u32),
    /// `send_packet` was given 0 bytes or more than 65535 bytes. Carries
    /// the offending length.
    InvalidPacketSize(usize),
    /// `WintunAllocateSendPacket` returned NULL because the send ring is
    /// full. Back off and retry; never a panic.
    SendBufferFull,
    /// `WintunAllocateSendPacket` failed for another reason. Carries the
    /// raw `GetLastError()` code.
    SendFailed(u32),
    /// Waiting on the read event failed. Carries the raw `GetLastError()`
    /// or wait status.
    WaitFailed(u32),
}

impl fmt::Display for WintunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DllNotFound(detail) => write!(f, "wintun.dll could not be loaded: {detail}"),
            Self::SymbolMissing(name) => {
                write!(f, "wintun.dll is missing required symbol: {name}")
            }
            Self::InvalidAdapterName => {
                write!(f, "invalid Wintun adapter name (must be 1-128 characters)")
            }
            Self::InvalidRingCapacity(cap) => write!(
                f,
                "invalid Wintun ring capacity {cap} (must be a power of two, 131072..=67108864)"
            ),
            Self::AdapterOpenFailed(code) => {
                write!(f, "failed to open Wintun adapter: {}", win32_error(*code))
            }
            Self::AdapterCreateFailed(code) => {
                write!(f, "failed to create Wintun adapter: {}", win32_error(*code))
            }
            Self::SessionStartFailed(code) => {
                write!(f, "failed to start Wintun session: {}", win32_error(*code))
            }
            Self::ReceiveFailed(code) => {
                write!(f, "Wintun packet receive failed: {}", win32_error(*code))
            }
            Self::InvalidPacketSize(len) => {
                write!(f, "invalid Wintun packet size {len} (must be 1..=65535)")
            }
            Self::SendBufferFull => {
                write!(f, "Wintun send ring is full; back off and retry")
            }
            Self::SendFailed(code) => {
                write!(f, "Wintun send allocation failed: {}", win32_error(*code))
            }
            Self::WaitFailed(code) => {
                write!(f, "Wintun read-wait failed: {}", win32_error(*code))
            }
        }
    }
}

impl std::error::Error for WintunError {}

/// Format a Win32 error code for humans. On Windows this resolves the real
/// system message via `FormatMessageW`; elsewhere it degrades to the raw
/// code (still preserves it for debugging).
pub(crate) fn win32_error(code: u32) -> String {
    #[cfg(windows)]
    if let Some(message) = system_message(code) {
        return format!("Windows error {code} ({message})");
    }
    format!("Windows error {code}")
}

/// Resolve a Win32 error code to its system message. Returns `None` when
/// the system has no message for the code.
#[cfg(windows)]
fn system_message(code: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
        FormatMessageW,
    };

    unsafe {
        let mut buffer: *mut u16 = std::ptr::null_mut();
        let length = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            code,
            0,
            std::ptr::addr_of_mut!(buffer) as *mut u16,
            0,
            std::ptr::null(),
        );
        if length == 0 || buffer.is_null() {
            return None;
        }
        let message = String::from_utf16_lossy(std::slice::from_raw_parts(buffer, length as usize));
        LocalFree(buffer as *mut std::ffi::c_void);
        let trimmed = message.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }
}

/// Read the calling thread's last-error value. Must be called immediately
/// after the failing FFI call, before anything else can overwrite it.
#[cfg(windows)]
pub(crate) fn last_error() -> u32 {
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}
