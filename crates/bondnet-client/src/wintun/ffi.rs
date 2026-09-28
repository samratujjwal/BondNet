//! Raw Wintun ABI: function-pointer types and constants.
//!
//! Everything here is platform-independent — plain `extern "system"`
//! function pointers and integer aliases — so this module compiles on any
//! target. Only `loader` touches real Windows DLL APIs; on non-Windows
//! targets loading is a clean `DllNotFound` error.
//!
//! Signatures follow the official `wintun.h` (Wintun 0.14+). Wintun uses
//! `WINAPI` (`extern "system"`, stdcall on Windows) and reports failures
//! as NULL return + `GetLastError()`.

use std::ffi::c_void;

/// Opaque Wintun adapter handle. Never dereferenced, only passed back.
pub type WintunAdapterHandle = *mut c_void;
/// Opaque Wintun session handle. Never dereferenced, only passed back.
pub type WintunSessionHandle = *mut c_void;
/// Wintun read-wait event HANDLE. Never dereferenced, only waited on.
pub type WintunEventHandle = *mut c_void;

/// `WINTUN_ADAPTER_HANDLE WINAPI WintunCreateAdapter(const WCHAR *Name, const WCHAR *TunnelType, const GUID *RequestedGUID)`
///
/// `RequestedGUID` is passed as NULL (Wintun generates the adapter GUID);
/// typed as `*const c_void` so no Windows GUID struct is needed here.
pub type WintunCreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> WintunAdapterHandle;
/// `WINTUN_ADAPTER_HANDLE WINAPI WintunOpenAdapter(const WCHAR *Name)`
pub type WintunOpenAdapterFn = unsafe extern "system" fn(*const u16) -> WintunAdapterHandle;
/// `void WINAPI WintunCloseAdapter(WINTUN_ADAPTER_HANDLE Adapter)`
pub type WintunCloseAdapterFn = unsafe extern "system" fn(WintunAdapterHandle);
/// `WINTUN_SESSION_HANDLE WINAPI WintunStartSession(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity)`
pub type WintunStartSessionFn =
    unsafe extern "system" fn(WintunAdapterHandle, u32) -> WintunSessionHandle;
/// `void WINAPI WintunEndSession(WINTUN_SESSION_HANDLE Session)`
pub type WintunEndSessionFn = unsafe extern "system" fn(WintunSessionHandle);
/// `HANDLE WINAPI WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Session)`
pub type WintunGetReadWaitEventFn =
    unsafe extern "system" fn(WintunSessionHandle) -> WintunEventHandle;
/// `BYTE *WINAPI WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize)`
///
/// Returns a pointer OWNED BY THE WINTUN SESSION. The caller must copy
/// the bytes first, then call `WintunReleaseReceivePacket` exactly once.
pub type WintunReceivePacketFn =
    unsafe extern "system" fn(WintunSessionHandle, *mut u32) -> *mut u8;
/// `void WINAPI WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet)`
pub type WintunReleaseReceivePacketFn = unsafe extern "system" fn(WintunSessionHandle, *const u8);
/// `BYTE *WINAPI WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize)`
///
/// The returned buffer is owned by the caller until `WintunSendPacket`,
/// which transfers ownership to Wintun. Never freed manually.
pub type WintunAllocateSendPacketFn =
    unsafe extern "system" fn(WintunSessionHandle, u32) -> *mut u8;
/// `void WINAPI WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet)`
pub type WintunSendPacketFn = unsafe extern "system" fn(WintunSessionHandle, *const u8);
/// `DWORD WINAPI WintunGetRunningDriverVersion(void)`
pub type WintunGetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;

/// `ERROR_NO_MORE_ITEMS` (259): `WintunReceivePacket`'s "ring is empty"
/// signal. Not a failure — the caller should wait on the read event.
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
/// `ERROR_FILE_NOT_FOUND` (2): one of two "no such adapter" signals from
/// `WintunOpenAdapter` observed on real Windows systems.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_NOT_FOUND` (1168, "Element not found"): the other "no such
/// adapter" signal from `WintunOpenAdapter`, seen on Windows 11 when the
/// BondNet adapter does not exist yet. `open_or_create` treats both as
/// "missing"; every other failure is returned as-is. If a future driver
/// reports yet another code here, the smoke test will show it.
pub const ERROR_NOT_FOUND: u32 = 1168;
/// `ERROR_INSUFFICIENT_BUFFER` (122): assumed "send ring full" signal from
/// `WintunAllocateSendPacket`. Any other NULL-allocation error is reported
/// as `SendFailed` instead of `SendBufferFull`.
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Every symbol Day 8 requires. `WintunSetLogger` is deliberately NOT in
/// this list: logging is optional and Day 8 proves the data plane, so a
/// missing logger symbol must not fail initialization.
pub const REQUIRED_SYMBOLS: [&str; 11] = [
    "WintunCreateAdapter",
    "WintunOpenAdapter",
    "WintunCloseAdapter",
    "WintunStartSession",
    "WintunEndSession",
    "WintunGetReadWaitEvent",
    "WintunReceivePacket",
    "WintunReleaseReceivePacket",
    "WintunAllocateSendPacket",
    "WintunSendPacket",
    "WintunGetRunningDriverVersion",
];
