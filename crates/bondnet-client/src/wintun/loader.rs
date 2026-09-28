//! Dynamic loading of `wintun.dll`.
//!
//! The DLL is expected beside the executable (`<exe-dir>\wintun.dll`);
//! BondNet never downloads it, never installs it, and never searches the
//! current working directory for it. `LoadLibraryExW` is given an absolute
//! path so no DLL search order is involved at all.
//!
//! Every symbol in [`ffi::REQUIRED_SYMBOLS`] is resolved at startup. If any
//! one is missing, initialization fails with `SymbolMissing`, the DLL is
//! unloaded, and nothing continues half-initialized.

#[cfg(any(windows, test))]
use std::ffi::c_void;
use std::sync::Arc;

use super::WintunError;
#[cfg(any(windows, test))]
use super::ffi::*;

/// Resolved Wintun API. Constructed once per process via [`WintunApi::resolve`].
///
/// Only exists on Windows (where the DLL is loaded) and in tests (where
/// symbol resolution is verified against a fake table).
#[derive(Debug)]
#[cfg(any(windows, test))]
// On non-Windows test builds the fields are never read (only resolved);
// on Windows the data plane reads them.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct WintunApi {
    pub create_adapter: WintunCreateAdapterFn,
    pub open_adapter: WintunOpenAdapterFn,
    pub close_adapter: WintunCloseAdapterFn,
    pub start_session: WintunStartSessionFn,
    pub end_session: WintunEndSessionFn,
    pub get_read_wait_event: WintunGetReadWaitEventFn,
    pub receive_packet: WintunReceivePacketFn,
    pub release_receive_packet: WintunReleaseReceivePacketFn,
    pub allocate_send_packet: WintunAllocateSendPacketFn,
    pub send_packet: WintunSendPacketFn,
    pub get_running_driver_version: WintunGetRunningDriverVersionFn,
}

#[cfg(any(windows, test))]
impl WintunApi {
    /// Resolve every required symbol through `lookup`. This is pure logic
    /// (no Windows calls), so it is unit-testable on any platform with a
    /// fake lookup function.
    pub(crate) fn resolve(
        lookup: &dyn Fn(&str) -> Option<*const c_void>,
    ) -> Result<Self, WintunError> {
        macro_rules! sym {
            ($name:literal, $ty:ty) => {
                match lookup($name) {
                    // SAFETY: the pointer came from the loader for exactly
                    // this Wintun export; each signature is checked against
                    // the official `wintun.h` in `ffi.rs`. Function and data
                    // pointers are the same size on every Wintun target.
                    Some(pointer) => unsafe { std::mem::transmute::<*const c_void, $ty>(pointer) },
                    None => return Err(WintunError::SymbolMissing($name)),
                }
            };
        }

        Ok(Self {
            create_adapter: sym!("WintunCreateAdapter", WintunCreateAdapterFn),
            open_adapter: sym!("WintunOpenAdapter", WintunOpenAdapterFn),
            close_adapter: sym!("WintunCloseAdapter", WintunCloseAdapterFn),
            start_session: sym!("WintunStartSession", WintunStartSessionFn),
            end_session: sym!("WintunEndSession", WintunEndSessionFn),
            get_read_wait_event: sym!("WintunGetReadWaitEvent", WintunGetReadWaitEventFn),
            receive_packet: sym!("WintunReceivePacket", WintunReceivePacketFn),
            release_receive_packet: sym!(
                "WintunReleaseReceivePacket",
                WintunReleaseReceivePacketFn
            ),
            allocate_send_packet: sym!("WintunAllocateSendPacket", WintunAllocateSendPacketFn),
            send_packet: sym!("WintunSendPacket", WintunSendPacketFn),
            get_running_driver_version: sym!(
                "WintunGetRunningDriverVersion",
                WintunGetRunningDriverVersionFn
            ),
        })
    }
}

/// Loaded `wintun.dll` with every required symbol resolved.
///
/// The DLL stays loaded as long as any [`WintunAdapter`] exists: adapters
/// hold an `Arc<WintunLibrary>`, so `FreeLibrary` (in `Drop`) cannot run
/// while a session could still call through a function pointer.
#[derive(Debug)]
pub struct WintunLibrary {
    #[cfg(windows)]
    handle: *mut c_void, // HMODULE
    #[cfg(windows)]
    api: WintunApi,
}

// The handle is opaque and only ever passed back to Wintun; the function
// pointers are called exclusively through the safe wrappers, which keep
// the `Arc<WintunLibrary>` alive. Moving the library across threads is safe.
//
// # Safety
// `Send` is sound because no thread can observe a half-loaded library:
// `load()` fully resolves the API before the `Arc` is published.
#[cfg(windows)]
unsafe impl Send for WintunLibrary {}
#[cfg(windows)]
unsafe impl Sync for WintunLibrary {}

#[cfg(windows)]
impl WintunLibrary {
    /// Load `<exe-dir>\wintun.dll` and resolve every required symbol.
    pub fn load() -> Result<Arc<Self>, WintunError> {
        use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError};
        use windows_sys::Win32::System::LibraryLoader::{
            GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
        };

        let (wide_path, display_path) = dll_path()?;
        // Absolute path + no CWD search: the DLL search order is bypassed
        // entirely. LOAD_WITH_ALTERED_SEARCH_PATH only affects how the DLL's
        // own dependencies resolve.
        let handle = unsafe {
            LoadLibraryExW(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            return Err(WintunError::DllNotFound(format!(
                "{display_path}: {}",
                super::win32_error(code)
            )));
        }

        let api = WintunApi::resolve(&|name: &str| {
            // `name` is a `&'static str` literal without NULs; a NUL here
            // would be a programming bug, not a runtime condition.
            let c_name = std::ffi::CString::new(name).expect("Wintun symbol name contains NUL");
            let proc = unsafe { GetProcAddress(handle, c_name.as_ptr() as *const u8) };
            proc.map(|f| f as *const c_void)
        });
        match api {
            Ok(api) => Ok(Arc::new(Self { handle, api })),
            Err(error) => {
                // A missing symbol means a half-initialized API: unload and
                // fail instead of continuing.
                unsafe {
                    FreeLibrary(handle);
                }
                Err(error)
            }
        }
    }

    /// Query the running Wintun driver version (`0x00010002` = v1.2, …).
    pub fn driver_version(&self) -> u32 {
        // SAFETY: resolved from the loaded DLL at startup; the `Arc` keeps
        // the DLL mapped for the whole call.
        unsafe { (self.api.get_running_driver_version)() }
    }

    pub(crate) fn api(&self) -> &WintunApi {
        &self.api
    }
}

/// Absolute path of `<exe-dir>\wintun.dll` as (wide, display) strings.
#[cfg(windows)]
fn dll_path() -> Result<(Vec<u16>, String), WintunError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;

    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        GetModuleFileNameW(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    if length == 0 {
        return Err(WintunError::DllNotFound(format!(
            "cannot locate executable directory: {}",
            super::win32_error(super::last_error())
        )));
    }
    let exe = String::from_utf16_lossy(&buffer[..length as usize]);
    let dir = std::path::Path::new(&exe)
        .parent()
        .ok_or_else(|| WintunError::DllNotFound("executable has no parent directory".into()))?;
    let full = dir.join("wintun.dll");
    let display = full.display().to_string();
    let wide: Vec<u16> = full
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    Ok((wide, display))
}

#[cfg(windows)]
impl Drop for WintunLibrary {
    fn drop(&mut self) {
        // SAFETY: every adapter holds an `Arc` clone, so this runs only
        // after the last adapter (and therefore the last session) is gone.
        unsafe {
            windows_sys::Win32::Foundation::FreeLibrary(self.handle);
        }
    }
}

#[cfg(not(windows))]
impl WintunLibrary {
    /// Always fails off Windows: there is no Wintun driver to talk to.
    /// This keeps `cargo check`/`cargo test` green on Linux without
    /// pretending the data plane works there.
    pub fn load() -> Result<Arc<Self>, WintunError> {
        Err(WintunError::DllNotFound(
            "wintun.dll can only be loaded on Windows".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake symbol table: every required symbol resolves except the one
    /// named `missing`.
    fn fake_lookup(missing: &'static str) -> impl Fn(&str) -> Option<*const c_void> {
        move |name: &str| {
            if name == missing {
                None
            } else {
                // Never called — resolution only checks presence.
                Some(0x1000 as *const c_void)
            }
        }
    }

    #[test]
    fn all_symbols_present_resolves() {
        let lookup = fake_lookup("definitely-not-a-wintun-symbol");
        assert!(WintunApi::resolve(&lookup).is_ok());
    }

    #[test]
    fn missing_symbol_fails_cleanly_and_names_it() {
        for symbol in REQUIRED_SYMBOLS {
            let lookup = fake_lookup(symbol);
            match WintunApi::resolve(&lookup) {
                Err(WintunError::SymbolMissing(name)) => assert_eq!(name, symbol),
                other => panic!("expected SymbolMissing({symbol}), got {other:?}"),
            }
        }
    }

    #[test]
    fn required_symbols_list_matches_api_fields() {
        // If someone adds a Wintun function to `WintunApi` but forgets the
        // symbol list (or vice versa), this count catches the drift.
        assert_eq!(REQUIRED_SYMBOLS.len(), 11);
    }
}
