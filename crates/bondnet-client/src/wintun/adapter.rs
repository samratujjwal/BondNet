//! Safe wrapper around a Wintun adapter handle.
//!
//! Preferred lifecycle: [`WintunAdapter::open_or_create`] — open the
//! existing `BondNet` adapter, create it only when it genuinely does not
//! exist (`ERROR_FILE_NOT_FOUND` or `ERROR_NOT_FOUND`). Any other
//! `WintunOpenAdapter` failure (access denied, driver failure, …) is
//! returned as-is and never misread as "adapter missing".
//!
//! Day 8 creates the adapter only. It does NOT assign an IP, routes, DNS,
//! MTU or gateway — that is a separate, later task.

use std::sync::Arc;

#[cfg(windows)]
use std::ffi::c_void;

use super::ffi::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND};
use super::{WintunError, WintunLibrary};

/// Default adapter name shown in Windows network settings.
pub const DEFAULT_ADAPTER_NAME: &str = "BondNet";
/// Default Wintun tunnel-type name.
pub const DEFAULT_TUNNEL_TYPE: &str = "BondNet";
/// Wintun adapter names are limited to 128 wide characters.
pub const MAX_ADAPTER_NAME_LEN: usize = 128;

/// Validate an adapter name without touching any Windows API.
pub fn validate_adapter_name(name: &str) -> Result<(), WintunError> {
    if name.is_empty() || name.len() > MAX_ADAPTER_NAME_LEN {
        Err(WintunError::InvalidAdapterName)
    } else {
        Ok(())
    }
}

/// Whether a `WintunOpenAdapter` failure code means "no such adapter".
///
/// Both codes have been observed on real Windows systems for a missing
/// adapter: 2 (`ERROR_FILE_NOT_FOUND`) and 1168 (`ERROR_NOT_FOUND`,
/// "Element not found" — seen on Windows 11). Pure function, tested on
/// every platform.
pub fn is_adapter_missing(code: u32) -> bool {
    code == ERROR_FILE_NOT_FOUND || code == ERROR_NOT_FOUND
}

/// Encode a Rust string as NUL-terminated UTF-16 for Wintun.
#[cfg(any(windows, test))]
fn widen(name: &str) -> Result<Vec<u16>, WintunError> {
    validate_adapter_name(name)?;
    Ok(name.encode_utf16().chain(std::iter::once(0)).collect())
}

/// An open (or newly created) Wintun adapter.
///
/// Holds an `Arc<WintunLibrary>` so the DLL outlives the adapter.
/// [`WintunSession`] borrows the adapter, so a session can never outlive
/// it — the close-while-session-alive ordering is unrepresentable.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct WintunAdapter {
    lib: Arc<WintunLibrary>,
    #[cfg(windows)]
    handle: *mut c_void,
}

// # Safety: the handle is opaque and only passed back to Wintun through
// the resolved API; the `Arc` keeps the DLL mapped across threads.
#[cfg(windows)]
unsafe impl Send for WintunAdapter {}

#[cfg(windows)]
impl WintunAdapter {
    /// Open an existing adapter by name.
    pub fn open(lib: &Arc<WintunLibrary>, name: &str) -> Result<Self, WintunError> {
        let wide = widen(name)?;
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 string for the
        // call; on success the returned handle is owned by us.
        let handle = unsafe { (lib.api().open_adapter)(wide.as_ptr()) };
        if handle.is_null() {
            return Err(WintunError::AdapterOpenFailed(super::last_error()));
        }
        Ok(Self {
            lib: Arc::clone(lib),
            handle,
        })
    }

    /// Create a new adapter. Requires Administrator privileges; without
    /// them this fails with `AdapterCreateFailed(5)` (Access is denied)
    /// instead of failing silently.
    pub fn create(lib: &Arc<WintunLibrary>, name: &str) -> Result<Self, WintunError> {
        let wide_name = widen(name)?;
        let wide_type = widen(DEFAULT_TUNNEL_TYPE)?;
        // SAFETY: both strings are valid NUL-terminated UTF-16 for the
        // call; NULL GUID asks Wintun to generate the adapter GUID.
        let handle = unsafe {
            (lib.api().create_adapter)(wide_name.as_ptr(), wide_type.as_ptr(), std::ptr::null())
        };
        if handle.is_null() {
            return Err(WintunError::AdapterCreateFailed(super::last_error()));
        }
        Ok(Self {
            lib: Arc::clone(lib),
            handle,
        })
    }

    /// Open the adapter if it exists, create it if it does not.
    ///
    /// Only the "missing adapter" codes (`ERROR_FILE_NOT_FOUND` /
    /// `ERROR_NOT_FOUND`) trigger creation. Permission, driver and DLL
    /// failures propagate unchanged.
    pub fn open_or_create(lib: &Arc<WintunLibrary>, name: &str) -> Result<Self, WintunError> {
        validate_adapter_name(name)?;
        match Self::open(lib, name) {
            Ok(adapter) => Ok(adapter),
            Err(WintunError::AdapterOpenFailed(code)) if is_adapter_missing(code) => {
                Self::create(lib, name)
            }
            Err(other) => Err(other),
        }
    }

    /// Borrow the loaded library (for session creation).
    pub(crate) fn library(&self) -> &Arc<WintunLibrary> {
        &self.lib
    }

    /// Raw handle, for session creation only. Never exposed publicly.
    pub(crate) fn handle(&self) -> *mut c_void {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for WintunAdapter {
    fn drop(&mut self) {
        // SAFETY: every session borrows `&WintunAdapter`, so no session can
        // still be alive when the adapter drops. The `Arc` keeps the DLL
        // mapped for this final call.
        unsafe {
            (self.lib.api().close_adapter)(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_name_rejected() {
        assert!(matches!(
            validate_adapter_name(""),
            Err(WintunError::InvalidAdapterName)
        ));
    }

    #[test]
    fn overlong_name_rejected() {
        let long = "a".repeat(MAX_ADAPTER_NAME_LEN + 1);
        assert!(matches!(
            validate_adapter_name(&long),
            Err(WintunError::InvalidAdapterName)
        ));
    }

    #[test]
    fn boundary_names_accepted() {
        assert!(validate_adapter_name("B").is_ok());
        assert!(validate_adapter_name(DEFAULT_ADAPTER_NAME).is_ok());
        let max = "a".repeat(MAX_ADAPTER_NAME_LEN);
        assert!(validate_adapter_name(&max).is_ok());
    }

    #[test]
    fn widen_produces_nul_terminated_utf16() {
        let wide = widen("BondNet").unwrap();
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(String::from_utf16_lossy(&wide[..wide.len() - 1]), "BondNet");
    }

    #[test]
    fn widen_rejects_empty_without_touching_windows() {
        assert!(widen("").is_err());
    }

    #[test]
    fn missing_adapter_codes_are_recognized() {
        // Seen on real Windows: 2 and 1168 both mean "no such adapter".
        assert!(is_adapter_missing(ERROR_FILE_NOT_FOUND));
        assert!(is_adapter_missing(ERROR_NOT_FOUND));
        // Everything else must NOT trigger creation.
        for code in [0u32, 5, 8, 31, 259, 1167, 1169, u32::MAX] {
            assert!(!is_adapter_missing(code), "{code} must not mean missing");
        }
    }
}
