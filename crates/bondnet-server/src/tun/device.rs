//! Portable [`TunDevice`] wrapper.
//!
//! On Linux this owns a [`LinuxTun`] (see `linux.rs`). On every other
//! platform [`TunDevice::create`] fails with
//! [`TunError::UnsupportedPlatform`] — the server binary still builds and
//! runs (Day 6/9 behavior), it just cannot forward into a TUN device.

use super::{TunConfig, TunError};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};

/// A TUN network device handle.
///
/// Owns its file descriptor: dropping the device closes it, and because
/// the device is created without `IFF_PERSIST`, the kernel destroys the
/// interface at that point. No stale interfaces after clean shutdown.
#[derive(Debug)]
pub struct TunDevice {
    #[cfg(target_os = "linux")]
    inner: super::linux::LinuxTun,
    name: String,
}

impl TunDevice {
    /// Create (or open) the TUN interface described by `config`.
    ///
    /// Fails clearly — never silently — when the platform lacks TUN or
    /// the process lacks `CAP_NET_ADMIN`.
    pub fn create(config: &TunConfig) -> Result<Self, TunError> {
        #[cfg(target_os = "linux")]
        {
            let inner = super::linux::LinuxTun::create(&config.name)?;
            Ok(Self {
                inner,
                name: config.name.clone(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            Err(TunError::UnsupportedPlatform(
                "TUN forwarding is implemented on Linux only (Day 10)",
            ))
        }
    }

    /// Interface name, e.g. `bondtun0`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Raw file descriptor, for the Day 11 reader thread's `poll(2)`.
    ///
    /// The fd stays owned by this device; callers must not close it.
    /// Only available on Linux, where the reader thread can exist.
    #[cfg(target_os = "linux")]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    /// Read one IP packet (blocking). Exists for the Day 11 return path;
    /// Day 10 does not call it.
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.read_packet(buf)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buf;
            Err(TunError::UnsupportedPlatform(
                "TUN forwarding is implemented on Linux only (Day 10)",
            ))
        }
    }

    /// Write one validated IP packet into the kernel.
    pub fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.write_packet(packet)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = packet;
            Err(TunError::UnsupportedPlatform(
                "TUN forwarding is implemented on Linux only (Day 10)",
            ))
        }
    }
}
