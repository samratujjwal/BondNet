//! Linux TUN device creation via `/dev/net/tun`.
//!
//! Kept deliberately small and isolated: the only unsafe in the server
//! crate lives in this file. Everything else talks to [`TunDevice`],
//! which owns the file descriptor and closes it on drop.
//!
//! Device semantics chosen here:
//!
//! * `IFF_TUN` — layer-3 IP packets, no Ethernet headers (never TAP).
//! * `IFF_NO_PI` — no 4-byte packet-information header; `read`/`write`
//!   move exactly one IP packet per call.
//! * NO `IFF_PERSIST` — the kernel destroys the device when our fd
//!   closes, so shutdown cannot leave a stale interface behind.
//! * `O_NONBLOCK` — a `write(2)` that would block returns `EAGAIN`
//!   instead of stalling. The writer thread maps that to
//!   [`TunError::WouldBlock`] (drop + count), so even a wedged kernel
//!   queue cannot hang the server.
//!
//! [`TunDevice`]: super::device::TunDevice
//! [`TunError::WouldBlock`]: super::TunError::WouldBlock

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::TunError;

/// Kernel interface-name buffer size (`IFNAMSIZ`).
const IFNAMSIZ: usize = 16;
/// `_IOW('T', 202, int)` — attach the fd to a TUN/TAP interface.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
/// Layer-3 TUN device (not TAP).
const IFF_TUN: libc::c_short = 0x0001;
/// No packet-information header on read/write.
const IFF_NO_PI: libc::c_short = 0x1000;

/// `struct ifreq` as the kernel expects it for `TUNSETIFF`.
///
/// Only `ifr_name` and the first union member (`ifr_flags`) are read by
/// the kernel for this ioctl; the trailing union space is padding.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// An open `/dev/net/tun` file descriptor bound to one TUN interface.
///
/// Closes (and thereby destroys, since the device is not persistent) the
/// interface on drop.
#[derive(Debug)]
pub struct LinuxTun {
    fd: OwnedFd,
}

impl LinuxTun {
    /// Open `/dev/net/tun` and attach it to `name` (created if missing).
    pub fn create(name: &str) -> Result<Self, TunError> {
        let path = CString::new("/dev/net/tun").expect("literal has no NUL");
        // SAFETY: open(2) with a valid NUL-terminated path. O_CLOEXEC so an
        // accidental exec never leaks the fd; O_NONBLOCK per module docs.
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(open_error(io::Error::last_os_error()));
        }
        // SAFETY: open succeeded, so we own the fd exactly once.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut req = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let name_bytes = name.as_bytes();
        // TunConfig already limits names to 15 bytes; this is belt and
        // braces against silent truncation by the kernel.
        if name_bytes.len() >= IFNAMSIZ {
            return Err(TunError::CreateFailed(format!(
                "interface name {name:?} too long for ifreq"
            )));
        }
        for (i, &b) in name_bytes.iter().enumerate() {
            req.name[i] = b as libc::c_char;
        }

        // SAFETY: TUNSETIFF expects a `struct ifreq *`; `req` is a correct
        // #[repr(C)] ifreq and `fd` is an open /dev/net/tun descriptor.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &req) };
        if rc < 0 {
            return Err(ioctl_error(io::Error::last_os_error()));
        }
        Ok(Self { fd })
    }

    /// Read one IP packet. Returns the byte count; never returns an empty
    /// packet to the caller (a zero-length read means end-of-device and is
    /// reported as an I/O error so loops terminate instead of spinning).
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        loop {
            // SAFETY: read(2) into a valid, borrowed buffer.
            let rc = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(map_rw_error(err));
            }
            if rc == 0 {
                return Err(TunError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN device returned EOF",
                )));
            }
            return Ok(rc as usize);
        }
    }

    /// Write exactly one IP packet. Retries on `EINTR`; anything else —
    /// including `EAGAIN` on the non-blocking fd — is an error.
    pub fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        if packet.is_empty() {
            return Err(TunError::CreateFailed(
                "refusing to write an empty packet to TUN".to_string(),
            ));
        }
        // TUN is a datagram interface: a write either takes the whole
        // packet or fails. A partial write must NEVER be continued with
        // the remainder — that would inject a truncated fragment as its
        // own packet. Treat it as an error so the caller drops + counts
        // it instead.
        //
        // SAFETY: write(2) from a valid, borrowed buffer slice.
        let rc = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Err(map_rw_error(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "TUN write interrupted",
                )));
            }
            return Err(map_rw_error(err));
        }
        let written = rc as usize;
        if written != packet.len() {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("TUN partial write: {written} of {} bytes", packet.len()),
            )));
        }
        Ok(())
    }
}

impl AsRawFd for LinuxTun {
    /// Exposes the fd for the Day 11 reader thread's `poll(2)`. Ownership
    /// stays here; callers must not close it.
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Map an `open(2)` failure to the most helpful [`TunError`].
fn open_error(err: io::Error) -> TunError {
    match err.kind() {
        io::ErrorKind::PermissionDenied => TunError::PermissionDenied(
            "cannot open /dev/net/tun: missing CAP_NET_ADMIN (run as root or grant the capability)"
                .to_string(),
        ),
        io::ErrorKind::NotFound => TunError::NotFound(
            "cannot open /dev/net/tun: TUN support missing (is the tun module loaded?)".to_string(),
        ),
        _ => TunError::CreateFailed(format!("cannot open /dev/net/tun: {err}")),
    }
}

/// Map a `TUNSETIFF` failure to the most helpful [`TunError`].
fn ioctl_error(err: io::Error) -> TunError {
    match err.raw_os_error() {
        // EPERM from the ioctl is the classic "no CAP_NET_ADMIN" signal.
        Some(libc::EPERM) => TunError::PermissionDenied(
            "TUNSETIFF denied: missing CAP_NET_ADMIN (run as root or grant the capability)"
                .to_string(),
        ),
        _ => TunError::CreateFailed(format!("TUNSETIFF ioctl failed: {err}")),
    }
}

/// Map `read(2)`/`write(2)` failures. `EAGAIN` on our non-blocking fd
/// becomes [`TunError::WouldBlock`] (drop + count, never hang).
fn map_rw_error(err: io::Error) -> TunError {
    if err.kind() == io::ErrorKind::WouldBlock {
        TunError::WouldBlock
    } else {
        TunError::Io(err)
    }
}
