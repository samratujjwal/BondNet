//! BondNet Windows client.
//!
//! Future home of Wintun integration, interface discovery, per-path UDP
//! sockets, routing exceptions, and the Windows service. All Windows-specific
//! code lives here, never in `bondnet-core`, so the core stays portable.
//! Day 1: scaffold only. The binary entry point arrives when there is an
//! actual client to run; an empty `main` today would be fake scaffolding.
