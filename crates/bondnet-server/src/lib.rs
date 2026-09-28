//! BondNet Linux VPS server.
//!
//! Future home of the UDP listener, session handling, the Linux tunnel
//! interface, and NAT/forwarding integration. All Linux-specific code lives
//! here, never in `bondnet-core`, so the core stays portable.
//! Day 1: scaffold only. The binary entry point arrives when there is an
//! actual server to run; an empty `main` today would be fake scaffolding.
