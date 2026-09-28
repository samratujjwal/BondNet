//! BondNet path scheduler.
//!
//! Decides which physical path carries each tunnel packet. It works only from
//! path measurements (bandwidth, RTT, loss, jitter, health) and never touches
//! sockets or platform code, so scheduling decisions stay unit-testable
//! without any networking.
//! Day 1: scaffold only, no scheduling logic implemented yet.
