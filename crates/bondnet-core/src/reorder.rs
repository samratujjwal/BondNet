//! Tunnel packet reorder buffer.
//!
//! Multi-path networking delivers packets out of order: path A may carry
//! tunnel sequence 10 while path B already delivers 12. BondNet must hand
//! the upper layers an in-order stream of *its own tunnel sequence numbers*
//! (not TCP sequence numbers — TCP behavior is never touched).
//!
//! This module is a deterministic, platform-independent data structure. It
//! performs no networking, no encryption, no path selection, no timers, and
//! no retransmission. A future timeout/recovery layer will use [`gap()`] to
//! decide what to do about persistent gaps; Day 5 only *reports* them.
//!
//! [`gap()`]: ReorderBuffer::gap
//!
//! # Sequence semantics
//!
//! * Sequences are `u64`. The initial expected sequence is explicit:
//!   `ReorderBuffer::new(100)` means `next_expected() == 100`.
//! * **No wrap-around is implemented.** The `u64` space is treated as
//!   monotonic. Delivering sequence `u64::MAX` permanently exhausts the
//!   buffer; afterwards every push is `Duplicate` (for `u64::MAX`) or
//!   `TooOld` (for anything lower). This is documented, not silent.
//! * Missing sequences are **never auto-skipped**. If 12 and 13 are
//!   buffered while 11 is missing, they stay buffered until 11 arrives or
//!   a higher-level policy acts. Auto-skipping would silently lose tunnel
//!   packets.
//!
//! # Safety
//!
//! The buffer will eventually sit behind untrusted network input, so:
//! no panics on any input, bounded memory, no unchecked arithmetic, no
//! `unsafe` code, and every outcome is an explicit result variant.

use std::collections::BTreeMap;

/// Outcome of [`ReorderBuffer::push`].
///
/// The caller can always distinguish the five cases. Rejected packets are
/// returned to the caller instead of being silently dropped, so the caller
/// decides whether to drop, log, or count them.
#[derive(Debug, PartialEq, Eq)]
pub enum PushResult<T> {
    /// One or more packets became deliverable, in ascending sequence order.
    /// The first element is the packet that was just pushed (it matched
    /// `next_expected`); any buffered packets that are now contiguous
    /// follow it.
    Released(Vec<T>),
    /// Out-of-order packet accepted into the buffer, waiting for earlier
    /// sequences.
    Buffered,
    /// The sequence was already delivered, or is already buffered with the
    /// original value kept. The rejected packet is returned. Never delivered
    /// twice, never overwrites the buffered original.
    Duplicate(T),
    /// `sequence < next_expected`: behind the delivery frontier. The
    /// rejected packet is returned; `next_expected` never moves backwards.
    TooOld(T),
    /// The buffer already holds `max_buffered` packets. The rejected packet
    /// is returned and memory stays bounded. Never panics.
    BufferFull(T),
}

/// Snapshot of a missing-sequence gap for a future timeout/recovery layer.
///
/// Returned by [`ReorderBuffer::gap`]. Day 5 only reports the gap; the
/// decision to skip, fail, or keep waiting belongs to a later policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapInfo {
    /// The sequence the buffer is waiting for.
    pub expected: u64,
    /// The smallest buffered sequence (strictly greater than `expected`).
    pub first_buffered: u64,
    /// `first_buffered - expected`: how far ahead the buffered data is.
    pub distance: u64,
    /// How many packets are currently buffered behind the gap.
    pub buffered: usize,
}

/// Deterministic reorder buffer over `(sequence, value)` pairs.
///
/// Generic over the payload type so it never depends on UDP, encryption, or
/// `bondnet-protocol::Packet`. Internally a `BTreeMap<u64, T>` gives ordered
/// keys, deterministic behavior, and easy gap inspection. No premature
/// ring-buffer optimization; benchmark after the real traffic path exists.
#[derive(Debug)]
pub struct ReorderBuffer<T> {
    /// Next sequence the buffer will deliver. Monotonic; never decreases.
    next_expected: u64,
    /// Out-of-order packets keyed by sequence. Bounded by `max_buffered`.
    buffered: BTreeMap<u64, T>,
    /// Maximum number of packets that may sit buffered. Zero is valid: the
    /// expected packet is still deliverable, but nothing can be buffered.
    max_buffered: usize,
    /// True once `u64::MAX` has been delivered: the sequence space is
    /// exhausted and there is nothing left to expect.
    exhausted: bool,
}

impl<T> ReorderBuffer<T> {
    /// Create a buffer expecting `initial_sequence` first, holding at most
    /// `max_buffered` out-of-order packets.
    pub fn new(initial_sequence: u64, max_buffered: usize) -> Self {
        Self {
            next_expected: initial_sequence,
            buffered: BTreeMap::new(),
            max_buffered,
            exhausted: false,
        }
    }

    /// The sequence the buffer currently waits for.
    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Number of out-of-order packets currently buffered.
    pub fn len(&self) -> usize {
        self.buffered.len()
    }

    /// True when no out-of-order packets are buffered.
    pub fn is_empty(&self) -> bool {
        self.buffered.is_empty()
    }

    /// Configured upper bound on buffered packets.
    pub fn max_buffered(&self) -> usize {
        self.max_buffered
    }

    /// Describe the current gap, if any.
    ///
    /// Returns `Some` exactly when at least one buffered packet exists ahead
    /// of `next_expected`. The future timeout layer uses this to decide when
    /// a missing sequence has been gone too long.
    pub fn gap(&self) -> Option<GapInfo> {
        let (&first, _) = self.buffered.iter().next()?;
        // `first > next_expected` is an invariant: keys equal to or below
        // the frontier are never inserted (see `push`).
        debug_assert!(first > self.next_expected);
        Some(GapInfo {
            expected: self.next_expected,
            first_buffered: first,
            distance: first - self.next_expected,
            buffered: self.buffered.len(),
        })
    }

    /// Feed one packet into the buffer.
    ///
    /// * `sequence == next_expected` → release it plus every buffered packet
    ///   that is now contiguous, in order. Gaps are never skipped: buffered
    ///   packets beyond a missing sequence stay buffered.
    /// * `sequence > next_expected` → buffer it (if capacity allows), unless
    ///   the sequence is already buffered (`Duplicate`) or the buffer is
    ///   full (`BufferFull`).
    /// * `sequence < next_expected` → `TooOld`; never delivered, frontier
    ///   never moves backwards.
    ///
    /// All arithmetic is overflow-checked; no input can panic.
    pub fn push(&mut self, sequence: u64, packet: T) -> PushResult<T> {
        // The sequence space is exhausted: u64::MAX was already delivered.
        if self.exhausted {
            return if sequence == u64::MAX {
                PushResult::Duplicate(packet)
            } else {
                PushResult::TooOld(packet)
            };
        }

        if sequence < self.next_expected {
            return PushResult::TooOld(packet);
        }

        if sequence > self.next_expected {
            // Never silently replace an already-buffered packet.
            if self.buffered.contains_key(&sequence) {
                return PushResult::Duplicate(packet);
            }
            if self.buffered.len() >= self.max_buffered {
                return PushResult::BufferFull(packet);
            }
            self.buffered.insert(sequence, packet);
            return PushResult::Buffered;
        }

        // sequence == next_expected: release it, then drain every buffered
        // packet that is now contiguous. Stop at the first missing sequence
        // or at the u64 boundary (checked_add returns None for u64::MAX).
        let mut released = vec![packet];
        self.advance_frontier(&mut released);
        PushResult::Released(released)
    }

    /// Move `next_expected` past the just-released sequence and then over every
    /// contiguous buffered packet, appending them to `released` in order.
    fn advance_frontier(&mut self, released: &mut Vec<T>) {
        loop {
            let Some(next) = self.next_expected.checked_add(1) else {
                // The just-released packet was u64::MAX: the sequence space
                // is exhausted. No wrap-around, ever.
                self.exhausted = true;
                return;
            };
            self.next_expected = next;
            let Some(packet) = self.buffered.remove(&next) else {
                // Gap: missing sequence. Do NOT skip it; higher-level policy
                // decides what to do via gap().
                return;
            };
            released.push(packet);
        }
    }
}
