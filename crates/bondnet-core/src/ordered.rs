//! Day 15: ordered packet delivery with timeout-based gap policy.
//!
//! Wraps the Day 5 [`ReorderBuffer`] with:
//! - a staleness timeout: a gap that persists longer than `timeout`
//!   is skipped (the missing sequences are abandoned as loss);
//! - metrics following the project's `AtomicU64` telemetry conventions.
//!
//! The timeout prevents a permanently lost packet from blocking delivery
//! forever. Skipping is LOSS, not recovery — the caller counts the
//! skipped sequences as gaps. No ACKs, no retransmission, no encryption.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::reorder::{PushResult, ReorderBuffer};

/// Live counters for one ordered-receiver instance.
#[derive(Debug, Default)]
pub struct ReorderMetrics {
    pub packets_received: AtomicU64,
    pub packets_delivered: AtomicU64,
    pub gaps_observed: AtomicU64,
    pub gap_timeouts: AtomicU64,
    pub duplicates_dropped: AtomicU64,
    pub late_dropped: AtomicU64,
    pub overflow_dropped: AtomicU64,
    pub max_depth_observed: AtomicU64,
}

/// Plain-data copy of [`ReorderMetrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReorderMetricsSnapshot {
    pub packets_received: u64,
    pub packets_delivered: u64,
    pub gaps_observed: u64,
    pub gap_timeouts: u64,
    pub duplicates_dropped: u64,
    pub late_dropped: u64,
    pub overflow_dropped: u64,
    pub max_depth_observed: u64,
    pub current_depth: usize,
    pub next_expected: u64,
}

impl ReorderMetrics {
    fn snapshot(&self, current_depth: usize, next_expected: u64) -> ReorderMetricsSnapshot {
        ReorderMetricsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_delivered: self.packets_delivered.load(Ordering::Relaxed),
            gaps_observed: self.gaps_observed.load(Ordering::Relaxed),
            gap_timeouts: self.gap_timeouts.load(Ordering::Relaxed),
            duplicates_dropped: self.duplicates_dropped.load(Ordering::Relaxed),
            late_dropped: self.late_dropped.load(Ordering::Relaxed),
            overflow_dropped: self.overflow_dropped.load(Ordering::Relaxed),
            max_depth_observed: self.max_depth_observed.load(Ordering::Relaxed),
            current_depth,
            next_expected,
        }
    }
}

/// An ordered packet receiver: buffers out-of-order packets, releases
/// them contiguously, and skips gaps that stay stale past `timeout`.
///
/// `T` is the inner packet payload (bytes). The caller is responsible
/// for decoding, validating session/path, and extracting the logical
/// sequence BEFORE calling [`push`](Self::push) — malformed packets
/// must never reach the buffer.
///
/// The receiver is `!Sync` by design (it holds no locks); the caller
/// runs it on a single task/thread. Sequence allocation (the sender
/// side) uses `AtomicU64` and is thread-safe.
#[derive(Debug)]
pub struct OrderedReceiver<T> {
    buffer: ReorderBuffer<T>,
    gap_since: Option<Instant>,
    timeout: Duration,
    metrics: ReorderMetrics,
}

impl<T> OrderedReceiver<T> {
    /// Create a receiver expecting `initial_sequence` first, holding at
    /// most `max_buffered` out-of-order packets, skipping gaps older than
    /// `timeout`.
    pub fn new(initial_sequence: u64, max_buffered: usize, timeout: Duration) -> Self {
        Self {
            buffer: ReorderBuffer::new(initial_sequence, max_buffered),
            gap_since: None,
            timeout,
            metrics: ReorderMetrics::default(),
        }
    }

    /// Feed one validated packet into the receiver.
    ///
    /// Returns the packets that became deliverable, in ascending sequence
    /// order (may be empty). Updates metrics and gap tracking.
    ///
    /// The caller must have already validated the packet (protocol,
    /// session, path, IP) and extracted its logical sequence.
    pub fn push(&mut self, sequence: u64, packet: T) -> Vec<T> {
        self.metrics
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        let had_gap = self.buffer.gap().is_some();
        let result = self.buffer.push(sequence, packet);
        match result {
            PushResult::Released(packets) => {
                self.metrics
                    .packets_delivered
                    .fetch_add(packets.len() as u64, Ordering::Relaxed);
                // The gap (if any) is gone — reset the staleness clock.
                self.gap_since = None;
                packets
            }
            PushResult::Buffered => {
                let depth = self.buffer.len();
                self.update_max_depth(depth);
                if !had_gap {
                    // A new gap just appeared; start the staleness clock.
                    self.metrics.gaps_observed.fetch_add(1, Ordering::Relaxed);
                    self.gap_since = Some(Instant::now());
                }
                Vec::new()
            }
            PushResult::Duplicate(_) => {
                self.metrics
                    .duplicates_dropped
                    .fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
            PushResult::TooOld(_) => {
                self.metrics.late_dropped.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
            PushResult::BufferFull(_) => {
                self.metrics
                    .overflow_dropped
                    .fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
        }
    }

    /// Check whether the current gap has been stale longer than `timeout`.
    /// If so, skip it (abandon the missing sequences as loss) and return
    /// the newly deliverable packets.
    ///
    /// The caller should invoke this periodically (e.g., on a timer or
    /// after each `push`). Returns an empty vec if there is no stale gap.
    pub fn check_timeout(&mut self) -> Vec<T> {
        let stale = match self.gap_since {
            Some(since) => since.elapsed() >= self.timeout,
            None => false,
        };
        if !stale {
            return Vec::new();
        }
        match self.buffer.skip_gap() {
            Some((skipped, released)) => {
                self.metrics.gap_timeouts.fetch_add(1, Ordering::Relaxed);
                // Count the abandoned sequences as gaps observed.
                self.metrics
                    .gaps_observed
                    .fetch_add(skipped, Ordering::Relaxed);
                self.metrics
                    .packets_delivered
                    .fetch_add(released.len() as u64, Ordering::Relaxed);
                // If there's still a gap, restart the clock; otherwise clear.
                self.gap_since = if self.buffer.gap().is_some() {
                    Some(Instant::now())
                } else {
                    None
                };
                released
            }
            None => {
                self.gap_since = None;
                Vec::new()
            }
        }
    }

    /// Current metrics snapshot.
    pub fn metrics_snapshot(&self) -> ReorderMetricsSnapshot {
        self.metrics
            .snapshot(self.buffer.len(), self.buffer.next_expected())
    }

    /// The sequence the receiver currently expects.
    pub fn next_expected(&self) -> u64 {
        self.buffer.next_expected()
    }

    /// Number of out-of-order packets currently buffered.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    fn update_max_depth(&self, depth: usize) {
        let depth = depth as u64;
        let mut max = self.metrics.max_depth_observed.load(Ordering::Relaxed);
        while depth > max {
            match self.metrics.max_depth_observed.compare_exchange_weak(
                max,
                depth,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => max = current,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receiver() -> OrderedReceiver<Vec<u8>> {
        OrderedReceiver::new(1, 16, Duration::from_millis(50))
    }

    fn pkt(seq: u64) -> Vec<u8> {
        vec![seq as u8; 4]
    }

    #[test]
    fn in_order_packets_deliver_immediately() {
        let mut r = receiver();
        for seq in 1..=3 {
            let delivered = r.push(seq, pkt(seq));
            assert_eq!(delivered.len(), 1);
            assert_eq!(delivered[0], pkt(seq));
        }
        let m = r.metrics_snapshot();
        assert_eq!(m.packets_received, 3);
        assert_eq!(m.packets_delivered, 3);
        assert_eq!(m.gaps_observed, 0);
    }

    #[test]
    fn out_of_order_1_3_2_emits_in_order() {
        let mut r = receiver();
        assert!(r.push(1, pkt(1)).len() == 1);
        assert!(r.push(3, pkt(3)).is_empty());
        let delivered = r.push(2, pkt(2));
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0], pkt(2));
        assert_eq!(delivered[1], pkt(3));
    }

    #[test]
    fn duplicate_is_dropped_once() {
        let mut r = receiver();
        // Buffer seq 3 (gap at 1,2), then send it again — the second
        // copy is a true duplicate (already buffered).
        assert!(r.push(3, pkt(3)).is_empty());
        assert!(r.push(3, pkt(3)).is_empty());
        let m = r.metrics_snapshot();
        assert_eq!(m.packets_delivered, 0);
        assert_eq!(m.duplicates_dropped, 1);
        // Delivering seq 1,2 releases 1,2,3 in order (3 emitted once).
        assert_eq!(r.push(1, pkt(1)).len(), 1);
        let delivered = r.push(2, pkt(2));
        assert_eq!(delivered.len(), 2);
        let m = r.metrics_snapshot();
        assert_eq!(m.packets_delivered, 3);
    }

    #[test]
    fn late_packet_below_expected_is_dropped() {
        let mut r = receiver();
        assert_eq!(r.push(1, pkt(1)).len(), 1);
        assert_eq!(r.push(2, pkt(2)).len(), 1);
        assert!(r.push(1, pkt(1)).is_empty());
        let m = r.metrics_snapshot();
        assert_eq!(m.late_dropped, 1);
        assert_eq!(m.packets_delivered, 2);
    }

    #[test]
    fn buffer_full_stays_bounded() {
        let mut r = OrderedReceiver::new(1, 2, Duration::from_millis(50));
        assert!(r.push(2, pkt(2)).is_empty());
        assert!(r.push(3, pkt(3)).is_empty());
        // Buffer holds 2 (max); the next out-of-order packet is rejected.
        assert!(r.push(4, pkt(4)).is_empty());
        let m = r.metrics_snapshot();
        assert_eq!(m.overflow_dropped, 1);
        assert_eq!(r.buffered_len(), 2);
    }

    #[test]
    fn stale_gap_is_skipped_by_timeout() {
        let mut r = OrderedReceiver::new(1, 16, Duration::from_millis(1));
        assert!(r.push(2, pkt(2)).is_empty());
        assert!(r.push(3, pkt(3)).is_empty());
        // Gap at 1 is fresh; no skip yet.
        assert!(r.check_timeout().is_empty());
        // Wait for staleness.
        std::thread::sleep(Duration::from_millis(5));
        let released = r.check_timeout();
        // Sequence 1 was abandoned; 2 and 3 are now deliverable.
        assert_eq!(released.len(), 2);
        assert_eq!(released[0], pkt(2));
        assert_eq!(released[1], pkt(3));
        let m = r.metrics_snapshot();
        assert_eq!(m.gap_timeouts, 1);
        assert_eq!(m.packets_delivered, 2);
        assert_eq!(r.next_expected(), 4);
    }

    #[test]
    fn payload_bytes_are_preserved() {
        let mut r = receiver();
        let payload = vec![0x45, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let delivered = r.push(1, payload.clone());
        assert_eq!(delivered[0], payload);
    }
}
