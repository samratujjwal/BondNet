use bondnet_core::reorder::{GapInfo, PushResult, ReorderBuffer};

fn buf(start: u64, capacity: usize) -> ReorderBuffer<String> {
    ReorderBuffer::new(start, capacity)
}

fn pkt(label: &str) -> String {
    label.to_string()
}

/// 1. Immediate delivery: expected packet releases at once and the frontier advances.
#[test]
fn immediate_delivery_advances_frontier() {
    let mut rb = buf(10, 16);
    match rb.push(10, pkt("A")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("A")]),
        other => panic!("expected Released, got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 11);
    assert_eq!(rb.len(), 0);
}

/// 2. Basic out-of-order: 10, 12, 11 delivers 10, 11, 12 in order.
#[test]
fn basic_out_of_order_reorders() {
    let mut rb = buf(10, 16);
    assert_eq!(rb.push(12, pkt("C")), PushResult::Buffered);
    match rb.push(10, pkt("A")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("A")]),
        other => panic!("expected Released(A), got {other:?}"),
    }
    match rb.push(11, pkt("B")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("B"), pkt("C")]),
        other => panic!("expected Released(B, C), got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 13);
    assert!(rb.is_empty());
}

/// 3. Multiple buffered packets collapse in one release, in order.
#[test]
fn multiple_buffered_release_in_order() {
    let mut rb = buf(10, 16);
    for (seq, label) in [(15, "F"), (14, "E"), (13, "D"), (12, "C"), (11, "B")] {
        assert_eq!(rb.push(seq, pkt(label)), PushResult::Buffered);
    }
    match rb.push(10, pkt("A")) {
        PushResult::Released(v) => assert_eq!(
            v,
            vec!["A", "B", "C", "D", "E", "F"]
                .into_iter()
                .map(pkt)
                .collect::<Vec<_>>()
        ),
        other => panic!("expected full ordered release, got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 16);
}

/// 4. A duplicate of an already-delivered sequence is never delivered twice.
///
/// Delivered sequences sit below the delivery frontier, so they classify
/// as TooOld — an explicit status, never a second delivery.
#[test]
fn duplicate_delivered_packet_not_redelivered() {
    let mut rb = buf(10, 16);
    assert!(matches!(rb.push(10, pkt("A")), PushResult::Released(_)));
    match rb.push(10, pkt("A2")) {
        PushResult::TooOld(returned) => assert_eq!(returned, pkt("A2")),
        other => panic!("expected TooOld (already delivered), got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 11);
}

/// 5. A duplicate of a buffered sequence does not replace the original.
#[test]
fn duplicate_buffered_packet_keeps_original() {
    let mut rb = buf(10, 16);
    assert_eq!(rb.push(12, pkt("C-original")), PushResult::Buffered);
    match rb.push(12, pkt("C-impostor")) {
        PushResult::Duplicate(returned) => assert_eq!(returned, pkt("C-impostor")),
        other => panic!("expected Duplicate, got {other:?}"),
    }
    // When the gap closes, the ORIGINAL value is the one delivered.
    assert!(matches!(rb.push(10, pkt("A")), PushResult::Released(_)));
    match rb.push(11, pkt("B")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("B"), pkt("C-original")]),
        other => panic!("expected original buffered value, got {other:?}"),
    }
}

/// 6. Late packets (below the frontier) are rejected and never move it backwards.
#[test]
fn late_packet_is_too_old() {
    let mut rb = buf(20, 16);
    match rb.push(19, pkt("old")) {
        PushResult::TooOld(returned) => assert_eq!(returned, pkt("old")),
        other => panic!("expected TooOld, got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 20);
    // Even after delivering 20..22, an old straggler stays too old.
    assert!(matches!(rb.push(20, pkt("T")), PushResult::Released(_)));
    assert!(matches!(rb.push(21, pkt("U")), PushResult::Released(_)));
    assert!(matches!(rb.push(22, pkt("V")), PushResult::Released(_)));
    assert_eq!(rb.next_expected(), 23);
    assert!(matches!(
        rb.push(19, pkt("old-again")),
        PushResult::TooOld(_)
    ));
}

/// 7. A full buffer rejects further out-of-order packets without panicking.
#[test]
fn buffer_limit_rejects_overflow() {
    let mut rb = buf(10, 2);
    assert_eq!(rb.push(11, pkt("B")), PushResult::Buffered);
    assert_eq!(rb.push(12, pkt("C")), PushResult::Buffered);
    match rb.push(13, pkt("D")) {
        PushResult::BufferFull(returned) => assert_eq!(returned, pkt("D")),
        other => panic!("expected BufferFull, got {other:?}"),
    }
    assert_eq!(rb.len(), 2);
    assert_eq!(rb.next_expected(), 10);
    // Closing the gap drains 10, 11, 12: the buffer empties and capacity
    // is usable again for fresh out-of-order packets.
    match rb.push(10, pkt("A")) {
        PushResult::Released(v) => assert_eq!(
            v,
            vec!["A", "B", "C"].into_iter().map(pkt).collect::<Vec<_>>()
        ),
        other => panic!("expected A,B,C drained in order, got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 13);
    assert!(rb.is_empty());
    assert_eq!(rb.push(15, pkt("F")), PushResult::Buffered);
    assert_eq!(rb.push(16, pkt("G")), PushResult::Buffered);
    assert!(matches!(rb.push(17, pkt("H")), PushResult::BufferFull(_)));
}

/// 8. Capacity N accepts exactly N buffered packets, then refuses the N+1th.
#[test]
fn exact_capacity_accepts_n_then_refuses() {
    const N: usize = 4;
    let mut rb = buf(100, N);
    for i in 0..N {
        assert_eq!(
            rb.push(102 + i as u64, pkt(&format!("P{i}"))),
            PushResult::Buffered,
            "packet {i} should fit"
        );
    }
    assert_eq!(rb.len(), N);
    assert!(matches!(
        rb.push(102 + N as u64, pkt("extra")),
        PushResult::BufferFull(_)
    ));
}

/// 9. A fresh buffer is empty and reports no gap.
#[test]
fn empty_buffer_has_no_gap() {
    let rb = buf(10, 16);
    assert_eq!(rb.len(), 0);
    assert!(rb.is_empty());
    assert_eq!(rb.gap(), None);
}

/// 10. Gap reporting exposes expected / first buffered / distance.
#[test]
fn gap_reporting_matches_buffer_state() {
    let mut rb = buf(10, 16);
    assert_eq!(rb.push(12, pkt("C")), PushResult::Buffered);
    assert_eq!(rb.push(13, pkt("D")), PushResult::Buffered);
    assert_eq!(rb.push(14, pkt("E")), PushResult::Buffered);
    assert_eq!(
        rb.gap(),
        Some(GapInfo {
            expected: 10,
            first_buffered: 12,
            distance: 2,
            buffered: 3,
        })
    );
    assert!(!rb.is_empty());
}

/// 11. Closing the gap releases everything buffered, in order.
#[test]
fn gap_closes_releases_buffered_in_order() {
    let mut rb = buf(10, 16);
    for (seq, label) in [(12, "C"), (13, "D"), (14, "E")] {
        assert_eq!(rb.push(seq, pkt(label)), PushResult::Buffered);
    }
    assert!(matches!(rb.push(10, pkt("A")), PushResult::Released(_)));
    match rb.push(11, pkt("B")) {
        PushResult::Released(v) => assert_eq!(
            v,
            vec!["B", "C", "D", "E"]
                .into_iter()
                .map(pkt)
                .collect::<Vec<_>>()
        ),
        other => panic!("expected B..E in order, got {other:?}"),
    }
    assert_eq!(rb.gap(), None);
    assert_eq!(rb.next_expected(), 15);
}

/// 12. A missing sequence is never auto-skipped: 10, 12, 13 leaves 12, 13 buffered.
#[test]
fn missing_sequence_is_not_auto_skipped() {
    let mut rb = buf(10, 16);
    assert!(matches!(rb.push(10, pkt("A")), PushResult::Released(_)));
    assert_eq!(rb.push(12, pkt("C")), PushResult::Buffered);
    assert_eq!(rb.push(13, pkt("D")), PushResult::Buffered);
    // Frontier must NOT jump over 11 just because 12/13 arrived.
    assert_eq!(rb.next_expected(), 11);
    assert_eq!(rb.len(), 2);
    assert_eq!(
        rb.gap(),
        Some(GapInfo {
            expected: 11,
            first_buffered: 12,
            distance: 1,
            buffered: 2,
        })
    );
}

/// 13. Path-independent: the buffer only sees (sequence, value); values from
///
/// any path behave identically. No PathId logic exists in this module.
#[test]
fn behavior_is_path_independent() {
    let mut a = buf(50, 8);
    let mut b = buf(50, 8);
    // Same arrival pattern, "from different paths", must give identical results.
    for rb in [&mut a, &mut b] {
        assert_eq!(rb.push(52, pkt("from-path-X")), PushResult::Buffered);
        assert!(matches!(
            rb.push(50, pkt("from-path-Y")),
            PushResult::Released(_)
        ));
    }
    assert_eq!(a.next_expected(), b.next_expected());
    assert_eq!(a.gap(), b.gap());
    match (a.push(51, pkt("late")), b.push(51, pkt("late"))) {
        (PushResult::Released(x), PushResult::Released(y)) => assert_eq!(x, y),
        other => panic!("identical behavior expected, got {other:?}"),
    }
}

/// 14. u64 boundary: MAX-1 and MAX deliver without panic or wrap; the space
///
/// then exhausts explicitly and later pushes are Duplicate/TooOld, never wrapped.
#[test]
fn u64_boundary_has_no_wrap_and_no_panic() {
    let mut rb = buf(u64::MAX - 1, 16);
    match rb.push(u64::MAX - 1, pkt("penultimate")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("penultimate")]),
        other => panic!("expected Released, got {other:?}"),
    }
    assert_eq!(rb.next_expected(), u64::MAX);
    match rb.push(u64::MAX, pkt("terminal")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("terminal")]),
        other => panic!("expected Released(terminal), got {other:?}"),
    }
    // No wrap to zero: the terminal sequence is a duplicate now, and
    // anything below the frontier is too old.
    assert!(matches!(
        rb.push(u64::MAX, pkt("terminal-dup")),
        PushResult::Duplicate(_)
    ));
    assert!(matches!(
        rb.push(u64::MAX - 1, pkt("straggler")),
        PushResult::TooOld(_)
    ));
    assert!(matches!(rb.push(0, pkt("wrapped")), PushResult::TooOld(_)));
    assert_eq!(rb.next_expected(), u64::MAX);
}

/// 15. Zero capacity: the expected packet still delivers; nothing can be buffered.
#[test]
fn zero_capacity_still_delivers_expected_packet() {
    let mut rb = buf(10, 0);
    assert_eq!(rb.max_buffered(), 0);
    // Out-of-order packets cannot be buffered at all.
    assert!(matches!(rb.push(11, pkt("B")), PushResult::BufferFull(_)));
    // But the expected packet is always deliverable.
    match rb.push(10, pkt("A")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("A")]),
        other => panic!("expected Released(A), got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 11);
    assert!(matches!(rb.push(12, pkt("C")), PushResult::BufferFull(_)));
}

/// 16. Large sequence values behave identically to small ones. The u64::MAX
///
/// neighborhood itself is covered by u64_boundary_has_no_wrap_and_no_panic;
/// here the starts stay clear of the terminal so plain arithmetic is safe.
#[test]
fn large_sequence_values_behave() {
    for start in [1_000_000_000u64, 4_000_000_000, u64::MAX - 5] {
        let mut rb = buf(start, 8);
        assert_eq!(rb.push(start + 2, pkt("C")), PushResult::Buffered);
        assert!(matches!(rb.push(start, pkt("A")), PushResult::Released(_)));
        match rb.push(start + 1, pkt("B")) {
            PushResult::Released(v) => assert_eq!(v, vec![pkt("B"), pkt("C")]),
            other => panic!("start={start}: expected B,C in order, got {other:?}"),
        }
        assert_eq!(rb.next_expected(), start + 3);
    }
}

/// Main acceptance scenario: 105,103,101,104,102,100 with expected=100
/// delivers 100..=105 in order, only after 100 arrives.
#[test]
fn acceptance_scenario_releases_only_after_gap_closes() {
    let mut rb = buf(100, 16);
    let mut released: Vec<String> = Vec::new();
    for seq in [105u64, 103, 101, 104, 102] {
        match rb.push(seq, pkt(&format!("P{seq}"))) {
            PushResult::Buffered => {}
            other => panic!("seq {seq}: expected Buffered, got {other:?}"),
        }
        assert!(
            released.is_empty(),
            "nothing may release before 100 arrives"
        );
    }
    match rb.push(100, pkt("P100")) {
        PushResult::Released(v) => released = v,
        other => panic!("expected full release, got {other:?}"),
    }
    let expected: Vec<String> = (100u64..=105).map(|s| format!("P{s}")).collect();
    assert_eq!(released, expected);
    assert_eq!(rb.next_expected(), 106);
    assert!(rb.is_empty());
}

/// Interleaved in-order traffic keeps flowing while a separate gap waits.
#[test]
fn in_order_traffic_flows_around_an_unrelated_gap() {
    let mut rb = buf(10, 16);
    // Gap forms at 12 while 10, 11 flow through.
    assert_eq!(rb.push(14, pkt("E")), PushResult::Buffered);
    assert!(matches!(rb.push(10, pkt("A")), PushResult::Released(_)));
    assert!(matches!(rb.push(11, pkt("B")), PushResult::Released(_)));
    // 12 and 13 arrive in order, each releasing immediately.
    match rb.push(12, pkt("C")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("C")]),
        other => panic!("expected Released(C), got {other:?}"),
    }
    match rb.push(13, pkt("D")) {
        // 13 was expected and 14 was already buffered: both release.
        PushResult::Released(v) => assert_eq!(v, vec![pkt("D"), pkt("E")]),
        other => panic!("expected Released(D, E), got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 15);
    assert!(rb.is_empty());
}

/// Duplicate arrives while its original is mid-release chain: still one delivery.
#[test]
fn duplicate_of_in_flight_chain_is_rejected() {
    let mut rb = buf(10, 16);
    assert_eq!(rb.push(11, pkt("B")), PushResult::Buffered);
    // 11 is already buffered; the duplicate is rejected even though 11 is next.
    match rb.push(11, pkt("B-dup")) {
        PushResult::Duplicate(returned) => assert_eq!(returned, pkt("B-dup")),
        other => panic!("expected Duplicate, got {other:?}"),
    }
    match rb.push(10, pkt("A")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("A"), pkt("B")]),
        other => panic!("expected A,B once each, got {other:?}"),
    }
}

/// A buffer of capacity 1 still closes single-packet gaps.
#[test]
fn capacity_one_closes_single_gaps() {
    let mut rb = buf(7, 1);
    assert_eq!(rb.push(8, pkt("B")), PushResult::Buffered);
    assert!(matches!(rb.push(9, pkt("C")), PushResult::BufferFull(_)));
    match rb.push(7, pkt("A")) {
        PushResult::Released(v) => assert_eq!(v, vec![pkt("A"), pkt("B")]),
        other => panic!("expected A,B in order, got {other:?}"),
    }
    assert_eq!(rb.next_expected(), 9);
}
