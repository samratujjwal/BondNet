//! Day 16: deterministic throughput benchmark harness.
//!
//! Measures the real MultipathDataPlane (scheduler plus sequence allocation
//! plus packet encoding plus UDP send) against a local loopback receiver,
//! and the real OrderedReceiver with controlled input patterns.
//!
//! This is a LOCAL benchmark: packets go through real UDP sockets on
//! 127.0.0.1, not across physical networks or the Internet. It measures
//! processing and loopback throughput, NOT Internet bonding performance.
//!
//! All scenarios are deterministic: no randomness, no timing-dependent
//! assertions. Throughput numbers vary by machine; correctness assertions
//! do not.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::{MAX_WINTUN_PACKET_LEN, MultipathDataPlane, PathManager, PhysicalPathConfig};
use bondnet_core::ordered::OrderedReceiver;
use bondnet_protocol::HEADER_LEN;

/// Benchmark configuration, validated before running.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Number of packets per repetition.
    pub packets: u64,
    /// Inner payload size in bytes (must be 1..=MAX_WINTUN_PACKET_LEN).
    pub payload_size: usize,
    /// Number of repetitions for aggregate stats.
    pub repetitions: u32,
    /// Path weights (e.g., [1] for single, [1, 1] for dual-equal,
    /// [3, 1] for 3:1). Length determines path count.
    pub weights: Vec<u64>,
}

impl BenchConfig {
    /// Validate the configuration. Returns an error string if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.packets == 0 {
            return Err("packets must be > 0".to_string());
        }
        if self.packets > 10_000_000 {
            return Err("packets must be <= 10_000_000".to_string());
        }
        if self.payload_size == 0 || self.payload_size > MAX_WINTUN_PACKET_LEN {
            return Err(format!("payload_size must be 1..={MAX_WINTUN_PACKET_LEN}"));
        }
        if self.repetitions == 0 || self.repetitions > 100 {
            return Err("repetitions must be 1..=100".to_string());
        }
        if self.weights.is_empty() || self.weights.len() > 8 {
            return Err("weights must have 1..=8 entries".to_string());
        }
        for (i, w) in self.weights.iter().enumerate() {
            if *w == 0 {
                return Err(format!("weight[{i}] must be > 0"));
            }
            if *w > 1_000_000_000 {
                return Err(format!("weight[{i}] must be <= 1_000_000_000"));
            }
        }
        // Check for overflow in total bytes: packets * (payload + header)
        let per_packet = self.payload_size as u64 + HEADER_LEN as u64;
        self.packets
            .checked_mul(per_packet)
            .ok_or_else(|| "packet count * size overflows u64".to_string())?;
        Ok(())
    }

    /// Total payload bytes offered per repetition.
    pub fn payload_bytes_per_rep(&self) -> u64 {
        self.packets * self.payload_size as u64
    }

    /// Total wire bytes (payload + 36-byte header) per repetition.
    pub fn wire_bytes_per_rep(&self) -> u64 {
        self.packets * (self.payload_size as u64 + HEADER_LEN as u64)
    }
}

/// Per-repetition measurement.
#[derive(Debug, Clone)]
pub struct BenchRun {
    /// Packets successfully sent (encode + UDP send succeeded).
    pub packets_sent: u64,
    /// Packets that failed to send.
    pub send_errors: u64,
    /// Per-path packet counts (index = path position in weights).
    pub per_path_packets: Vec<u64>,
    /// Elapsed wall-clock time for the send loop.
    pub elapsed: Duration,
    /// Payload bytes offered.
    pub payload_bytes: u64,
    /// Wire bytes (payload + headers) for sent packets.
    pub wire_bytes: u64,
}

impl BenchRun {
    /// Offered payload throughput in Mbps (megabits per second).
    pub fn payload_mbps(&self) -> f64 {
        let bits = self.payload_bytes as f64 * 8.0;
        bits / self.elapsed.as_secs_f64() / 1_000_000.0
    }

    /// Wire throughput in Mbps.
    pub fn wire_mbps(&self) -> f64 {
        let bits = self.wire_bytes as f64 * 8.0;
        bits / self.elapsed.as_secs_f64() / 1_000_000.0
    }

    /// Payload throughput in MiB/s.
    pub fn payload_mib_per_sec(&self) -> f64 {
        self.payload_bytes as f64 / self.elapsed.as_secs_f64() / (1024.0 * 1024.0)
    }
}

/// Aggregate across repetitions.
#[derive(Debug)]
pub struct BenchSummary {
    pub runs: Vec<BenchRun>,
    pub config: BenchConfig,
}

impl BenchSummary {
    fn sorted_mbps(&self) -> Vec<f64> {
        let mut v: Vec<f64> = self.runs.iter().map(|r| r.payload_mbps()).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    }

    pub fn median_mbps(&self) -> f64 {
        let v = self.sorted_mbps();
        let n = v.len();
        if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        }
    }

    pub fn min_mbps(&self) -> f64 {
        self.sorted_mbps().into_iter().next().unwrap_or(0.0)
    }

    pub fn max_mbps(&self) -> f64 {
        self.sorted_mbps().into_iter().last().unwrap_or(0.0)
    }

    pub fn total_packets_sent(&self) -> u64 {
        self.runs.iter().map(|r| r.packets_sent).sum()
    }

    pub fn total_send_errors(&self) -> u64 {
        self.runs.iter().map(|r| r.send_errors).sum()
    }
}

/// Build a test payload: deterministic bytes, valid IPv4 header.
fn make_payload(size: usize, seed: u8) -> Vec<u8> {
    let mut p = vec![0u8; size];
    // Minimal IPv4 header so the payload is realistic.
    if size >= 20 {
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    }
    // Fill the rest deterministically.
    for (i, b) in p.iter_mut().enumerate().skip(20) {
        *b = (i as u8).wrapping_mul(7).wrapping_add(seed);
    }
    p
}

/// Set up N paths with the given weights, each connected to a local
/// receiver. Returns (manager, receivers).
async fn setup_paths(
    weights: &[u64],
    session_id: u64,
) -> (Arc<Mutex<PathManager>>, Vec<UdpSocket>) {
    let mut configs = Vec::new();
    let mut receivers = Vec::new();
    for (i, weight) in weights.iter().enumerate() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        receivers.push(rx);
        configs.push(PhysicalPathConfig {
            name: format!("bench-path-{}", i + 1),
            path_id: (i + 1) as u16,
            local_addr: "127.0.0.1:0".parse().unwrap(),
            remote_addr: rx_addr,
            enabled: true,
            bandwidth_bps: weight * 1_000_000,
        });
    }
    let mut manager = PathManager::new(configs).unwrap();
    manager.initialize(session_id).await;
    (Arc::new(Mutex::new(manager)), receivers)
}

/// Drain receivers in the background so sends don't block.
fn spawn_drainers(receivers: Vec<UdpSocket>) -> Vec<tokio::task::JoinHandle<u64>> {
    receivers
        .into_iter()
        .map(|rx| {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                let mut count = 0u64;
                while let Ok(Ok(_)) =
                    tokio::time::timeout(Duration::from_millis(100), rx.recv(&mut buf)).await
                {
                    count += 1;
                }
                count
            })
        })
        .collect()
}

/// Run one benchmark repetition.
pub async fn run_once(config: &BenchConfig, session_id: u64) -> BenchRun {
    let (manager, receivers) = setup_paths(&config.weights, session_id).await;
    let drainers = spawn_drainers(receivers);
    let plane = MultipathDataPlane::with_defaults(Arc::clone(&manager), session_id);

    let payload = make_payload(config.payload_size, 0x42);
    let mut per_path_packets = vec![0u64; config.weights.len()];
    let mut packets_sent = 0u64;
    let mut send_errors = 0u64;

    let start = Instant::now();
    for _ in 0..config.packets {
        match plane.send_wintun_packet(&payload).await {
            Ok((path_id, _)) => {
                packets_sent += 1;
                let idx = (path_id - 1) as usize;
                if idx < per_path_packets.len() {
                    per_path_packets[idx] += 1;
                }
            }
            Err(_) => {
                send_errors += 1;
            }
        }
    }
    let elapsed = start.elapsed();

    // Let drainers finish.
    tokio::time::sleep(Duration::from_millis(200)).await;
    for d in drainers {
        let _ = d.await;
    }

    let payload_bytes = packets_sent * config.payload_size as u64;
    let wire_bytes = packets_sent * (config.payload_size as u64 + HEADER_LEN as u64);

    BenchRun {
        packets_sent,
        send_errors,
        per_path_packets,
        elapsed,
        payload_bytes,
        wire_bytes,
    }
}

/// Run the full benchmark with repetitions.
pub async fn run(config: &BenchConfig) -> Result<BenchSummary, String> {
    config.validate()?;
    let mut runs = Vec::new();
    for rep in 0..config.repetitions {
        // Different session per repetition to avoid sequence overlap.
        let session_id = 9000 + rep as u64;
        runs.push(run_once(config, session_id).await);
    }
    Ok(BenchSummary {
        runs,
        config: config.clone(),
    })
}

/// Ordering benchmark: feed packets in a controlled pattern through
/// OrderedReceiver and measure processing time.
pub struct OrderingBench {
    pub pattern: &'static str,
    pub packets: u64,
    pub delivered: u64,
    pub gaps: u64,
    pub timeouts: u64,
    pub duplicates_dropped: u64,
    pub elapsed: Duration,
}

/// Run an ordering benchmark with the given input sequence pattern.
pub fn bench_ordering(pattern: &'static str, sequences: &[u64]) -> OrderingBench {
    let mut receiver = OrderedReceiver::new(1, 256, Duration::from_millis(200));
    let start = Instant::now();
    let mut delivered = 0u64;
    for &seq in sequences {
        let payload = vec![seq as u8; 64];
        delivered += receiver.push(seq, payload).len() as u64;
    }
    // Drain any remaining via timeout (for gap patterns).
    std::thread::sleep(Duration::from_millis(250));
    delivered += receiver.check_timeout().len() as u64;
    let elapsed = start.elapsed();
    let m = receiver.metrics_snapshot();
    OrderingBench {
        pattern,
        packets: sequences.len() as u64,
        delivered,
        gaps: m.gaps_observed,
        timeouts: m.gap_timeouts,
        duplicates_dropped: m.duplicates_dropped,
        elapsed,
    }
}

/// Print a human-readable benchmark report.
pub fn print_report(summary: &BenchSummary) {
    let cfg = &summary.config;
    println!("=== BondNet Day 16 Benchmark ===");
    println!(
        "Mode: {} path(s), weights {:?}",
        cfg.weights.len(),
        cfg.weights
    );
    println!(
        "Packets: {} x {}B payload, {} repetition(s)",
        cfg.packets, cfg.payload_size, cfg.repetitions
    );
    println!();
    println!("Per-run results:");
    for (i, run) in summary.runs.iter().enumerate() {
        println!(
            "  Run {}: {:.2} Mbps payload ({:.2} MiB/s), {:.2} Mbps wire, {} sent, {} errors, {:?} per-path",
            i + 1,
            run.payload_mbps(),
            run.payload_mib_per_sec(),
            run.wire_mbps(),
            run.packets_sent,
            run.send_errors,
            run.per_path_packets,
        );
    }
    println!();
    println!("Aggregate (payload throughput):");
    println!("  Median: {:.2} Mbps", summary.median_mbps());
    println!("  Min:    {:.2} Mbps", summary.min_mbps());
    println!("  Max:    {:.2} Mbps", summary.max_mbps());
    println!("  Total sent: {} packets", summary.total_packets_sent());
    println!("  Total errors: {}", summary.total_send_errors());
    println!();
    println!("NOTE: Local loopback benchmark. Not Internet throughput.");
}

/// Parse CLI args for the bench subcommand.
pub fn parse_bench_args(args: &[String]) -> Result<BenchConfig, String> {
    let mut packets: u64 = 10_000;
    let mut payload_size: usize = 1200;
    let mut repetitions: u32 = 3;
    let mut weights: Vec<u64> = vec![1, 1];

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--packets" => {
                i += 1;
                packets = args
                    .get(i)
                    .ok_or("--packets requires a value")?
                    .parse()
                    .map_err(|_| "--packets must be a number")?;
            }
            "--payload-size" => {
                i += 1;
                payload_size = args
                    .get(i)
                    .ok_or("--payload-size requires a value")?
                    .parse()
                    .map_err(|_| "--payload-size must be a number")?;
            }
            "--repetitions" => {
                i += 1;
                repetitions = args
                    .get(i)
                    .ok_or("--repetitions requires a value")?
                    .parse()
                    .map_err(|_| "--repetitions must be a number")?;
            }
            "--weights" => {
                i += 1;
                let s = args.get(i).ok_or("--weights requires a value")?;
                weights = s
                    .split(',')
                    .map(|p| {
                        p.parse()
                            .map_err(|_| "--weights must be comma-separated numbers")
                    })
                    .collect::<Result<Vec<u64>, _>>()?;
            }
            "--mode" => {
                i += 1;
                let mode = args.get(i).ok_or("--mode requires a value")?;
                weights = match mode.as_str() {
                    "single" => vec![1],
                    "dual-equal" => vec![1, 1],
                    "dual-3to1" => vec![3, 1],
                    _ => return Err("--mode must be single, dual-equal, or dual-3to1".to_string()),
                };
            }
            _ => return Err(format!("unknown bench arg: {}", args[i])),
        }
        i += 1;
    }

    let config = BenchConfig {
        packets,
        payload_size,
        repetitions,
        weights,
    };
    config.validate()?;
    Ok(config)
}

/// Run the bench subcommand.
pub async fn run_bench(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_bench_args(args).map_err(|e| format!("bench: {e}"))?;
    println!("Running benchmark: {config:?}");
    let summary = run(&config).await.map_err(|e| format!("bench: {e}"))?;
    print_report(&summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_zero_packets() {
        let c = BenchConfig {
            packets: 0,
            payload_size: 100,
            repetitions: 1,
            weights: vec![1],
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_oversized_payload() {
        let c = BenchConfig {
            packets: 100,
            payload_size: MAX_WINTUN_PACKET_LEN + 1,
            repetitions: 1,
            weights: vec![1],
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_weight() {
        let c = BenchConfig {
            packets: 100,
            payload_size: 100,
            repetitions: 1,
            weights: vec![1, 0],
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_empty_weights() {
        let c = BenchConfig {
            packets: 100,
            payload_size: 100,
            repetitions: 1,
            weights: vec![],
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_accepts_valid() {
        let c = BenchConfig {
            packets: 1000,
            payload_size: 1200,
            repetitions: 3,
            weights: vec![3, 1],
        };
        assert!(c.validate().is_ok());
        assert_eq!(c.wire_bytes_per_rep(), 1000 * (1200 + 36));
    }

    #[test]
    fn ordering_in_order_delivers_all() {
        let seqs: Vec<u64> = (1..=100).collect();
        let b = bench_ordering("in-order", &seqs);
        assert_eq!(b.delivered, 100);
        assert_eq!(b.gaps, 0);
    }

    #[test]
    fn ordering_out_of_order_recovers() {
        // 1,3,2,5,4,... pattern
        let mut seqs = Vec::new();
        for i in (1..=100).step_by(2) {
            seqs.push(i);
            if i < 100 {
                seqs.push(i + 1);
            }
        }
        // Swap pairs to create out-of-order
        let mut ooo = Vec::new();
        for chunk in seqs.chunks(2) {
            if chunk.len() == 2 {
                ooo.push(chunk[1]);
                ooo.push(chunk[0]);
            } else {
                ooo.push(chunk[0]);
            }
        }
        let b = bench_ordering("out-of-order", &ooo);
        assert_eq!(b.delivered, 100);
    }

    #[test]
    fn ordering_duplicate_dropped() {
        // True duplicates: buffer seq 3 (gap at 1,2), then send 3 again.
        let seqs = vec![3, 3, 1, 2];
        let b = bench_ordering("duplicates", &seqs);
        // 1,2,3 delivered (3 once); one duplicate dropped.
        assert_eq!(b.delivered, 3);
        assert_eq!(b.duplicates_dropped, 1);
    }

    #[test]
    fn ordering_gap_timeout_recovers() {
        // Skip seq 5; timeout should skip it and deliver 6,7
        let seqs = vec![1, 2, 3, 4, 6, 7];
        let b = bench_ordering("gap", &seqs);
        // 1-4 delivered immediately, 6,7 buffered, timeout releases them
        assert_eq!(b.delivered, 6);
        assert_eq!(b.timeouts, 1);
    }
}
