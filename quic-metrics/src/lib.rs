//! QUIC connection metrics and statistics
//!
//! Provides utilities for monitoring QUIC connection health and performance.

use std::sync::Mutex;
use std::time::Instant;

/// State for tracking interval-based metrics
struct MetricsState {
    last_time: Instant,
    last_tx_bytes: u64,
    last_rx_bytes: u64,
}

static METRICS_STATE: Mutex<Option<MetricsState>> = Mutex::new(None);

/// Log QUIC connection statistics to stdout
///
/// Outputs RTT, congestion window, packet loss, and bytes sent/received with interval rate.
/// Format: `[QUIC:node_name] rtt=12ms cwnd=14720 loss=0.0% tx=23.1KB (+1.2MB/s) rx=45.2KB`
pub fn log_stats(conn: &quinn::Connection, node_name: &str) {
    let stats = conn.stats();
    let loss_pct = if stats.path.sent_packets > 0 {
        (stats.path.lost_packets as f64 / stats.path.sent_packets as f64) * 100.0
    } else {
        0.0
    };

    let now = Instant::now();
    let current_tx = stats.udp_tx.bytes;
    let current_rx = stats.udp_rx.bytes;

    // Calculate interval rate
    let mut state = METRICS_STATE.lock().unwrap();
    let tx_rate = if let Some(ref prev) = *state {
        let elapsed = now.duration_since(prev.last_time).as_secs_f64();
        if elapsed > 0.0 {
            let tx_delta = current_tx.saturating_sub(prev.last_tx_bytes);
            Some(tx_delta as f64 / elapsed)
        } else {
            None
        }
    } else {
        None
    };

    // Update state
    *state = Some(MetricsState {
        last_time: now,
        last_tx_bytes: current_tx,
        last_rx_bytes: current_rx,
    });
    drop(state);

    let tx = format_bytes(current_tx);
    let rx = format_bytes(current_rx);
    let rate_str = tx_rate.map(|r| format!(" (+{})", format_rate(r))).unwrap_or_default();

    println!(
        "[QUIC:{}] rtt={}ms cwnd={} loss={:.1}% ({}/{} pkts) tx={}{} rx={}",
        node_name,
        stats.path.rtt.as_millis(),
        stats.path.cwnd,
        loss_pct,
        stats.path.lost_packets,
        stats.path.sent_packets,
        tx,
        rate_str,
        rx
    );
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1}MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1}KB", bytes as f64 / 1_000.0)
    } else {
        format!("{}B", bytes)
    }
}

fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_000_000.0 {
        format!("{:.2}MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.1}KB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.0}B/s", bytes_per_sec)
    }
}
