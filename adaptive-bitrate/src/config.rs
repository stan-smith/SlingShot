//! Configuration types for adaptive bitrate streaming

use serde::{Deserialize, Serialize};

/// Priority mode for quality degradation
///
/// Determines which parameter to preserve when network conditions require
/// stepping down quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AdaptivePriority {
    /// Preserve resolution, drop framerate + bitrate first
    /// Good for: surveillance, detail-critical applications
    Resolution,

    /// Preserve framerate, drop resolution first
    /// Good for: motion tracking, sports, action scenes
    Framerate,

    /// Drop both proportionally (interleaved)
    /// Good for: general purpose, balanced experience
    #[default]
    Balanced,
}

/// Adaptive bitrate configuration
///
/// Stored in RemoteConfig and used to initialize the ABR controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConfig {
    /// Enable adaptive bitrate control
    pub enabled: bool,

    /// Target (maximum) width in pixels
    pub target_width: i32,

    /// Target (maximum) height in pixels
    pub target_height: i32,

    /// Target (maximum) framerate in fps
    pub target_framerate: i32,

    /// Target bitrate in kbps
    pub target_bitrate: u32,

    /// Minimum acceptable width in pixels
    pub min_width: i32,

    /// Minimum acceptable height in pixels
    pub min_height: i32,

    /// Priority mode for quality degradation
    pub priority: AdaptivePriority,

    // --- Advanced thresholds (optional, with sensible defaults) ---
    /// Packet loss % to trigger quality step-down (default: 2.0)
    #[serde(default = "default_loss_threshold")]
    pub loss_threshold: f64,

    /// RTT in milliseconds to trigger quality step-down (default: 200)
    #[serde(default = "default_rtt_threshold")]
    pub rtt_threshold_ms: u64,

    /// Seconds to wait after step-down before attempting recovery (default: 15)
    #[serde(default = "default_recovery_delay")]
    pub recovery_delay_secs: u64,
}

fn default_loss_threshold() -> f64 {
    2.0
}

fn default_rtt_threshold() -> u64 {
    200
}

fn default_recovery_delay() -> u64 {
    5
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_width: 1280,
            target_height: 720,
            target_framerate: 30,
            target_bitrate: 2000,
            min_width: 640,
            min_height: 360,
            priority: AdaptivePriority::Balanced,
            loss_threshold: default_loss_threshold(),
            rtt_threshold_ms: default_rtt_threshold(),
            recovery_delay_secs: default_recovery_delay(),
        }
    }
}

impl AdaptiveConfig {
    /// Create a new adaptive config with specified parameters (uses default thresholds)
    pub fn new(
        target_width: i32,
        target_height: i32,
        target_framerate: i32,
        target_bitrate: u32,
        min_width: i32,
        min_height: i32,
        priority: AdaptivePriority,
    ) -> Self {
        Self {
            enabled: true,
            target_width,
            target_height,
            target_framerate,
            target_bitrate,
            min_width,
            min_height,
            priority,
            loss_threshold: default_loss_threshold(),
            rtt_threshold_ms: default_rtt_threshold(),
            recovery_delay_secs: default_recovery_delay(),
        }
    }
}
