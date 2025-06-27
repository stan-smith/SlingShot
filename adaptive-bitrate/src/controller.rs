//! Adaptive bitrate controller state machine
//!
//! Monitors QUIC QoS metrics and decides when to step up/down quality.

use std::time::{Duration, Instant};

use crate::config::AdaptiveConfig;
use crate::floors::BitrateFloors;
use crate::ladder::{QualityLadder, QualityStep};

/// Default thresholds for adaptation
#[derive(Debug, Clone)]
pub struct Thresholds {
    /// Packet loss % to trigger step down (default: 2.0%)
    pub loss_step_down: f64,
    /// Packet loss % ceiling for step up consideration (default: 0.5%)
    pub loss_step_up: f64,
    /// RTT in milliseconds to trigger step down (default: 200ms)
    pub rtt_threshold_ms: u64,
    /// Number of consecutive stable samples needed to step up (default: 3)
    pub stable_samples_for_up: u32,
    /// Minimum time between any quality changes (default: 5s)
    pub cooldown: Duration,
    /// Minimum time before trying to step up after stepping down (default: 15s)
    pub recovery_delay: Duration,
    /// EMA alpha for metrics smoothing (default: 0.5)
    pub ema_alpha: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            loss_step_down: 2.0,
            loss_step_up: 0.5,
            rtt_threshold_ms: 200,
            stable_samples_for_up: 1,
            cooldown: Duration::from_secs(5),
            recovery_delay: Duration::from_secs(5),
            ema_alpha: 0.5,
        }
    }
}

/// Controller state
#[derive(Debug, Clone)]
pub enum ControllerState {
    /// Normal operation, monitoring metrics
    Stable,
    /// Recently made a change, waiting before next action
    Cooldown { until: Instant },
    /// Waiting minimum time after step-down before attempting recovery
    RecoveryWait { step_down_at: Instant },
}

/// Quality change action
#[derive(Debug, Clone)]
pub enum QualityChange {
    /// Step down to lower quality
    StepDown(QualityStep),
    /// Step up to higher quality
    StepUp(QualityStep),
}

/// Smoothed metrics using exponential moving average
#[derive(Debug, Clone)]
struct SmoothedMetrics {
    loss_ema: f64,
    rtt_ema: f64,
    alpha: f64,
    baseline_rtt: Option<f64>,
    samples_for_baseline: u32,
}

impl SmoothedMetrics {
    fn new(alpha: f64) -> Self {
        Self {
            loss_ema: 0.0,
            rtt_ema: 0.0,
            alpha,
            baseline_rtt: None,
            samples_for_baseline: 0,
        }
    }

    fn update(&mut self, loss: f64, rtt: f64) {
        self.loss_ema = self.alpha * loss + (1.0 - self.alpha) * self.loss_ema;
        self.rtt_ema = self.alpha * rtt + (1.0 - self.alpha) * self.rtt_ema;

        // Capture baseline RTT from first 10 stable samples
        if self.baseline_rtt.is_none() {
            self.samples_for_baseline += 1;
            if self.samples_for_baseline >= 10 {
                self.baseline_rtt = Some(self.rtt_ema);
            }
        }
    }

    fn reset_baseline(&mut self) {
        self.baseline_rtt = None;
        self.samples_for_baseline = 0;
    }
}

/// Adaptive bitrate controller
///
/// Monitors metrics and decides when to adjust quality.
#[derive(Debug)]
pub struct AdaptiveController {
    ladder: QualityLadder,
    thresholds: Thresholds,
    state: ControllerState,
    metrics: SmoothedMetrics,
    stable_count: u32,
    last_step_down: Option<Instant>,
    consecutive_step_downs: u32,
    current_recovery_delay: Duration,
    current_bitrate: u32,
}

impl AdaptiveController {
    /// Create a new adaptive controller
    ///
    /// Returns None if no valid quality ladder could be generated from the config.
    pub fn new(config: &AdaptiveConfig) -> Option<Self> {
        let floors = BitrateFloors::load_embedded();
        let ladder = QualityLadder::new(config, &floors)?;

        // Use thresholds from config (with sensible defaults)
        let thresholds = Thresholds {
            loss_step_down: config.loss_threshold,
            loss_step_up: config.loss_threshold / 4.0, // Recovery at 1/4 of step-down threshold
            rtt_threshold_ms: config.rtt_threshold_ms,
            stable_samples_for_up: 1, // Fast recovery - single good sample
            cooldown: Duration::from_secs(5),
            recovery_delay: Duration::from_secs(config.recovery_delay_secs),
            ema_alpha: 0.5, // Faster response than 0.3
        };

        let initial_bitrate = config.target_bitrate;
        let recovery_delay = thresholds.recovery_delay;

        Some(Self {
            ladder,
            metrics: SmoothedMetrics::new(thresholds.ema_alpha),
            thresholds,
            state: ControllerState::Stable,
            stable_count: 0,
            last_step_down: None,
            consecutive_step_downs: 0,
            current_recovery_delay: recovery_delay,
            current_bitrate: initial_bitrate,
        })
    }

    /// Create a new adaptive controller with custom thresholds
    ///
    /// Returns None if no valid quality ladder could be generated from the config.
    pub fn with_thresholds(config: &AdaptiveConfig, thresholds: Thresholds) -> Option<Self> {
        let floors = BitrateFloors::load_embedded();
        let ladder = QualityLadder::new(config, &floors)?;
        let initial_bitrate = config.target_bitrate;
        let recovery_delay = thresholds.recovery_delay;

        Some(Self {
            ladder,
            metrics: SmoothedMetrics::new(thresholds.ema_alpha),
            thresholds,
            state: ControllerState::Stable,
            stable_count: 0,
            last_step_down: None,
            consecutive_step_downs: 0,
            current_recovery_delay: recovery_delay,
            current_bitrate: initial_bitrate,
        })
    }

    /// Process new metrics and return any quality change action
    ///
    /// Call this periodically (e.g., every 1 second) with current metrics.
    pub fn process(&mut self, loss_percent: f64, rtt_ms: u64) -> Option<QualityChange> {
        let now = Instant::now();
        let rtt = rtt_ms as f64;

        // Update smoothed metrics
        self.metrics.update(loss_percent, rtt);

        // Check state
        match &self.state {
            ControllerState::Cooldown { until } => {
                if now >= *until {
                    // Cooldown expired, check if we should enter recovery wait
                    if self.last_step_down.is_some() {
                        self.state = ControllerState::RecoveryWait {
                            step_down_at: self.last_step_down.unwrap(),
                        };
                    } else {
                        self.state = ControllerState::Stable;
                    }
                }
                return None;
            }
            ControllerState::RecoveryWait { step_down_at } => {
                // Check if enough time has passed since step down
                if now.duration_since(*step_down_at) < self.current_recovery_delay {
                    // Still waiting, but check for congestion
                    if self.is_congested() {
                        return self.try_step_down(now);
                    }
                    return None;
                }
                // Recovery delay passed, move to stable
                self.state = ControllerState::Stable;
            }
            ControllerState::Stable => {
                // Normal processing continues below
            }
        }

        // Check for congestion - step down if needed
        if self.is_congested() {
            return self.try_step_down(now);
        }

        // Check for recovery opportunity
        if self.metrics.loss_ema < self.thresholds.loss_step_up {
            self.stable_count += 1;
            if self.stable_count >= self.thresholds.stable_samples_for_up {
                return self.try_step_up(now);
            }
        } else {
            self.stable_count = 0;
        }

        None
    }

    /// Check if current metrics indicate congestion
    fn is_congested(&self) -> bool {
        // Primary signal: packet loss above threshold
        if self.metrics.loss_ema > self.thresholds.loss_step_down {
            return true;
        }

        // Secondary signal: RTT above absolute threshold (only if also some loss)
        // RTT spikes without loss are normal network jitter, not congestion
        let rtt_high = self.metrics.rtt_ema > self.thresholds.rtt_threshold_ms as f64;
        let has_some_loss = self.metrics.loss_ema > 0.1; // At least 0.1% loss
        if rtt_high && has_some_loss {
            return true;
        }

        false
    }

    /// Try to step down quality
    fn try_step_down(&mut self, now: Instant) -> Option<QualityChange> {
        if !self.ladder.can_step_down() {
            // Already at minimum quality
            return None;
        }

        // Check for rapid repeated step-downs
        if let Some(last) = self.last_step_down {
            if now.duration_since(last) < Duration::from_secs(60) {
                self.consecutive_step_downs += 1;
                // Exponential backoff on recovery delay
                self.current_recovery_delay = Duration::from_secs(
                    (30 * 2u64.pow(self.consecutive_step_downs.min(2))).min(120),
                );
            } else {
                self.consecutive_step_downs = 0;
                self.current_recovery_delay = self.thresholds.recovery_delay;
            }
        }

        self.last_step_down = Some(now);
        self.stable_count = 0;

        let new_step = self.ladder.step_down()?.clone();
        self.current_bitrate = new_step.min_bitrate;

        self.state = ControllerState::Cooldown {
            until: now + self.thresholds.cooldown,
        };

        Some(QualityChange::StepDown(new_step))
    }

    /// Try to step up quality
    fn try_step_up(&mut self, now: Instant) -> Option<QualityChange> {
        if !self.ladder.can_step_up() {
            // Already at maximum quality
            return None;
        }

        self.stable_count = 0;
        self.consecutive_step_downs = 0;
        self.current_recovery_delay = self.thresholds.recovery_delay;

        let new_step = self.ladder.step_up()?.clone();
        self.current_bitrate = new_step.min_bitrate;

        self.state = ControllerState::Cooldown {
            until: now + self.thresholds.cooldown,
        };

        // Reset last_step_down since we're recovering
        self.last_step_down = None;

        Some(QualityChange::StepUp(new_step))
    }

    /// Reset the controller to initial state
    ///
    /// Call this on reconnection to start fresh.
    pub fn reset(&mut self) {
        self.ladder.reset();
        self.state = ControllerState::Stable;
        self.stable_count = 0;
        self.last_step_down = None;
        self.consecutive_step_downs = 0;
        self.current_recovery_delay = self.thresholds.recovery_delay;
        self.metrics.reset_baseline();
    }

    /// Get the current quality step
    pub fn current_step(&self) -> &QualityStep {
        self.ladder.current()
    }

    /// Get the current controller state
    pub fn state(&self) -> &ControllerState {
        &self.state
    }

    /// Get the current recommended bitrate
    pub fn current_bitrate(&self) -> u32 {
        self.current_bitrate
    }

    /// Get the current position in the quality ladder (0 = highest)
    pub fn ladder_position(&self) -> usize {
        self.ladder.position()
    }

    /// Get the total number of steps in the ladder
    pub fn ladder_size(&self) -> usize {
        self.ladder.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdaptivePriority;

    fn test_config() -> AdaptiveConfig {
        AdaptiveConfig {
            enabled: true,
            target_width: 1280,
            target_height: 720,
            target_framerate: 30,
            target_bitrate: 2000,
            min_width: 640,
            min_height: 360,
            priority: AdaptivePriority::Balanced,
            loss_threshold: 2.0,
            rtt_threshold_ms: 200,
            recovery_delay_secs: 5,
        }
    }

    fn fast_thresholds() -> Thresholds {
        Thresholds {
            loss_step_down: 2.0,
            loss_step_up: 0.5,
            rtt_threshold_ms: 200,
            stable_samples_for_up: 2,
            cooldown: Duration::from_millis(1),
            recovery_delay: Duration::from_millis(1),
            ema_alpha: 0.9, // High alpha = fast response for testing
        }
    }

    #[test]
    fn test_step_down_on_loss() {
        let config = test_config();
        let mut controller = AdaptiveController::with_thresholds(&config, fast_thresholds())
            .expect("controller should be created");

        // Simulate high packet loss - keep calling until we get a step down
        let mut result = None;
        for _ in 0..20 {
            result = controller.process(5.0, 50);
            if result.is_some() {
                break;
            }
        }

        // Should trigger step down
        assert!(
            matches!(result, Some(QualityChange::StepDown(_))),
            "Expected step down, got {:?}. Ladder size: {}, position: {}",
            result,
            controller.ladder_size(),
            controller.ladder_position()
        );
    }

    #[test]
    fn test_cooldown_prevents_rapid_changes() {
        let config = test_config();
        let mut controller = AdaptiveController::with_thresholds(&config, fast_thresholds())
            .expect("controller should be created");

        // Simulate high loss until we get a step down
        let mut result1 = None;
        for _ in 0..20 {
            result1 = controller.process(5.0, 50);
            if result1.is_some() {
                break;
            }
        }
        assert!(
            matches!(result1, Some(QualityChange::StepDown(_))),
            "Expected step down, got {:?}",
            result1
        );

        // Immediately after, should be in cooldown
        let result2 = controller.process(5.0, 50);
        assert!(result2.is_none(), "Expected None during cooldown");
    }

    #[test]
    fn test_step_up_after_recovery() {
        let config = test_config();
        let mut controller = AdaptiveController::with_thresholds(&config, fast_thresholds())
            .expect("controller should be created");

        // Step down first
        let mut step_down = None;
        for _ in 0..20 {
            step_down = controller.process(5.0, 50);
            if step_down.is_some() {
                break;
            }
        }
        assert!(
            matches!(step_down, Some(QualityChange::StepDown(_))),
            "Expected initial step down"
        );

        // Wait for cooldown and recovery delay
        std::thread::sleep(Duration::from_millis(10));

        // Now simulate stable conditions - with high alpha, EMA converges quickly to low loss
        for _ in 0..20 {
            let result = controller.process(0.1, 30);
            if matches!(result, Some(QualityChange::StepUp(_))) {
                return; // Test passed
            }
        }

        // Should have stepped up by now
        panic!(
            "Expected step up after stable conditions. State: {:?}, Position: {}",
            controller.state(),
            controller.ladder_position()
        );
    }
}
