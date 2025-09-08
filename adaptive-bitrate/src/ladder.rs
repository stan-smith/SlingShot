//! Quality ladder generation based on priority mode
//!
//! The quality ladder is an ordered list of quality steps from highest
//! to lowest quality. The order depends on the user's priority preference.

use crate::config::{AdaptiveConfig, AdaptivePriority};
use crate::floors::BitrateFloors;

/// Standard resolutions in descending order
const RESOLUTIONS: &[(i32, i32)] = &[
    (1920, 1080),
    (1280, 720),
    (1024, 576),
    (640, 480),
    (640, 360),
    (426, 240),
    (256, 144),
];

/// Standard framerates in descending order
const FRAMERATES: &[i32] = &[30, 15, 10, 5, 1];

/// A single quality step in the ladder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityStep {
    /// Width in pixels
    pub width: i32,
    /// Height in pixels
    pub height: i32,
    /// Framerate in fps
    pub framerate: i32,
    /// Minimum viable bitrate in kbps (from floor data)
    pub min_bitrate: u32,
}

impl QualityStep {
    /// Create a new quality step
    pub fn new(width: i32, height: i32, framerate: i32, min_bitrate: u32) -> Self {
        Self {
            width,
            height,
            framerate,
            min_bitrate,
        }
    }

    /// Get the pixel count for this step
    pub fn pixels(&self) -> i64 {
        self.width as i64 * self.height as i64
    }
}

/// Quality ladder - ordered list of quality steps
#[derive(Debug, Clone)]
pub struct QualityLadder {
    steps: Vec<QualityStep>,
    current_index: usize,
}

impl QualityLadder {
    /// Create a new quality ladder from config
    ///
    /// The ladder is generated based on the priority mode:
    /// - Resolution: Keep resolution, vary framerate first
    /// - Framerate: Keep framerate, vary resolution first
    /// - Balanced: Interleave resolution and framerate changes
    ///
    /// Returns None if no valid quality steps could be generated from the config.
    pub fn new(config: &AdaptiveConfig, floors: &BitrateFloors) -> Option<Self> {
        let steps = match config.priority {
            AdaptivePriority::Resolution => {
                Self::generate_resolution_priority(config, floors)
            }
            AdaptivePriority::Framerate => {
                Self::generate_framerate_priority(config, floors)
            }
            AdaptivePriority::Balanced => {
                Self::generate_balanced(config, floors)
            }
        };

        if steps.is_empty() {
            return None;
        }

        Some(Self {
            steps,
            current_index: 0,
        })
    }

    /// Generate ladder with resolution priority
    ///
    /// Sorted by bitrate descending. At equal bitrates, prefers higher resolution
    /// (keeps resolution, drops framerate first).
    fn generate_resolution_priority(
        config: &AdaptiveConfig,
        floors: &BitrateFloors,
    ) -> Vec<QualityStep> {
        let target_pixels = config.target_width as i64 * config.target_height as i64;
        let min_pixels = config.min_width as i64 * config.min_height as i64;

        // Collect all valid combinations with resolution tier for tiebreaker
        let mut scored_steps: Vec<(usize, QualityStep)> = Vec::new();

        for (res_tier, &(width, height)) in RESOLUTIONS.iter().enumerate() {
            let pixels = width as i64 * height as i64;
            if pixels > target_pixels || pixels < min_pixels {
                continue;
            }

            for &fps in FRAMERATES {
                if fps > config.target_framerate {
                    continue;
                }

                let min_bitrate = floors.get(width, height, fps);
                scored_steps.push((res_tier, QualityStep::new(width, height, fps, min_bitrate)));
            }
        }

        // Sort by bitrate descending (primary), then by resolution tier ascending (tiebreaker)
        // Lower res_tier = higher resolution = preferred at equal bitrate
        scored_steps.sort_by(|a, b| {
            match b.1.min_bitrate.cmp(&a.1.min_bitrate) {
                std::cmp::Ordering::Equal => a.0.cmp(&b.0), // Lower tier (higher res) wins
                other => other,
            }
        });

        scored_steps.into_iter().map(|(_, step)| step).collect()
    }

    /// Generate ladder with framerate priority
    ///
    /// Sorted by bitrate descending. At equal bitrates, prefers higher framerate
    /// (keeps framerate, drops resolution first).
    fn generate_framerate_priority(
        config: &AdaptiveConfig,
        floors: &BitrateFloors,
    ) -> Vec<QualityStep> {
        let target_pixels = config.target_width as i64 * config.target_height as i64;
        let min_pixels = config.min_width as i64 * config.min_height as i64;

        // Collect all valid combinations with framerate tier for tiebreaker
        let mut scored_steps: Vec<(usize, QualityStep)> = Vec::new();

        for (fps_tier, &fps) in FRAMERATES.iter().enumerate() {
            if fps > config.target_framerate {
                continue;
            }

            for &(width, height) in RESOLUTIONS {
                let pixels = width as i64 * height as i64;
                if pixels > target_pixels || pixels < min_pixels {
                    continue;
                }

                let min_bitrate = floors.get(width, height, fps);
                scored_steps.push((fps_tier, QualityStep::new(width, height, fps, min_bitrate)));
            }
        }

        // Sort by bitrate descending (primary), then by framerate tier ascending (tiebreaker)
        // Lower fps_tier = higher framerate = preferred at equal bitrate
        scored_steps.sort_by(|a, b| {
            match b.1.min_bitrate.cmp(&a.1.min_bitrate) {
                std::cmp::Ordering::Equal => a.0.cmp(&b.0), // Lower tier (higher fps) wins
                other => other,
            }
        });

        scored_steps.into_iter().map(|(_, step)| step).collect()
    }

    /// Generate balanced ladder
    ///
    /// Sorted by bitrate floor descending to ensure stepping down always reduces
    /// bandwidth. Quality score (resolution weighted 2x vs framerate) is used as
    /// a tiebreaker when bitrates are equal.
    fn generate_balanced(
        config: &AdaptiveConfig,
        floors: &BitrateFloors,
    ) -> Vec<QualityStep> {
        let target_pixels = config.target_width as i64 * config.target_height as i64;
        let min_pixels = config.min_width as i64 * config.min_height as i64;

        // Collect all valid combinations with quality scores
        let mut scored_steps: Vec<(i32, QualityStep)> = Vec::new();

        for (res_tier, &(width, height)) in RESOLUTIONS.iter().enumerate() {
            let pixels = width as i64 * height as i64;
            if pixels > target_pixels || pixels < min_pixels {
                continue;
            }

            for (fps_tier, &fps) in FRAMERATES.iter().enumerate() {
                if fps > config.target_framerate {
                    continue;
                }

                // Quality score: higher is better (used as tiebreaker)
                // Resolution weighted 2x compared to framerate
                let score = (RESOLUTIONS.len() - res_tier) as i32 * 2
                    + (FRAMERATES.len() - fps_tier) as i32;

                let min_bitrate = floors.get(width, height, fps);
                scored_steps.push((score, QualityStep::new(width, height, fps, min_bitrate)));
            }
        }

        // Sort by bitrate descending (primary), then by quality score descending (tiebreaker)
        // This ensures stepping down ALWAYS reduces bitrate
        scored_steps.sort_by(|a, b| {
            match b.1.min_bitrate.cmp(&a.1.min_bitrate) {
                std::cmp::Ordering::Equal => b.0.cmp(&a.0), // Higher quality score wins ties
                other => other,
            }
        });

        scored_steps.into_iter().map(|(_, step)| step).collect()
    }

    /// Get the current quality step
    pub fn current(&self) -> &QualityStep {
        &self.steps[self.current_index]
    }

    /// Check if we can step down to lower quality
    pub fn can_step_down(&self) -> bool {
        self.current_index < self.steps.len() - 1
    }

    /// Check if we can step up to higher quality
    pub fn can_step_up(&self) -> bool {
        self.current_index > 0
    }

    /// Step down to lower quality, returns the new step
    pub fn step_down(&mut self) -> Option<&QualityStep> {
        if self.can_step_down() {
            self.current_index += 1;
            Some(self.current())
        } else {
            None
        }
    }

    /// Step up to higher quality, returns the new step
    pub fn step_up(&mut self) -> Option<&QualityStep> {
        if self.can_step_up() {
            self.current_index -= 1;
            Some(self.current())
        } else {
            None
        }
    }

    /// Reset to the highest quality (first step)
    pub fn reset(&mut self) {
        self.current_index = 0;
    }

    /// Get the number of steps in the ladder
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Check if the ladder is empty
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Get the current position in the ladder (0 = highest quality)
    pub fn position(&self) -> usize {
        self.current_index
    }

    /// Get all steps (for debugging/display)
    pub fn steps(&self) -> &[QualityStep] {
        &self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_ladder_generation() {
        let config = test_config();
        let floors = BitrateFloors::load_embedded();
        let ladder = QualityLadder::new(&config, &floors).expect("ladder should be created");

        assert!(!ladder.is_empty());
        // First step should be target resolution
        let first = ladder.current();
        assert_eq!(first.width, 1280);
        assert_eq!(first.height, 720);
        assert_eq!(first.framerate, 30);
    }

    #[test]
    fn test_step_down_up() {
        let config = test_config();
        let floors = BitrateFloors::load_embedded();
        let mut ladder = QualityLadder::new(&config, &floors).expect("ladder should be created");

        // Should be able to step down from start
        assert!(ladder.can_step_down());
        let before = ladder.current().clone();
        ladder.step_down();
        let after = ladder.current();

        // After stepping down, bitrate should be lower or equal
        assert!(
            after.min_bitrate <= before.min_bitrate,
            "Step down should not increase bitrate: {} -> {}",
            before.min_bitrate,
            after.min_bitrate
        );

        // Should be able to step back up
        assert!(ladder.can_step_up());
        ladder.step_up();
        assert_eq!(ladder.current(), &before);
    }

    #[test]
    fn test_bitrate_monotonically_decreasing() {
        // Test all priority modes ensure bitrate never increases when stepping down
        for priority in [
            AdaptivePriority::Balanced,
            AdaptivePriority::Resolution,
            AdaptivePriority::Framerate,
        ] {
            let mut config = test_config();
            config.priority = priority;

            let floors = BitrateFloors::load_embedded();
            let ladder = QualityLadder::new(&config, &floors).expect("ladder should be created");

            let steps = ladder.steps();
            for i in 1..steps.len() {
                assert!(
                    steps[i].min_bitrate <= steps[i - 1].min_bitrate,
                    "{:?}: Step {} ({:?}) has higher bitrate ({}) than step {} ({:?}, {})",
                    priority,
                    i,
                    steps[i],
                    steps[i].min_bitrate,
                    i - 1,
                    steps[i - 1],
                    steps[i - 1].min_bitrate
                );
            }
        }
    }

    #[test]
    fn test_resolution_priority_tiebreaker() {
        let mut config = test_config();
        config.priority = AdaptivePriority::Resolution;

        let floors = BitrateFloors::load_embedded();
        let ladder = QualityLadder::new(&config, &floors).expect("ladder should be created");

        // At equal bitrates, higher resolution should come first
        let steps = ladder.steps();
        for i in 1..steps.len() {
            if steps[i].min_bitrate == steps[i - 1].min_bitrate {
                // Equal bitrate - higher resolution should be earlier
                assert!(
                    steps[i].pixels() <= steps[i - 1].pixels(),
                    "At equal bitrate, higher resolution should come first"
                );
            }
        }
    }

    #[test]
    fn test_framerate_priority_tiebreaker() {
        let mut config = test_config();
        config.priority = AdaptivePriority::Framerate;

        let floors = BitrateFloors::load_embedded();
        let ladder = QualityLadder::new(&config, &floors).expect("ladder should be created");

        // At equal bitrates, higher framerate should come first
        let steps = ladder.steps();
        for i in 1..steps.len() {
            if steps[i].min_bitrate == steps[i - 1].min_bitrate {
                // Equal bitrate - higher framerate should be earlier
                assert!(
                    steps[i].framerate <= steps[i - 1].framerate,
                    "At equal bitrate, higher framerate should come first"
                );
            }
        }
    }
}
