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
    pub fn new(config: &AdaptiveConfig, floors: &BitrateFloors) -> Self {
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

        Self {
            steps,
            current_index: 0,
        }
    }

    /// Generate ladder with resolution priority
    ///
    /// For each resolution tier, cycle through all framerates before
    /// moving to the next resolution.
    fn generate_resolution_priority(
        config: &AdaptiveConfig,
        floors: &BitrateFloors,
    ) -> Vec<QualityStep> {
        let mut steps = Vec::new();

        // Filter resolutions between target and minimum
        let target_pixels = config.target_width as i64 * config.target_height as i64;
        let min_pixels = config.min_width as i64 * config.min_height as i64;

        for &(width, height) in RESOLUTIONS {
            let pixels = width as i64 * height as i64;
            if pixels > target_pixels || pixels < min_pixels {
                continue;
            }

            for &fps in FRAMERATES {
                if fps > config.target_framerate {
                    continue;
                }

                let min_bitrate = floors.get(width, height, fps);
                steps.push(QualityStep::new(width, height, fps, min_bitrate));
            }
        }

        steps
    }

    /// Generate ladder with framerate priority
    ///
    /// For each framerate tier, cycle through all resolutions before
    /// moving to the next framerate.
    fn generate_framerate_priority(
        config: &AdaptiveConfig,
        floors: &BitrateFloors,
    ) -> Vec<QualityStep> {
        let mut steps = Vec::new();

        let target_pixels = config.target_width as i64 * config.target_height as i64;
        let min_pixels = config.min_width as i64 * config.min_height as i64;

        for &fps in FRAMERATES {
            if fps > config.target_framerate {
                continue;
            }

            for &(width, height) in RESOLUTIONS {
                let pixels = width as i64 * height as i64;
                if pixels > target_pixels || pixels < min_pixels {
                    continue;
                }

                let min_bitrate = floors.get(width, height, fps);
                steps.push(QualityStep::new(width, height, fps, min_bitrate));
            }
        }

        steps
    }

    /// Generate balanced ladder
    ///
    /// Uses a scoring system to interleave resolution and framerate drops.
    fn generate_balanced(
        config: &AdaptiveConfig,
        floors: &BitrateFloors,
    ) -> Vec<QualityStep> {
        let target_pixels = config.target_width as i64 * config.target_height as i64;
        let min_pixels = config.min_width as i64 * config.min_height as i64;

        // Collect all valid combinations with scores
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

                // Score: higher is better quality
                // Resolution weighted 2x compared to framerate
                let score = (RESOLUTIONS.len() - res_tier) as i32 * 2
                    + (FRAMERATES.len() - fps_tier) as i32;

                let min_bitrate = floors.get(width, height, fps);
                scored_steps.push((score, QualityStep::new(width, height, fps, min_bitrate)));
            }
        }

        // Sort by score descending (highest quality first)
        scored_steps.sort_by(|a, b| b.0.cmp(&a.0));

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
        let ladder = QualityLadder::new(&config, &floors);

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
        let mut ladder = QualityLadder::new(&config, &floors);

        // Should be able to step down from start
        assert!(ladder.can_step_down());
        let before = ladder.current().clone();
        ladder.step_down();
        let after = ladder.current();

        // After stepping down, quality should be lower
        // (either lower resolution or lower framerate)
        assert!(
            after.pixels() < before.pixels()
                || after.framerate < before.framerate
        );

        // Should be able to step back up
        assert!(ladder.can_step_up());
        ladder.step_up();
        assert_eq!(ladder.current(), &before);
    }

    #[test]
    fn test_resolution_priority_order() {
        let mut config = test_config();
        config.priority = AdaptivePriority::Resolution;

        let floors = BitrateFloors::load_embedded();
        let ladder = QualityLadder::new(&config, &floors);

        // In resolution priority, we should see all framerates for
        // 1280x720 before seeing 1024x576
        let steps = ladder.steps();
        let mut seen_720p = false;
        let mut seen_576p_after_720p = false;

        for step in steps {
            if step.width == 1280 && step.height == 720 {
                seen_720p = true;
            }
            if step.width == 1024 && step.height == 576 {
                if seen_720p {
                    seen_576p_after_720p = true;
                }
            }
        }

        assert!(seen_576p_after_720p);
    }

    #[test]
    fn test_framerate_priority_order() {
        let mut config = test_config();
        config.priority = AdaptivePriority::Framerate;

        let floors = BitrateFloors::load_embedded();
        let ladder = QualityLadder::new(&config, &floors);

        // In framerate priority, we should see all resolutions at 30fps
        // before seeing any at 15fps
        let steps = ladder.steps();

        // Find index of first 15fps step
        let first_15fps_idx = steps.iter().position(|s| s.framerate == 15);
        // Find index of last 30fps step
        let last_30fps_idx = steps.iter().rposition(|s| s.framerate == 30);

        // All 30fps should come before any 15fps
        if let (Some(last_30), Some(first_15)) = (last_30fps_idx, first_15fps_idx) {
            assert!(
                last_30 < first_15,
                "Expected all 30fps before 15fps, but last 30fps at {} and first 15fps at {}",
                last_30,
                first_15
            );
        }

        // There should be steps at both framerates
        assert!(steps.iter().any(|s| s.framerate == 30));
        assert!(steps.iter().any(|s| s.framerate == 15));
    }
}
