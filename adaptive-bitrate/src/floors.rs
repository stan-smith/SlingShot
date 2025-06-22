//! Bitrate floor data for various resolution/framerate combinations
//!
//! These values represent the minimum viable bitrate for acceptable quality
//! at each resolution/framerate combination, determined through empirical testing.

use std::collections::HashMap;

/// Bitrate floors for resolution/framerate combinations
///
/// Maps (width, height, fps) to minimum viable bitrate in kbps.
#[derive(Debug, Clone)]
pub struct BitrateFloors {
    floors: HashMap<(i32, i32, i32), u32>,
}

impl BitrateFloors {
    /// Load embedded bitrate floor data from measurements
    pub fn load_embedded() -> Self {
        let mut floors = HashMap::new();

        // 1920x1080 (Full HD)
        floors.insert((1920, 1080, 30), 800);
        floors.insert((1920, 1080, 15), 550);
        floors.insert((1920, 1080, 10), 450);
        floors.insert((1920, 1080, 5), 250);
        floors.insert((1920, 1080, 1), 200);

        // 1280x720 (HD)
        floors.insert((1280, 720, 30), 500);
        floors.insert((1280, 720, 15), 300);
        floors.insert((1280, 720, 10), 225);
        floors.insert((1280, 720, 5), 150);
        floors.insert((1280, 720, 1), 100);

        // 1024x576 (Wide SD)
        floors.insert((1024, 576, 30), 350);
        floors.insert((1024, 576, 15), 200);
        floors.insert((1024, 576, 10), 150);
        floors.insert((1024, 576, 5), 100);
        floors.insert((1024, 576, 1), 100);

        // 640x480 (SD 4:3)
        floors.insert((640, 480, 30), 200);
        floors.insert((640, 480, 15), 150);
        floors.insert((640, 480, 10), 75);
        floors.insert((640, 480, 5), 75);
        floors.insert((640, 480, 1), 75);

        // 640x360 (SD 16:9)
        floors.insert((640, 360, 30), 150);
        floors.insert((640, 360, 15), 100);
        floors.insert((640, 360, 10), 80);
        floors.insert((640, 360, 5), 50);
        floors.insert((640, 360, 1), 50);

        // 426x240 (Low)
        floors.insert((426, 240, 30), 90);
        floors.insert((426, 240, 15), 55);
        floors.insert((426, 240, 10), 60);
        floors.insert((426, 240, 5), 35);
        floors.insert((426, 240, 1), 30);

        // 256x144 (Very Low)
        floors.insert((256, 144, 30), 40);
        floors.insert((256, 144, 15), 35);
        floors.insert((256, 144, 10), 30);
        floors.insert((256, 144, 5), 25);
        floors.insert((256, 144, 1), 25);

        // 80x80 (Thumbnail)
        floors.insert((80, 80, 30), 15);
        floors.insert((80, 80, 15), 15);
        floors.insert((80, 80, 10), 15);
        floors.insert((80, 80, 5), 15);
        floors.insert((80, 80, 1), 10);

        Self { floors }
    }

    /// Get the minimum bitrate for a given resolution and framerate
    ///
    /// Returns exact match if available, otherwise interpolates based on pixel count.
    pub fn get(&self, width: i32, height: i32, fps: i32) -> u32 {
        // Try exact match first
        if let Some(&floor) = self.floors.get(&(width, height, fps)) {
            return floor;
        }

        // Interpolate based on pixel count and framerate
        let pixels = (width * height) as f64;
        let base = (pixels / 1000.0) * (fps as f64 / 30.0) * 0.3;
        base.max(50.0) as u32
    }

    /// Get the maximum sensible bitrate for a resolution/framerate
    ///
    /// This is a rough upper bound - encoding above this wastes bandwidth.
    pub fn max_sensible(&self, width: i32, height: i32, fps: i32) -> u32 {
        let pixels = (width * height) as f64;
        let fps_factor = fps as f64 / 30.0;

        // Rough formula: 8 bits per pixel * fps factor, in kbps
        let max = (pixels * 8.0 * fps_factor / 1000.0) as u32;
        max.min(20000) // Cap at 20 Mbps
    }
}

impl Default for BitrateFloors {
    fn default() -> Self {
        Self::load_embedded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_lookup() {
        let floors = BitrateFloors::load_embedded();
        assert_eq!(floors.get(1920, 1080, 30), 800);
        assert_eq!(floors.get(1280, 720, 15), 300);
        assert_eq!(floors.get(640, 360, 10), 80);
    }

    #[test]
    fn test_interpolation() {
        let floors = BitrateFloors::load_embedded();
        // Non-standard resolution should interpolate
        let result = floors.get(1600, 900, 25);
        assert!(result >= 50); // Should be at least minimum
    }
}
