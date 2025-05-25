//! FFmpeg-based RTSP recorder library
//!
//! Records RTSP streams from ONVIF cameras to disk using ffmpeg.
//! Designed to run independently of any GStreamer pipeline.
//!
//! # Features
//! - Records original quality video without re-encoding (`-c copy`)
//! - Splits recordings into configurable time-based segments
//! - Timestamp-based file naming (e.g., `2024-12-01_15-30-00.mp4`)
//! - Auto-restart on ffmpeg crash with exponential backoff
//! - Disk space monitoring with configurable reserve threshold
//! - Optional encryption of completed segments (X25519 + AES-256-GCM)
//!
//! # Example
//! ```ignore
//! use ffmpeg_recorder::{RecorderConfig, Recorder, has_disk_space};
//! use std::path::PathBuf;
//!
//! let config = RecorderConfig::new(
//!     "rtsp://user:pass@camera/stream".to_string(),
//!     PathBuf::from("/media/recordings"),
//! );
//!
//! let mut recorder = Recorder::new(config);
//! recorder.start()?;
//!
//! // Periodically check health
//! loop {
//!     recorder.check_and_restart()?;
//!     if !has_disk_space(&recorder.config().output_dir, recorder.config().disk_reserve_percent) {
//!         recorder.stop()?;
//!         break;
//!     }
//!     std::thread::sleep(std::time::Duration::from_secs(5));
//! }
//! ```

pub mod cleanup;
pub mod config;
pub mod encryptor;
pub mod recorder;

pub use cleanup::{
    delete_oldest_recording, disk_usage_summary, ensure_disk_space, format_bytes,
    get_available_bytes, get_disk_usage, get_total_bytes, has_disk_space, DiskError,
};
pub use config::{ConfigError, RecorderConfig};
pub use encryptor::{EncryptorError, SegmentEncryptor, ENCRYPTED_EXT};
pub use recorder::{Recorder, RecorderError};

/// Check if ffmpeg is available on the system
pub fn ffmpeg_available() -> bool {
    std::process::Command::new("ffmpeg")
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get ffmpeg version string
pub fn ffmpeg_version() -> Option<String> {
    let output = std::process::Command::new("ffmpeg")
        .arg("-version")
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next().map(|s| s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffmpeg_check() {
        // Just check it doesn't panic
        let _ = ffmpeg_available();
    }
}
