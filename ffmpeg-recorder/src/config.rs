use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the recorder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecorderConfig {
    /// RTSP URL with embedded credentials
    pub rtsp_url: String,
    /// Directory to store recordings
    pub output_dir: PathBuf,
    /// Duration of each segment in seconds (default: 30)
    #[serde(default = "default_segment_duration")]
    pub segment_duration: u32,
    /// Stop recording when disk usage exceeds this percentage (default: 90)
    #[serde(default = "default_disk_reserve_percent")]
    pub disk_reserve_percent: u8,
    /// File format: "mp4" or "mkv" (default: "mp4")
    #[serde(default = "default_file_format")]
    pub file_format: String,
    /// Optional encryption public key (hex-encoded X25519, 64 chars)
    /// When set, completed segments are encrypted and original deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_pubkey: Option<String>,
}

fn default_segment_duration() -> u32 {
    30
}

fn default_disk_reserve_percent() -> u8 {
    90
}

fn default_file_format() -> String {
    "mp4".to_string()
}

impl RecorderConfig {
    /// Create a new config with defaults
    pub fn new(rtsp_url: String, output_dir: PathBuf) -> Self {
        Self {
            rtsp_url,
            output_dir,
            segment_duration: default_segment_duration(),
            disk_reserve_percent: default_disk_reserve_percent(),
            file_format: default_file_format(),
            encryption_pubkey: None,
        }
    }

    /// Set the encryption public key (builder pattern)
    pub fn with_encryption(mut self, pubkey_hex: String) -> Self {
        self.encryption_pubkey = Some(pubkey_hex);
        self
    }

    /// Check if encryption is enabled
    pub fn encryption_enabled(&self) -> bool {
        self.encryption_pubkey.is_some()
    }

    /// Load config from a TOML file
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save config to a TOML file
    pub fn save(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Build the output pattern for ffmpeg
    pub fn output_pattern(&self) -> String {
        let pattern = self.output_dir.join(format!("%Y-%m-%d_%H-%M-%S.{}", self.file_format));
        pattern.to_string_lossy().to_string()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
}
