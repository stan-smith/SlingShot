use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadFailed(#[from] std::io::Error),
    #[error("Failed to parse config file: {0}")]
    ParseFailed(#[from] toml::de::Error),
    #[error("Failed to write config file: {0}")]
    WriteFailed(toml::ser::Error),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageConfig {
    pub device: String,
    pub device_type: String,
    pub size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mountpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fstype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub selected_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount: Option<MountInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MountInfo {
    pub mountpoint: String,
    pub uuid: String,
    pub mounted_at: String,
    pub in_fstab: bool,
}

impl StorageConfig {
    pub fn read_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self).map_err(ConfigError::WriteFailed)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn device_name(&self) -> &str {
        self.device.strip_prefix("/dev/").unwrap_or(&self.device)
    }
}
