use crate::lsblk::SelectableDevice;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to serialize config: {0}")]
    SerializeFailed(#[from] toml::ser::Error),
    #[error("Failed to serialize JSON: {0}")]
    JsonSerializeFailed(#[from] serde_json::Error),
    #[error("Failed to write config file: {0}")]
    WriteFailed(#[from] std::io::Error),
    #[error("Failed to read config file: {0}")]
    ReadFailed(std::io::Error),
    #[error("Failed to parse config file: {0}")]
    ParseFailed(#[from] toml::de::Error),
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
}

impl StorageConfig {
    pub fn from_selection(selection: &SelectableDevice) -> Self {
        let device = &selection.device;
        let mountpoint = if device.is_mounted() {
            Some(device.mount_point_str())
        } else {
            None
        };

        Self {
            device: device.device_path(),
            device_type: device.device_type.clone(),
            size: device.size_str(),
            parent: selection.parent.as_ref().map(|p| format!("/dev/{}", p)),
            model: device.model.clone(),
            mountpoint,
            fstype: device.fstype.clone(),
            label: device.label.clone(),
            selected_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn to_json(&self) -> Result<String, ConfigError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), ConfigError> {
        let content = self.to_toml()?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn write_json_to_file(&self, path: &Path) -> Result<(), ConfigError> {
        let content = self.to_json()?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn read_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFailed)?;
        Ok(toml::from_str(&content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsblk::BlockDevice;

    #[test]
    fn test_config_serialization() {
        let device = BlockDevice {
            name: "sda1".to_string(),
            size: Some("100G".to_string()),
            device_type: "part".to_string(),
            mountpoint: None,
            mountpoints: None,
            model: None,
            children: None,
            fstype: Some("ext4".to_string()),
            label: Some("data".to_string()),
        };

        let selection = SelectableDevice {
            device,
            parent: Some("sda".to_string()),
            indent_level: 1,
        };

        let config = StorageConfig::from_selection(&selection);
        assert_eq!(config.device, "/dev/sda1");
        assert_eq!(config.device_type, "part");
        assert_eq!(config.parent, Some("/dev/sda".to_string()));

        let toml_str = config.to_toml().unwrap();
        assert!(toml_str.contains("device = \"/dev/sda1\""));
    }
}
