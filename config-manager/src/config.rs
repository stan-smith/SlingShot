use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::paths;
use crate::source::SourceConfig;
use crate::storage::StorageConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingConfig {
    pub enabled: bool,
    pub disk_reserve_percent: u8,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            disk_reserve_percent: 90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub node_name: String,
    pub central_address: String,
    pub source: SourceConfig,
    pub recording: RecordingConfig,
    pub storage: StorageConfig,
}

impl RemoteConfig {
    /// Check if config exists at default location
    pub fn exists() -> bool {
        paths::remote_config_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Get default config path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        paths::remote_config_path()
    }

    /// Load config from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let path = paths::remote_config_path()?;
        Self::load_from(&path)
    }

    /// Load config from specific path
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.display().to_string()));
        }
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save config to default XDG location
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = paths::remote_config_path()?;
        self.save_to(&path)
    }

    /// Save config to specific path
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        paths::ensure_config_dir()?;
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
