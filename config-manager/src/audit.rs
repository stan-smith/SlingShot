use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::paths;

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// How many days to retain audit logs (default: 30)
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
        }
    }
}

impl AuditConfig {
    /// Get default config path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        Ok(paths::config_dir()?.join("audit.toml"))
    }

    /// Check if config exists at default location
    pub fn exists() -> bool {
        Self::default_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Load config from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
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

    /// Load config or return defaults if not found
    pub fn load_or_default() -> Self {
        Self::load().unwrap_or_default()
    }

    /// Save config to default XDG location
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = Self::default_path()?;
        self.save_to(&path)
    }

    /// Save config to specific path.
    /// Uses restrictive file permissions (0600 on Unix).
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        paths::ensure_config_dir()?;
        let content = toml::to_string_pretty(self)?;
        paths::write_secure(path, &content)?;
        Ok(())
    }
}
