use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::paths;
use crate::source::SourceConfig;
use crate::storage::StorageConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CentralConfig {
    /// Network interfaces to bind services to (e.g., ["127.0.0.1", "192.168.1.100"])
    pub bind_interfaces: Vec<String>,
    /// Admin web interface port (default: 8081)
    pub admin_port: u16,
    /// QUIC server port (default: 5001)
    pub quic_port: u16,
    /// ONVIF server port (default: 8080)
    pub onvif_port: u16,
    /// RTSP server port (default: 8554)
    pub rtsp_port: u16,
}

impl Default for CentralConfig {
    fn default() -> Self {
        Self {
            bind_interfaces: vec!["0.0.0.0".to_string()],
            admin_port: 8081,
            quic_port: 5001,
            onvif_port: 8080,
            rtsp_port: 8554,
        }
    }
}

impl CentralConfig {
    /// Check if config exists at default location
    pub fn exists() -> bool {
        paths::central_config_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Get default config path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        paths::central_config_path()
    }

    /// Load config from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let path = paths::central_config_path()?;
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
        let path = paths::central_config_path()?;
        self.save_to(&path)
    }

    /// Save config to specific path
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        paths::ensure_config_dir()?;
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get socket addresses for a given port across all configured interfaces
    pub fn bind_addrs(&self, port: u16) -> Vec<String> {
        self.bind_interfaces
            .iter()
            .map(|iface| format!("{}:{}", iface, port))
            .collect()
    }

    /// Get admin web bind addresses
    pub fn admin_addrs(&self) -> Vec<String> {
        self.bind_addrs(self.admin_port)
    }

    /// Get QUIC server bind addresses
    pub fn quic_addrs(&self) -> Vec<String> {
        self.bind_addrs(self.quic_port)
    }

    /// Get ONVIF server bind addresses
    pub fn onvif_addrs(&self) -> Vec<String> {
        self.bind_addrs(self.onvif_port)
    }

    /// Get RTSP server bind addresses
    pub fn rtsp_addrs(&self) -> Vec<String> {
        self.bind_addrs(self.rtsp_port)
    }
}

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
    /// Enable encryption for recordings (requires key from central)
    #[serde(default)]
    pub encryption_enabled: bool,
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
