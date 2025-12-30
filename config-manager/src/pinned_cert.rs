//! Pinned certificate configuration for remote node
//!
//! Stores the fingerprint of central's TLS certificate for TOFU pinning.
//! On first connection, the fingerprint is saved. On subsequent connections,
//! the certificate is validated against this pinned fingerprint.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::paths;

/// Pinned certificate configuration storing central's cert fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedCertConfig {
    /// SHA-256 fingerprint of central's TLS certificate (format: "SHA256:hexstring")
    fingerprint: String,
}

impl PinnedCertConfig {
    /// Create new pinned cert config with fingerprint
    pub fn new(fingerprint: String) -> Self {
        Self { fingerprint }
    }

    /// Get the pinned fingerprint
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Check if pinned cert file exists
    pub fn exists() -> bool {
        pinned_cert_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Get default pinned cert file path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        pinned_cert_path()
    }

    /// Load pinned cert from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let path = pinned_cert_path()?;
        Self::load_from(&path)
    }

    /// Load pinned cert from specific path
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.display().to_string()));
        }
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save pinned cert to default XDG location
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = pinned_cert_path()?;
        self.save_to(&path)
    }

    /// Save pinned cert to specific path
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        paths::ensure_config_dir()?;
        let content = toml::to_string_pretty(self)?;
        paths::write_secure(path, &content)?;
        Ok(())
    }

    /// Delete pinned cert file (for certificate rotation)
    pub fn delete() -> Result<(), ConfigError> {
        let path = pinned_cert_path()?;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

/// Get pinned cert file path: ~/.config/slingshot/pinned-cert.toml
fn pinned_cert_path() -> Result<PathBuf, ConfigError> {
    Ok(paths::config_dir()?.join("pinned-cert.toml"))
}
