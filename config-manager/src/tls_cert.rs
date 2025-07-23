//! TLS certificate configuration for central node
//!
//! Stores Ed25519 TLS certificate and private key as PEM files.
//! Certificate is persistent across restarts for stable fingerprinting.

use std::path::{Path, PathBuf};

use crate::error::ConfigError;
use crate::paths;

/// TLS certificate configuration storing cert and key as PEM strings
#[derive(Debug, Clone)]
pub struct TlsCertConfig {
    cert_pem: String,
    key_pem: String,
}

impl TlsCertConfig {
    /// Create new config from PEM strings
    pub fn new(cert_pem: String, key_pem: String) -> Self {
        Self { cert_pem, key_pem }
    }

    /// Get certificate PEM
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Get private key PEM
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Check if certificate files exist
    pub fn exists() -> bool {
        cert_path().map(|p| p.exists()).unwrap_or(false)
            && key_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Get certificate file path
    pub fn cert_path() -> Result<PathBuf, ConfigError> {
        cert_path()
    }

    /// Get key file path
    pub fn key_path() -> Result<PathBuf, ConfigError> {
        key_path()
    }

    /// Load certificate from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let cert_path = cert_path()?;
        let key_path = key_path()?;
        Self::load_from(&cert_path, &key_path)
    }

    /// Load certificate from specific paths
    pub fn load_from(cert_path: &Path, key_path: &Path) -> Result<Self, ConfigError> {
        if !cert_path.exists() {
            return Err(ConfigError::NotFound(cert_path.display().to_string()));
        }
        if !key_path.exists() {
            return Err(ConfigError::NotFound(key_path.display().to_string()));
        }
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        Ok(Self { cert_pem, key_pem })
    }

    /// Save certificate to default XDG location
    pub fn save(&self) -> Result<(), ConfigError> {
        let cert_path = cert_path()?;
        let key_path = key_path()?;
        self.save_to(&cert_path, &key_path)
    }

    /// Save certificate to specific paths with secure permissions (0600)
    pub fn save_to(&self, cert_path: &Path, key_path: &Path) -> Result<(), ConfigError> {
        paths::ensure_config_dir()?;
        paths::write_secure(cert_path, &self.cert_pem)?;
        paths::write_secure(key_path, &self.key_pem)?;
        Ok(())
    }

    /// Delete certificate files
    pub fn delete() -> Result<(), ConfigError> {
        let cert = cert_path()?;
        let key = key_path()?;
        if cert.exists() {
            std::fs::remove_file(&cert)?;
        }
        if key.exists() {
            std::fs::remove_file(&key)?;
        }
        Ok(())
    }
}

/// Get certificate file path: ~/.config/kaiju/tls-cert.pem
fn cert_path() -> Result<PathBuf, ConfigError> {
    Ok(paths::config_dir()?.join("tls-cert.pem"))
}

/// Get key file path: ~/.config/kaiju/tls-key.pem
fn key_path() -> Result<PathBuf, ConfigError> {
    Ok(paths::config_dir()?.join("tls-key.pem"))
}
