//! Encryption configuration for remote nodes
//!
//! Stores the X25519 public key received from central for encrypting recordings.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::paths;

/// Maximum length for X25519 public key hex string (32 bytes = 64 hex chars)
const MAX_PUBKEY_HEX_LEN: usize = 64;

/// Encryption configuration storing the X25519 public key from central
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Hex-encoded X25519 public key (64 chars)
    pub x25519_pubkey: String,
}

impl EncryptionConfig {
    /// Create new encryption config with the given public key
    pub fn new(pubkey_hex: &str) -> Result<Self, ConfigError> {
        // Validate length
        if pubkey_hex.len() != MAX_PUBKEY_HEX_LEN {
            return Err(ConfigError::Invalid(format!(
                "Invalid public key length: expected {} hex chars, got {}",
                MAX_PUBKEY_HEX_LEN,
                pubkey_hex.len()
            )));
        }
        // Validate hex
        if hex::decode(pubkey_hex).is_err() {
            return Err(ConfigError::Invalid(
                "Invalid public key: not valid hex".to_string(),
            ));
        }
        Ok(Self {
            x25519_pubkey: pubkey_hex.to_string(),
        })
    }

    /// Get the public key as bytes
    pub fn pubkey_bytes(&self) -> Result<[u8; 32], ConfigError> {
        let bytes = hex::decode(&self.x25519_pubkey)
            .map_err(|e| ConfigError::DecodeError(e.to_string()))?;
        bytes
            .try_into()
            .map_err(|_| ConfigError::DecodeError("Invalid key length".to_string()))
    }

    /// Check if encryption config exists at default location
    pub fn exists() -> bool {
        encryption_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Get default encryption config path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        encryption_path()
    }

    /// Load config from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let path = encryption_path()?;
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
        let path = encryption_path()?;
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

/// Get encryption config path: ~/.config/kaiju/encryption.toml
fn encryption_path() -> Result<PathBuf, ConfigError> {
    Ok(paths::config_dir()?.join("encryption.toml"))
}
