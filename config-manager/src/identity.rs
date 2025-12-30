//! Identity configuration for remote nodes
//!
//! Stores Ed25519 keypair for stable fingerprinting across restarts.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::obfuscate;
use crate::paths;

/// Identity configuration storing Ed25519 secret key
///
/// The secret key is base64-encoded for storage (obfuscation, not security).
/// The fingerprint is derived from the corresponding public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Base64-encoded hex string of Ed25519 secret key (32 bytes)
    secret_key_b64: String,
}

impl IdentityConfig {
    /// Create new identity with provided secret bytes
    pub fn new(secret_bytes: &[u8; 32]) -> Self {
        Self {
            secret_key_b64: obfuscate::encode(&hex::encode(secret_bytes)),
        }
    }

    /// Get secret key bytes
    pub fn secret_bytes(&self) -> Result<[u8; 32], ConfigError> {
        let hex_str = obfuscate::decode(&self.secret_key_b64)?;
        let bytes = hex::decode(&hex_str)
            .map_err(|e| ConfigError::DecodeError(e.to_string()))?;
        bytes
            .try_into()
            .map_err(|_| ConfigError::DecodeError("Invalid key length (expected 32 bytes)".to_string()))
    }

    /// Check if identity file exists
    pub fn exists() -> bool {
        identity_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Get default identity file path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        identity_path()
    }

    /// Load identity from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let path = identity_path()?;
        Self::load_from(&path)
    }

    /// Load identity from specific path
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.display().to_string()));
        }
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save identity to default XDG location
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = identity_path()?;
        self.save_to(&path)
    }

    /// Save identity to specific path.
    /// Uses restrictive file permissions (0600 on Unix) since this contains the secret key.
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        paths::ensure_config_dir()?;
        let content = toml::to_string_pretty(self)?;
        paths::write_secure(path, &content)?;
        Ok(())
    }
}

/// Get identity file path: ~/.config/slingshot/identity.toml
fn identity_path() -> Result<PathBuf, ConfigError> {
    Ok(paths::config_dir()?.join("identity.toml"))
}
