//! Central public key storage for command verification (TOFU model)
//!
//! Remote nodes store central's Ed25519 public key on first connection.
//! Subsequent connections verify the fingerprint matches (like SSH known_hosts).

use crate::error::ConfigError;
use crate::paths::{config_dir, ensure_config_dir, write_secure};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Central's Ed25519 public key for command verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CentralPubkeyConfig {
    /// Ed25519 public key as 64-character hex string
    pub ed25519_pubkey: String,
}

impl CentralPubkeyConfig {
    /// Create a new config from a hex-encoded public key
    pub fn new(pubkey_hex: &str) -> Result<Self, ConfigError> {
        // Validate hex encoding and length
        let bytes = hex::decode(pubkey_hex)
            .map_err(|_| ConfigError::Invalid("Invalid hex encoding for public key".to_string()))?;

        if bytes.len() != 32 {
            return Err(ConfigError::Invalid(format!(
                "Public key must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        Ok(Self {
            ed25519_pubkey: pubkey_hex.to_string(),
        })
    }

    /// Get the public key as bytes
    pub fn pubkey_bytes(&self) -> Result<[u8; 32], ConfigError> {
        let bytes = hex::decode(&self.ed25519_pubkey)
            .map_err(|_| ConfigError::Invalid("Invalid hex encoding for public key".to_string()))?;

        bytes
            .try_into()
            .map_err(|_| ConfigError::Invalid("Public key must be exactly 32 bytes".to_string()))
    }

    /// Get the default config file path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        Ok(config_dir()?.join("central-pubkey.toml"))
    }

    /// Check if config file exists
    pub fn exists() -> bool {
        Self::default_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Load config from default path
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path()?;
        let contents = fs::read_to_string(&path)?;
        Ok(toml::from_str(&contents)?)
    }

    /// Save config to default path
    pub fn save(&self) -> Result<(), ConfigError> {
        ensure_config_dir()?;
        let path = Self::default_path()?;
        let contents = toml::to_string_pretty(self)?;
        write_secure(&path, &contents)?;
        Ok(())
    }

    /// Delete the config file (for testing or reset)
    pub fn delete() -> Result<(), ConfigError> {
        let path = Self::default_path()?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_valid_pubkey() {
        // 32 bytes = 64 hex chars
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let config = CentralPubkeyConfig::new(hex).unwrap();
        assert_eq!(config.ed25519_pubkey, hex);
    }

    #[test]
    fn test_new_invalid_hex() {
        let err = CentralPubkeyConfig::new("not valid hex!").unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn test_new_wrong_length() {
        // Only 16 bytes
        let hex = "0123456789abcdef0123456789abcdef";
        let err = CentralPubkeyConfig::new(hex).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn test_pubkey_bytes() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let config = CentralPubkeyConfig::new(hex).unwrap();
        let bytes = config.pubkey_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x23);
    }
}
