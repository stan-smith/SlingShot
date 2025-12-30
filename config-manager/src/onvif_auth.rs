//! ONVIF authentication configuration
//!
//! Stores credentials for WS-Security authentication on ONVIF endpoints.

use std::path::{Path, PathBuf};

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::paths;

/// Characters used for generating random passwords
const PASSWORD_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// ONVIF authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnvifAuthConfig {
    /// Username for ONVIF authentication
    pub username: String,
    /// Password for ONVIF authentication
    pub password: String,
}

impl OnvifAuthConfig {
    /// Create new ONVIF auth config with the given credentials
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Generate config with default username and random password
    pub fn generate_default() -> Self {
        Self {
            username: "onvif".to_string(),
            password: generate_random_password(16),
        }
    }

    /// Check if config exists at default location
    pub fn exists() -> bool {
        onvif_auth_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Get default config path
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        onvif_auth_path()
    }

    /// Load config from default XDG location
    pub fn load() -> Result<Self, ConfigError> {
        let path = onvif_auth_path()?;
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
        let path = onvif_auth_path()?;
        self.save_to(&path)
    }

    /// Save config to specific path.
    /// Uses restrictive file permissions (0600 on Unix) since this contains credentials.
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        paths::ensure_config_dir()?;
        let content = toml::to_string_pretty(self)?;
        paths::write_secure(path, &content)?;
        Ok(())
    }
}

/// Get ONVIF auth config path: ~/.config/slingshot/onvif_auth.toml
fn onvif_auth_path() -> Result<PathBuf, ConfigError> {
    Ok(paths::config_dir()?.join("onvif_auth.toml"))
}

/// Generate a random alphanumeric password of the given length
pub fn generate_random_password(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..PASSWORD_CHARS.len());
            PASSWORD_CHARS[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_password() {
        let pw1 = generate_random_password(16);
        let pw2 = generate_random_password(16);

        assert_eq!(pw1.len(), 16);
        assert_eq!(pw2.len(), 16);
        assert_ne!(pw1, pw2); // Should be different (very high probability)

        // All chars should be alphanumeric
        assert!(pw1.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_default() {
        let config = OnvifAuthConfig::generate_default();
        assert_eq!(config.username, "onvif");
        assert_eq!(config.password.len(), 16);
    }
}
