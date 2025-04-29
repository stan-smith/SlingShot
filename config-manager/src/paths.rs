use std::path::PathBuf;

use crate::error::ConfigError;

/// Get XDG config directory for kaiju
/// Returns ~/.config/kaiju or $XDG_CONFIG_HOME/kaiju
pub fn config_dir() -> Result<PathBuf, ConfigError> {
    dirs::config_dir()
        .map(|p| p.join("kaiju"))
        .ok_or(ConfigError::NoConfigDir)
}

/// Get default config file path for remote node
/// Returns ~/.config/kaiju/remote.toml
pub fn remote_config_path() -> Result<PathBuf, ConfigError> {
    Ok(config_dir()?.join("remote.toml"))
}

/// Ensure config directory exists, creating it if necessary
pub fn ensure_config_dir() -> Result<PathBuf, ConfigError> {
    let dir = config_dir()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}
