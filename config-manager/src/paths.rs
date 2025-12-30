use std::path::{Path, PathBuf};

use crate::error::ConfigError;

/// Get XDG config directory for slingshot
/// Returns ~/.config/slingshot or $XDG_CONFIG_HOME/slingshot
pub fn config_dir() -> Result<PathBuf, ConfigError> {
    dirs::config_dir()
        .map(|p| p.join("slingshot"))
        .ok_or(ConfigError::NoConfigDir)
}

/// Get default config file path for remote node
/// Returns ~/.config/slingshot/remote.toml
pub fn remote_config_path() -> Result<PathBuf, ConfigError> {
    Ok(config_dir()?.join("remote.toml"))
}

/// Get default config file path for central node
/// Returns ~/.config/slingshot/central.toml
pub fn central_config_path() -> Result<PathBuf, ConfigError> {
    Ok(config_dir()?.join("central.toml"))
}

/// Ensure config directory exists, creating it if necessary.
/// On Unix, sets directory permissions to 0700 (owner only).
pub fn ensure_config_dir() -> Result<PathBuf, ConfigError> {
    let dir = config_dir()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&dir, perms)?;
        }
    }
    Ok(dir)
}

/// Write content to a file with restrictive permissions (0600 on Unix).
/// Use this for files containing sensitive data like keys.
pub fn write_secure(path: &Path, content: &str) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // rw------- (owner only)
            .open(path)?;

        file.write_all(content.as_bytes())?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
        Ok(())
    }
}
