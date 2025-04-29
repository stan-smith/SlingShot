use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("Config file not found at {0}")]
    NotFound(String),

    #[error("Failed to determine config directory")]
    NoConfigDir,

    #[error("Base64 decode error: {0}")]
    DecodeError(String),

    #[error("Invalid config: {0}")]
    Invalid(String),
}
