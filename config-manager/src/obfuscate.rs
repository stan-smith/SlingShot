use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::ConfigError;

/// Encode string to base64 (for obfuscation, NOT security)
pub fn encode(plain: &str) -> String {
    STANDARD.encode(plain.as_bytes())
}

/// Decode base64 string
pub fn decode(encoded: &str) -> Result<String, ConfigError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|e| ConfigError::DecodeError(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| ConfigError::DecodeError(e.to_string()))
}
