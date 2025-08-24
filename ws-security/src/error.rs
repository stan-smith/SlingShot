//! WS-Security error types

use thiserror::Error;

/// Errors that can occur during WS-Security processing
#[derive(Debug, Error)]
pub enum WsSecurityError {
    /// Security header not found in SOAP envelope
    #[error("Missing Security header")]
    MissingSecurityHeader,

    /// UsernameToken not found in Security header
    #[error("Missing UsernameToken")]
    MissingUsernameToken,

    /// Required element missing from UsernameToken
    #[error("Missing required element: {0}")]
    MissingElement(String),

    /// Nonce value has invalid Base64 encoding
    #[error("Invalid nonce encoding")]
    InvalidNonce,

    /// Created timestamp has invalid format
    #[error("Invalid timestamp format")]
    InvalidTimestamp,

    /// Request timestamp is too old
    #[error("Request expired (age: {age_secs}s, max: {max_secs}s)")]
    Expired { age_secs: u64, max_secs: u64 },

    /// Username or password digest does not match
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// XML parsing failed
    #[error("XML parse error: {0}")]
    XmlError(String),
}
