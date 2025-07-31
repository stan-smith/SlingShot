use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to determine data directory")]
    NoDataDir,

    #[error("Node not found: {0}")]
    NotFound(String),

    #[error("Field too long: {field} (max {max} chars, got {actual})")]
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },

    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("TOTP error: {0}")]
    TotpError(String),

    #[error("Invalid role: {0} (must be 'admin' or 'user')")]
    InvalidRole(String),

    #[error("Cannot remove or demote the last admin user")]
    LastAdmin,
}
