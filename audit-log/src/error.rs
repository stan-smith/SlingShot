use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to determine data directory")]
    NoDataDir,

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}
