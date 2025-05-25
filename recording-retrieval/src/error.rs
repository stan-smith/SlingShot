//! Error types for recording retrieval

use chrono::{DateTime, Local};
use kaiju_encryption::EncryptionError;

#[derive(Debug, thiserror::Error)]
pub enum RetrievalError {
    #[error("Invalid time format: {0}")]
    InvalidTimeFormat(String),

    #[error("Missing time range argument")]
    MissingTimeRange,

    #[error("Invalid time range: from ({from}) must be before to ({to})")]
    InvalidTimeRange {
        from: DateTime<Local>,
        to: DateTime<Local>,
    },

    #[error("No recordings found in specified time range")]
    NoRecordingsFound,

    #[error("Storage not available")]
    StorageNotAvailable,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Unexpected chunk received for unknown file")]
    UnexpectedChunk,

    #[error("Unexpected file complete for unknown file")]
    UnexpectedComplete,

    #[error("File corrupted: {filename} (expected CRC 0x{expected:08X}, got 0x{actual:08X})")]
    FileCorrupted {
        filename: String,
        expected: u32,
        actual: u32,
    },

    #[error("QUIC connection error: {0}")]
    QuicError(String),

    #[error("Transfer cancelled")]
    Cancelled,

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encrypted file received but no decryption key available")]
    NoDecryptionKey,
}

impl From<std::io::Error> for RetrievalError {
    fn from(e: std::io::Error) -> Self {
        RetrievalError::IoError(e.to_string())
    }
}

impl From<quinn::ConnectionError> for RetrievalError {
    fn from(e: quinn::ConnectionError) -> Self {
        RetrievalError::QuicError(e.to_string())
    }
}

impl From<quinn::WriteError> for RetrievalError {
    fn from(e: quinn::WriteError) -> Self {
        RetrievalError::QuicError(e.to_string())
    }
}

impl From<quinn::ClosedStream> for RetrievalError {
    fn from(e: quinn::ClosedStream) -> Self {
        RetrievalError::QuicError(e.to_string())
    }
}

impl From<EncryptionError> for RetrievalError {
    fn from(e: EncryptionError) -> Self {
        RetrievalError::DecryptionFailed(e.to_string())
    }
}
