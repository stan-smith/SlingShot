use thiserror::Error;

#[derive(Error, Debug)]
pub enum HlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Node not connected: {0}")]
    NodeNotConnected(String),

    #[error("Stream not running for node: {0}")]
    StreamNotRunning(String),

    #[error("Recording not found: {0}")]
    RecordingNotFound(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Transmux failed: {0}")]
    TransmuxFailed(String),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("Invalid time range: {0}")]
    InvalidTimeRange(String),

    #[error("FFmpeg error: {0}")]
    Ffmpeg(String),

    #[error("Playlist generation failed: {0}")]
    PlaylistFailed(String),
}

impl From<quinn::ConnectionError> for HlsError {
    fn from(e: quinn::ConnectionError) -> Self {
        HlsError::Quic(e.to_string())
    }
}

impl From<quinn::WriteError> for HlsError {
    fn from(e: quinn::WriteError) -> Self {
        HlsError::Quic(e.to_string())
    }
}

impl From<quinn::ReadError> for HlsError {
    fn from(e: quinn::ReadError) -> Self {
        HlsError::Quic(e.to_string())
    }
}
