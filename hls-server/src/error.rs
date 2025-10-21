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

    #[error("Segment not found: {0}")]
    SegmentNotFound(String),

    #[error("FFmpeg error: {0}")]
    Ffmpeg(String),
}
