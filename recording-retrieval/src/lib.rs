//! Recording retrieval protocol for QUIC-based file transfer
//!
//! Enables Central to request recordings from Remote nodes by time range.
//! Supports both relative ("5 mins ago") and absolute (ISO8601) time formats.

pub mod error;
pub mod files;
pub mod protocol;
pub mod time;
pub mod transfer;

pub use error::RetrievalError;
pub use files::{find_recordings_in_range, list_all_recordings, RecordingFile};
pub use protocol::{
    decode_message_type, FileChunk, FileComplete, FileHeader, FileMessageType, TransferComplete,
    TransferError, TransferRequest, FILE_TRANSFER_MAGIC,
};
pub use time::{parse_time_range, TimeRange};
pub use transfer::{FileTransferReceiver, FileTransferSender};

/// Format bytes as human-readable string
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}
