//! Wire protocol for file transfer over QUIC
//!
//! Message format uses a magic byte (0x01) to distinguish from video frames and text.

use crc32fast::Hasher;

use crate::RetrievalError;

/// Magic byte for file transfer messages
/// Distinguishes from video frames (low bytes) and text (>= 0x20)
pub const FILE_TRANSFER_MAGIC: u8 = 0x01;

/// Message types for file transfer protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMessageType {
    /// Request to transfer files (central -> remote)
    TransferRequest = 0x10,
    /// Metadata for a file about to be sent
    FileHeader = 0x11,
    /// Chunk of file data
    FileChunk = 0x12,
    /// File transfer complete
    FileComplete = 0x13,
    /// Transfer session complete (all files sent)
    TransferComplete = 0x14,
    /// Error during transfer
    TransferError = 0x15,
}

impl TryFrom<u8> for FileMessageType {
    type Error = RetrievalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x10 => Ok(FileMessageType::TransferRequest),
            0x11 => Ok(FileMessageType::FileHeader),
            0x12 => Ok(FileMessageType::FileChunk),
            0x13 => Ok(FileMessageType::FileComplete),
            0x14 => Ok(FileMessageType::TransferComplete),
            0x15 => Ok(FileMessageType::TransferError),
            _ => Err(RetrievalError::ProtocolError(format!(
                "Unknown message type: 0x{:02X}",
                value
            ))),
        }
    }
}

/// Transfer request sent from central to remote
#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub request_id: u32,
    pub time_from: i64, // Unix timestamp
    pub time_to: i64,   // Unix timestamp
}

impl TransferRequest {
    /// Encode for wire transmission
    /// Format: [magic:1][type:1][request_id:4][time_from:8][time_to:8] = 22 bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(22);
        buf.push(FILE_TRANSFER_MAGIC);
        buf.push(FileMessageType::TransferRequest as u8);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&self.time_from.to_be_bytes());
        buf.extend_from_slice(&self.time_to.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, RetrievalError> {
        if data.len() < 22 || data[0] != FILE_TRANSFER_MAGIC {
            return Err(RetrievalError::ProtocolError("Invalid TransferRequest".into()));
        }
        Ok(Self {
            request_id: u32::from_be_bytes(data[2..6].try_into().unwrap()),
            time_from: i64::from_be_bytes(data[6..14].try_into().unwrap()),
            time_to: i64::from_be_bytes(data[14..22].try_into().unwrap()),
        })
    }
}

/// File header sent before file data
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub request_id: u32,
    pub file_index: u32,  // 0-based index in this transfer
    pub total_files: u32, // Total number of files
    pub file_size: u64,   // Size in bytes
    pub chunk_size: u32,  // Size of each chunk
    pub total_chunks: u32,
    pub crc32: u32, // CRC32 of entire file
    pub filename: String,
}

impl FileHeader {
    /// Encode for wire transmission
    /// Format: [magic:1][type:1][request_id:4][file_index:4][total_files:4]
    ///         [file_size:8][chunk_size:4][total_chunks:4][crc32:4]
    ///         [filename_len:2][filename:N]
    pub fn encode(&self) -> Vec<u8> {
        let filename_bytes = self.filename.as_bytes();
        let mut buf = Vec::with_capacity(36 + filename_bytes.len());
        buf.push(FILE_TRANSFER_MAGIC);
        buf.push(FileMessageType::FileHeader as u8);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&self.file_index.to_be_bytes());
        buf.extend_from_slice(&self.total_files.to_be_bytes());
        buf.extend_from_slice(&self.file_size.to_be_bytes());
        buf.extend_from_slice(&self.chunk_size.to_be_bytes());
        buf.extend_from_slice(&self.total_chunks.to_be_bytes());
        buf.extend_from_slice(&self.crc32.to_be_bytes());
        buf.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(filename_bytes);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, RetrievalError> {
        if data.len() < 36 || data[0] != FILE_TRANSFER_MAGIC {
            return Err(RetrievalError::ProtocolError("Invalid FileHeader".into()));
        }
        let filename_len = u16::from_be_bytes(data[34..36].try_into().unwrap()) as usize;
        if data.len() < 36 + filename_len {
            return Err(RetrievalError::ProtocolError(
                "FileHeader truncated".into(),
            ));
        }
        Ok(Self {
            request_id: u32::from_be_bytes(data[2..6].try_into().unwrap()),
            file_index: u32::from_be_bytes(data[6..10].try_into().unwrap()),
            total_files: u32::from_be_bytes(data[10..14].try_into().unwrap()),
            file_size: u64::from_be_bytes(data[14..22].try_into().unwrap()),
            chunk_size: u32::from_be_bytes(data[22..26].try_into().unwrap()),
            total_chunks: u32::from_be_bytes(data[26..30].try_into().unwrap()),
            crc32: u32::from_be_bytes(data[30..34].try_into().unwrap()),
            filename: String::from_utf8_lossy(&data[36..36 + filename_len]).to_string(),
        })
    }
}

/// File chunk with data
#[derive(Debug, Clone)]
pub struct FileChunk {
    pub request_id: u32,
    pub file_index: u32,
    pub chunk_index: u32,
    pub chunk_crc32: u32,
    pub data: Vec<u8>,
}

impl FileChunk {
    /// Recommended chunk size (under stream limit, good for QUIC efficiency)
    pub const DEFAULT_CHUNK_SIZE: usize = 512 * 1024; // 512KB per chunk

    /// Encode for wire transmission
    /// Format: [magic:1][type:1][request_id:4][file_index:4][chunk_index:4]
    ///         [chunk_crc32:4][data_len:4][data:N]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(22 + self.data.len());
        buf.push(FILE_TRANSFER_MAGIC);
        buf.push(FileMessageType::FileChunk as u8);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&self.file_index.to_be_bytes());
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());
        buf.extend_from_slice(&self.chunk_crc32.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, RetrievalError> {
        if data.len() < 22 || data[0] != FILE_TRANSFER_MAGIC {
            return Err(RetrievalError::ProtocolError("Invalid FileChunk".into()));
        }
        let data_len = u32::from_be_bytes(data[18..22].try_into().unwrap()) as usize;
        if data.len() < 22 + data_len {
            return Err(RetrievalError::ProtocolError("FileChunk truncated".into()));
        }
        let chunk_data = data[22..22 + data_len].to_vec();
        let expected_crc = u32::from_be_bytes(data[14..18].try_into().unwrap());

        // Verify chunk CRC
        let mut hasher = Hasher::new();
        hasher.update(&chunk_data);
        let actual_crc = hasher.finalize();
        if actual_crc != expected_crc {
            return Err(RetrievalError::ChecksumMismatch);
        }

        Ok(Self {
            request_id: u32::from_be_bytes(data[2..6].try_into().unwrap()),
            file_index: u32::from_be_bytes(data[6..10].try_into().unwrap()),
            chunk_index: u32::from_be_bytes(data[10..14].try_into().unwrap()),
            chunk_crc32: expected_crc,
            data: chunk_data,
        })
    }

    /// Create a chunk with automatic CRC calculation
    pub fn new(request_id: u32, file_index: u32, chunk_index: u32, data: Vec<u8>) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&data);
        let chunk_crc32 = hasher.finalize();

        Self {
            request_id,
            file_index,
            chunk_index,
            chunk_crc32,
            data,
        }
    }
}

/// File transfer complete marker
#[derive(Debug, Clone)]
pub struct FileComplete {
    pub request_id: u32,
    pub file_index: u32,
}

impl FileComplete {
    /// Format: [magic:1][type:1][request_id:4][file_index:4] = 10 bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10);
        buf.push(FILE_TRANSFER_MAGIC);
        buf.push(FileMessageType::FileComplete as u8);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&self.file_index.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, RetrievalError> {
        if data.len() < 10 || data[0] != FILE_TRANSFER_MAGIC {
            return Err(RetrievalError::ProtocolError("Invalid FileComplete".into()));
        }
        Ok(Self {
            request_id: u32::from_be_bytes(data[2..6].try_into().unwrap()),
            file_index: u32::from_be_bytes(data[6..10].try_into().unwrap()),
        })
    }
}

/// All files transfer complete
#[derive(Debug, Clone)]
pub struct TransferComplete {
    pub request_id: u32,
    pub total_files: u32,
    pub total_bytes: u64,
}

impl TransferComplete {
    /// Format: [magic:1][type:1][request_id:4][total_files:4][total_bytes:8] = 18 bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18);
        buf.push(FILE_TRANSFER_MAGIC);
        buf.push(FileMessageType::TransferComplete as u8);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&self.total_files.to_be_bytes());
        buf.extend_from_slice(&self.total_bytes.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, RetrievalError> {
        if data.len() < 18 || data[0] != FILE_TRANSFER_MAGIC {
            return Err(RetrievalError::ProtocolError(
                "Invalid TransferComplete".into(),
            ));
        }
        Ok(Self {
            request_id: u32::from_be_bytes(data[2..6].try_into().unwrap()),
            total_files: u32::from_be_bytes(data[6..10].try_into().unwrap()),
            total_bytes: u64::from_be_bytes(data[10..18].try_into().unwrap()),
        })
    }
}

/// Error during transfer
#[derive(Debug, Clone)]
pub struct TransferError {
    pub request_id: u32,
    pub error_code: u16,
    pub message: String,
}

impl TransferError {
    pub const NO_RECORDINGS_FOUND: u16 = 1;
    pub const IO_ERROR: u16 = 2;
    pub const INVALID_TIME_RANGE: u16 = 3;
    pub const TRANSFER_CANCELLED: u16 = 4;
    pub const STORAGE_NOT_AVAILABLE: u16 = 5;

    /// Format: [magic:1][type:1][request_id:4][error_code:2][msg_len:2][message:N]
    pub fn encode(&self) -> Vec<u8> {
        let msg_bytes = self.message.as_bytes();
        let mut buf = Vec::with_capacity(10 + msg_bytes.len());
        buf.push(FILE_TRANSFER_MAGIC);
        buf.push(FileMessageType::TransferError as u8);
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&self.error_code.to_be_bytes());
        buf.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(msg_bytes);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, RetrievalError> {
        if data.len() < 10 || data[0] != FILE_TRANSFER_MAGIC {
            return Err(RetrievalError::ProtocolError(
                "Invalid TransferError".into(),
            ));
        }
        let msg_len = u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize;
        if data.len() < 10 + msg_len {
            return Err(RetrievalError::ProtocolError(
                "TransferError truncated".into(),
            ));
        }
        Ok(Self {
            request_id: u32::from_be_bytes(data[2..6].try_into().unwrap()),
            error_code: u16::from_be_bytes(data[6..8].try_into().unwrap()),
            message: String::from_utf8_lossy(&data[10..10 + msg_len]).to_string(),
        })
    }
}

/// Decode message type from raw data
pub fn decode_message_type(data: &[u8]) -> Result<FileMessageType, RetrievalError> {
    if data.len() < 2 || data[0] != FILE_TRANSFER_MAGIC {
        return Err(RetrievalError::ProtocolError(
            "Not a file transfer message".into(),
        ));
    }
    FileMessageType::try_from(data[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_header_roundtrip() {
        let header = FileHeader {
            request_id: 42,
            file_index: 0,
            total_files: 3,
            file_size: 1024 * 1024,
            chunk_size: 512 * 1024,
            total_chunks: 2,
            crc32: 0xDEADBEEF,
            filename: "2024-12-01_15-30-00.mp4".to_string(),
        };

        let encoded = header.encode();
        let decoded = FileHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.file_index, 0);
        assert_eq!(decoded.total_files, 3);
        assert_eq!(decoded.file_size, 1024 * 1024);
        assert_eq!(decoded.crc32, 0xDEADBEEF);
        assert_eq!(decoded.filename, "2024-12-01_15-30-00.mp4");
    }

    #[test]
    fn test_file_chunk_crc() {
        let chunk = FileChunk::new(1, 0, 0, vec![1, 2, 3, 4, 5]);
        let encoded = chunk.encode();
        let decoded = FileChunk::decode(&encoded).unwrap();

        assert_eq!(decoded.data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_file_chunk_bad_crc() {
        let mut chunk = FileChunk::new(1, 0, 0, vec![1, 2, 3, 4, 5]);
        chunk.chunk_crc32 = 0; // Wrong CRC
        let encoded = chunk.encode();
        let result = FileChunk::decode(&encoded);

        assert!(matches!(result, Err(RetrievalError::ChecksumMismatch)));
    }
}
