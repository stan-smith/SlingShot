//! File transfer sender and receiver implementations

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use crc32fast::Hasher;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{FileChunk, FileComplete, FileHeader, TransferComplete, TransferError};
use crate::{RecordingFile, RetrievalError};

/// File transfer sender (runs on remote)
pub struct FileTransferSender {
    request_counter: AtomicU32,
}

impl FileTransferSender {
    pub fn new() -> Self {
        Self {
            request_counter: AtomicU32::new(0),
        }
    }

    /// Generate a new request ID
    pub fn next_request_id(&self) -> u32 {
        self.request_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Send all files over QUIC connection
    pub async fn send_files(
        &self,
        conn: &quinn::Connection,
        files: &[RecordingFile],
        request_id: u32,
    ) -> Result<u64, RetrievalError> {
        let total_files = files.len() as u32;
        let mut total_bytes: u64 = 0;

        for (index, recording) in files.iter().enumerate() {
            let bytes = self
                .send_single_file(conn, recording, request_id, index as u32, total_files)
                .await?;
            total_bytes += bytes;
        }

        // Send transfer complete
        let complete = TransferComplete {
            request_id,
            total_files,
            total_bytes,
        };
        let mut stream = conn.open_uni().await?;
        stream.write_all(&complete.encode()).await?;
        stream.finish()?;

        Ok(total_bytes)
    }

    /// Send a single file
    async fn send_single_file(
        &self,
        conn: &quinn::Connection,
        recording: &RecordingFile,
        request_id: u32,
        file_index: u32,
        total_files: u32,
    ) -> Result<u64, RetrievalError> {
        // Calculate file CRC32
        let file_crc = Self::calculate_file_crc(&recording.path).await?;

        // Calculate chunking
        let chunk_size = FileChunk::DEFAULT_CHUNK_SIZE as u32;
        let total_chunks =
            ((recording.size_bytes + chunk_size as u64 - 1) / chunk_size as u64) as u32;

        let filename = recording
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Send file header
        let header = FileHeader {
            request_id,
            file_index,
            total_files,
            file_size: recording.size_bytes,
            chunk_size,
            total_chunks,
            crc32: file_crc,
            filename: filename.clone(),
        };

        println!(
            "[FILE TRANSFER] Sending {}/{}: {} ({})",
            file_index + 1,
            total_files,
            filename,
            crate::format_size(recording.size_bytes)
        );

        let mut stream = conn.open_uni().await?;
        stream.write_all(&header.encode()).await?;
        stream.finish()?;

        // Send chunks
        self.send_file_chunks(conn, &recording.path, request_id, file_index, chunk_size)
            .await?;

        // Send file complete
        let complete = FileComplete {
            request_id,
            file_index,
        };
        let mut stream = conn.open_uni().await?;
        stream.write_all(&complete.encode()).await?;
        stream.finish()?;

        Ok(recording.size_bytes)
    }

    /// Send file in chunks
    async fn send_file_chunks(
        &self,
        conn: &quinn::Connection,
        path: &Path,
        request_id: u32,
        file_index: u32,
        chunk_size: u32,
    ) -> Result<(), RetrievalError> {
        let mut file = File::open(path).await?;
        let mut buffer = vec![0u8; chunk_size as usize];
        let mut chunk_index = 0u32;

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            let chunk_data = &buffer[..bytes_read];
            let chunk = FileChunk::new(request_id, file_index, chunk_index, chunk_data.to_vec());

            // Send chunk on its own stream
            let mut stream = conn.open_uni().await?;
            stream.write_all(&chunk.encode()).await?;
            stream.finish()?;

            chunk_index += 1;

            // Small yield to avoid starving video streams
            tokio::task::yield_now().await;
        }

        Ok(())
    }

    /// Calculate CRC32 of entire file
    async fn calculate_file_crc(path: &Path) -> Result<u32, RetrievalError> {
        let mut file = File::open(path).await?;
        let mut hasher = Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB read buffer

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize())
    }

    /// Send an error message
    pub async fn send_error(
        conn: &quinn::Connection,
        request_id: u32,
        error_code: u16,
        message: &str,
    ) -> Result<(), RetrievalError> {
        let error = TransferError {
            request_id,
            error_code,
            message: message.to_string(),
        };
        let mut stream = conn.open_uni().await?;
        stream.write_all(&error.encode()).await?;
        stream.finish()?;
        Ok(())
    }
}

impl Default for FileTransferSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Active file transfer state
struct ActiveTransfer {
    header: FileHeader,
    file: File,
    output_path: PathBuf,
    chunks_received: u32,
    bytes_received: u64,
    chunk_buffer: HashMap<u32, Vec<u8>>, // For out-of-order chunks
    next_expected_chunk: u32,
}

/// File transfer receiver (runs on central)
pub struct FileTransferReceiver {
    output_dir: PathBuf,
    active_transfers: HashMap<(u32, u32), ActiveTransfer>, // (request_id, file_index)
}

/// Progress information for a file transfer
#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub file_index: u32,
    pub total_files: u32,
    pub filename: String,
    pub chunks_received: u32,
    pub total_chunks: u32,
    pub bytes_received: u64,
    pub total_bytes: u64,
}

impl TransferProgress {
    pub fn percent_complete(&self) -> f64 {
        if self.total_bytes == 0 {
            100.0
        } else {
            (self.bytes_received as f64 / self.total_bytes as f64) * 100.0
        }
    }
}

impl FileTransferReceiver {
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            output_dir,
            active_transfers: HashMap::new(),
        }
    }

    /// Start receiving a new file
    pub async fn start_file(&mut self, header: FileHeader) -> Result<PathBuf, RetrievalError> {
        // Ensure output directory exists
        tokio::fs::create_dir_all(&self.output_dir).await?;

        let output_path = self.output_dir.join(&header.filename);
        let file = File::create(&output_path).await?;

        let key = (header.request_id, header.file_index);
        self.active_transfers.insert(
            key,
            ActiveTransfer {
                header,
                file,
                output_path: output_path.clone(),
                chunks_received: 0,
                bytes_received: 0,
                chunk_buffer: HashMap::new(),
                next_expected_chunk: 0,
            },
        );

        Ok(output_path)
    }

    /// Receive a chunk of file data
    pub async fn receive_chunk(&mut self, chunk: FileChunk) -> Result<(), RetrievalError> {
        let key = (chunk.request_id, chunk.file_index);
        let transfer = self
            .active_transfers
            .get_mut(&key)
            .ok_or(RetrievalError::UnexpectedChunk)?;

        // Handle out-of-order delivery
        if chunk.chunk_index == transfer.next_expected_chunk {
            // Write this chunk
            transfer.file.write_all(&chunk.data).await?;
            transfer.chunks_received += 1;
            transfer.bytes_received += chunk.data.len() as u64;
            transfer.next_expected_chunk += 1;

            // Write any buffered subsequent chunks
            while let Some(buffered) = transfer.chunk_buffer.remove(&transfer.next_expected_chunk) {
                transfer.file.write_all(&buffered).await?;
                transfer.chunks_received += 1;
                transfer.bytes_received += buffered.len() as u64;
                transfer.next_expected_chunk += 1;
            }
        } else if chunk.chunk_index > transfer.next_expected_chunk {
            // Buffer for later
            transfer.chunk_buffer.insert(chunk.chunk_index, chunk.data);
        }
        // Ignore duplicate/old chunks

        Ok(())
    }

    /// Complete a file transfer and verify CRC
    pub async fn complete_file(
        &mut self,
        request_id: u32,
        file_index: u32,
    ) -> Result<PathBuf, RetrievalError> {
        let key = (request_id, file_index);
        let transfer = self
            .active_transfers
            .remove(&key)
            .ok_or(RetrievalError::UnexpectedComplete)?;

        // Flush and sync file
        drop(transfer.file); // Close the file handle

        // Verify file CRC
        let actual_crc = Self::calculate_file_crc(&transfer.output_path).await?;
        if actual_crc != transfer.header.crc32 {
            // Delete corrupted file
            let _ = tokio::fs::remove_file(&transfer.output_path).await;
            return Err(RetrievalError::FileCorrupted {
                filename: transfer.header.filename,
                expected: transfer.header.crc32,
                actual: actual_crc,
            });
        }

        Ok(transfer.output_path)
    }

    /// Get progress for a specific file transfer
    pub fn progress(&self, request_id: u32, file_index: u32) -> Option<TransferProgress> {
        let key = (request_id, file_index);
        self.active_transfers.get(&key).map(|t| TransferProgress {
            file_index: t.header.file_index,
            total_files: t.header.total_files,
            filename: t.header.filename.clone(),
            chunks_received: t.chunks_received,
            total_chunks: t.header.total_chunks,
            bytes_received: t.bytes_received,
            total_bytes: t.header.file_size,
        })
    }

    /// Calculate CRC32 of a file
    async fn calculate_file_crc(path: &Path) -> Result<u32, RetrievalError> {
        let mut file = File::open(path).await?;
        let mut hasher = Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize())
    }

    /// Get output directory
    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }
}
