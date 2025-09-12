//! File transfer sender and receiver implementations

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crc32fast::Hasher;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{FileChunk, FileComplete, FileHeader, TransferComplete, TransferError};
use crate::{RecordingFile, RetrievalError};

/// Sanitize and validate a filename received from remote.
/// Prevents path traversal attacks by rejecting dangerous patterns.
fn sanitize_filename(filename: &str) -> Result<String, RetrievalError> {
    // Reject path traversal attempts
    if filename.contains("..") {
        return Err(RetrievalError::InvalidFilename(
            "path traversal attempt detected (contains '..')".into(),
        ));
    }

    let path = Path::new(filename);

    // Reject absolute paths
    if path.is_absolute() {
        return Err(RetrievalError::InvalidFilename(
            "absolute paths not allowed".into(),
        ));
    }

    // Extract just the filename component (rejects paths with directories)
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| RetrievalError::InvalidFilename("invalid filename".into()))?;

    // If filename contained path separators, the extracted name will differ
    if name != filename {
        return Err(RetrievalError::InvalidFilename(
            "filename contains path separators".into(),
        ));
    }

    // Validate expected recording file extensions
    if !name.ends_with(".mp4") && !name.ends_with(".mp4.enc") {
        return Err(RetrievalError::InvalidFilename(
            "unexpected file extension (expected .mp4 or .mp4.enc)".into(),
        ));
    }

    // Validate characters: only alphanumeric, dash, underscore, dot allowed
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(RetrievalError::InvalidFilename(
            "filename contains invalid characters".into(),
        ));
    }

    Ok(name.to_string())
}

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

        // Detect if file is encrypted (has .enc extension)
        let encrypted = filename.ends_with(".enc");

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
            encrypted,
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
    /// Secret key for decrypting encrypted recordings (hex-encoded)
    decryption_key: Option<String>,
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
            decryption_key: None,
        }
    }

    /// Create a receiver with a decryption key for encrypted recordings
    pub fn with_decryption_key(output_dir: PathBuf, secret_key_hex: String) -> Self {
        Self {
            output_dir,
            active_transfers: HashMap::new(),
            decryption_key: Some(secret_key_hex),
        }
    }

    /// Set the decryption key (can be called after construction)
    pub fn set_decryption_key(&mut self, secret_key_hex: String) {
        self.decryption_key = Some(secret_key_hex);
    }

    /// Start receiving a new file
    pub async fn start_file(&mut self, header: FileHeader) -> Result<PathBuf, RetrievalError> {
        // Validate and sanitize filename to prevent path traversal
        let safe_filename = sanitize_filename(&header.filename)?;

        // Ensure output directory exists
        tokio::fs::create_dir_all(&self.output_dir).await?;

        // Write to temp file during transfer, rename on successful CRC
        let temp_filename = format!("{}.tmpss", safe_filename);
        let output_path = self.output_dir.join(&temp_filename);
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
    /// If the file is encrypted and we have a decryption key, decrypt it.
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
            // Delete corrupted file with retry
            for attempt in 1..=3 {
                match tokio::fs::remove_file(&transfer.output_path).await {
                    Ok(()) => break,
                    Err(e) if attempt < 3 => {
                        eprintln!(
                            "Warning: Failed to remove corrupted file '{}' (attempt {}): {}",
                            transfer.output_path.display(),
                            attempt,
                            e
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        eprintln!(
                            "ERROR: Could not remove corrupted file '{}' after 3 attempts: {}",
                            transfer.output_path.display(),
                            e
                        );
                    }
                }
            }
            return Err(RetrievalError::FileCorrupted {
                filename: transfer.header.filename,
                expected: transfer.header.crc32,
                actual: actual_crc,
            });
        }

        // CRC verified - rename from .tmpss to final filename
        let final_path = self.output_dir.join(&transfer.header.filename);
        tokio::fs::rename(&transfer.output_path, &final_path).await?;

        // If file is encrypted, decrypt it
        if transfer.header.encrypted {
            return self.decrypt_file(&final_path).await;
        }

        Ok(final_path)
    }

    /// Decrypt an encrypted file and return the path to the decrypted file
    async fn decrypt_file(&self, encrypted_path: &Path) -> Result<PathBuf, RetrievalError> {
        let secret_key = self
            .decryption_key
            .as_ref()
            .ok_or(RetrievalError::NoDecryptionKey)?;

        // Read encrypted content
        let ciphertext = tokio::fs::read(encrypted_path).await?;

        // Decrypt
        let plaintext = kaiju_encryption::open_with_hex_key(&ciphertext, secret_key)?;

        // Compute decrypted filename by stripping .enc extension
        let encrypted_name = encrypted_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let decrypted_name = encrypted_name.strip_suffix(".enc").unwrap_or(encrypted_name);
        let decrypted_path = encrypted_path.with_file_name(decrypted_name);

        // Write decrypted file
        tokio::fs::write(&decrypted_path, &plaintext).await?;

        // Delete encrypted file
        tokio::fs::remove_file(encrypted_path).await?;

        println!(
            "[DECRYPT] {} ({}) -> {} ({})",
            encrypted_name,
            crate::format_size(ciphertext.len() as u64),
            decrypted_name,
            crate::format_size(plaintext.len() as u64)
        );

        Ok(decrypted_path)
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

    /// Clean up incomplete transfers from previous sessions
    ///
    /// Scans output directory and removes .tmpss files (SlingShot temp files
    /// from interrupted transfers). Returns the number of files cleaned up.
    pub async fn cleanup_orphans(&self) -> Result<u32, RetrievalError> {
        let mut cleaned = 0;

        // Ensure directory exists before scanning
        if !self.output_dir.exists() {
            return Ok(0);
        }

        let mut entries = match tokio::fs::read_dir(&self.output_dir).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Warning: Could not scan for orphans: {}", e);
                return Ok(0);
            }
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            // Remove .tmpss files (SlingShot temp files from interrupted transfers)
            if name.ends_with(".tmpss") {
                if tokio::fs::remove_file(&path).await.is_ok() {
                    println!("[CLEANUP] Removed orphan: {}", name);
                    cleaned += 1;
                }
            }
        }

        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_valid_filename() {
        assert_eq!(
            sanitize_filename("2024-12-01_15-30-00.mp4").unwrap(),
            "2024-12-01_15-30-00.mp4"
        );
    }

    #[test]
    fn test_sanitize_valid_encrypted_filename() {
        assert_eq!(
            sanitize_filename("2024-12-01_15-30-00.mp4.enc").unwrap(),
            "2024-12-01_15-30-00.mp4.enc"
        );
    }

    #[test]
    fn test_sanitize_rejects_path_traversal() {
        assert!(sanitize_filename("../../../etc/passwd").is_err());
        assert!(sanitize_filename("..\\..\\windows\\system32").is_err());
        assert!(sanitize_filename("foo/../bar.mp4").is_err());
    }

    #[test]
    fn test_sanitize_rejects_absolute_paths() {
        assert!(sanitize_filename("/etc/passwd").is_err());
        assert!(sanitize_filename("/tmp/evil.mp4").is_err());
    }

    #[test]
    fn test_sanitize_rejects_directory_paths() {
        assert!(sanitize_filename("subdir/file.mp4").is_err());
        assert!(sanitize_filename("a/b/c.mp4").is_err());
    }

    #[test]
    fn test_sanitize_rejects_wrong_extension() {
        assert!(sanitize_filename("file.txt").is_err());
        assert!(sanitize_filename("file.sh").is_err());
        assert!(sanitize_filename("authorized_keys").is_err());
    }

    #[test]
    fn test_sanitize_rejects_special_characters() {
        assert!(sanitize_filename("file;rm -rf.mp4").is_err());
        assert!(sanitize_filename("file$(cmd).mp4").is_err());
        assert!(sanitize_filename("file`id`.mp4").is_err());
    }
}
