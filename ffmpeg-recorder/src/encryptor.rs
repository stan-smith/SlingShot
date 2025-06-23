//! Segment encryption for recordings
//!
//! Monitors the output directory for completed segments and encrypts them.
//! Uses hybrid encryption (X25519 + AES-256-GCM) via kaiju-encryption.

use kaiju_encryption::{seal_with_hex_key, EncryptionError};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Extension for encrypted files
pub const ENCRYPTED_EXT: &str = "enc";

/// Segment encryptor that watches for new files and encrypts them
pub struct SegmentEncryptor {
    /// Directory to watch
    output_dir: PathBuf,
    /// File format to watch for (e.g., "mp4")
    file_format: String,
    /// Encryption public key (hex-encoded)
    pubkey_hex: String,
    /// Set of files we've already seen (to detect new completions)
    known_files: HashSet<PathBuf>,
    /// File currently being written by ffmpeg (last seen, not yet stable)
    current_file: Option<(PathBuf, u64)>, // (path, size)
}

impl SegmentEncryptor {
    /// Create a new segment encryptor
    pub fn new(output_dir: PathBuf, file_format: String, pubkey_hex: String) -> Self {
        Self {
            output_dir,
            file_format,
            pubkey_hex,
            known_files: HashSet::new(),
            current_file: None,
        }
    }

    /// Scan for existing files (call once at startup to avoid encrypting old files)
    /// Also cleans up orphaned plaintext files that have corresponding .enc files
    /// and incomplete .enc.tmp files from interrupted encryption.
    pub fn scan_existing(&mut self) -> Result<(), EncryptorError> {
        // First pass: collect all files and identify encrypted ones
        let mut encrypted_stems: HashSet<PathBuf> = HashSet::new();
        let mut plaintext_files: Vec<PathBuf> = Vec::new();
        let mut temp_files: Vec<PathBuf> = Vec::new();

        for entry in fs::read_dir(&self.output_dir)? {
            let entry = entry?;
            let path = entry.path();
            let path_str = path.to_string_lossy();

            // Check for temp files from interrupted encryption
            if path_str.ends_with(".enc.tmp") {
                temp_files.push(path);
                continue;
            }

            // Check for encrypted files
            if path.extension().map(|e| e == ENCRYPTED_EXT).unwrap_or(false) {
                // Get the original stem (e.g., "file.mp4" from "file.mp4.enc")
                let original = path.with_extension("");
                encrypted_stems.insert(original.clone());
                self.known_files.insert(original);
                continue;
            }

            // Check for plaintext recording files
            if path.extension().map(|e| e == self.file_format.as_str()).unwrap_or(false) {
                plaintext_files.push(path);
            }
        }

        // Clean up temp files from interrupted encryption
        for temp_path in temp_files {
            eprintln!(
                "[CLEANUP] Removing incomplete temp file: {}",
                temp_path.display()
            );
            if let Err(e) = fs::remove_file(&temp_path) {
                eprintln!("Warning: Failed to remove temp file {}: {}", temp_path.display(), e);
            }
        }

        // Process plaintext files
        for path in plaintext_files {
            if encrypted_stems.contains(&path) {
                // Orphaned plaintext - encrypted version exists, delete the plaintext
                eprintln!(
                    "[CLEANUP] Removing orphaned plaintext (encrypted version exists): {}",
                    path.display()
                );
                if let Err(e) = fs::remove_file(&path) {
                    eprintln!("Warning: Failed to remove orphaned file {}: {}", path.display(), e);
                }
            }
            // Track all plaintext files (even if we just deleted them, to prevent re-processing)
            self.known_files.insert(path);
        }

        Ok(())
    }

    /// Check for completed segments and encrypt them.
    /// A segment is considered complete when a new segment starts
    /// (ffmpeg closes the old file before opening the new one).
    ///
    /// Returns the number of files encrypted.
    pub fn process_completed(&mut self) -> Result<usize, EncryptorError> {
        let mut encrypted_count = 0;

        // List current unencrypted files
        let mut current_files: Vec<(PathBuf, u64)> = Vec::new();
        for entry in fs::read_dir(&self.output_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == self.file_format.as_str()).unwrap_or(false) {
                let metadata = entry.metadata()?;
                current_files.push((path, metadata.len()));
            }
        }

        // Sort by filename (oldest first based on timestamp in name)
        // Files are named like: 2024-12-01_15-30-00.mp4
        current_files.sort_by(|(a, _), (b, _)| a.cmp(b));

        // If we have more than one file, all but the last are complete
        if current_files.len() > 1 {
            // All except the last file are complete and should be encrypted
            for (path, _size) in current_files.iter().take(current_files.len() - 1) {
                if !self.known_files.contains(path) {
                    match self.encrypt_file(path) {
                        Ok(()) => {
                            self.known_files.insert(path.clone());
                            encrypted_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to encrypt {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        // Track the current (in-progress) file
        if let Some((path, size)) = current_files.last() {
            self.current_file = Some((path.clone(), *size));
        }

        Ok(encrypted_count)
    }

    /// Encrypt a single file and delete the original.
    /// Uses atomic write pattern: write to temp file, verify, rename, then delete original.
    /// If deletion fails, the orphaned plaintext will be cleaned up on next scan_existing().
    fn encrypt_file(&self, path: &Path) -> Result<(), EncryptorError> {
        // Read plaintext
        let plaintext = fs::read(path)?;
        let plaintext_len = plaintext.len();

        // Encrypt
        let ciphertext = seal_with_hex_key(&plaintext, &self.pubkey_hex)?;
        let ciphertext_len = ciphertext.len();

        // Write to temp file first (atomic write pattern)
        let encrypted_path = PathBuf::from(format!("{}.{}", path.display(), ENCRYPTED_EXT));
        let temp_path = PathBuf::from(format!("{}.{}.tmp", path.display(), ENCRYPTED_EXT));

        fs::write(&temp_path, &ciphertext)?;

        // Verify temp file was written correctly
        let written_size = fs::metadata(&temp_path)?.len();
        if written_size != ciphertext_len as u64 {
            // Clean up failed temp file
            let _ = fs::remove_file(&temp_path);
            return Err(EncryptorError::VerificationFailed(
                "encrypted file size mismatch".into(),
            ));
        }

        // Atomic rename: temp -> final (atomic on POSIX when same filesystem)
        fs::rename(&temp_path, &encrypted_path)?;

        // Now safe to delete original.
        // If this fails, the file will be cleaned up on next scan_existing()
        // since the .enc file now exists.
        if let Err(e) = fs::remove_file(path) {
            eprintln!(
                "Warning: Failed to delete original {} after encryption: {}. Will be cleaned up on restart.",
                path.display(),
                e
            );
        }

        println!(
            "Encrypted: {} ({} bytes) -> {} ({} bytes)",
            path.display(),
            plaintext_len,
            encrypted_path.display(),
            ciphertext_len
        );

        Ok(())
    }

    /// Encrypt any remaining unencrypted files (call on shutdown)
    pub fn finalize(&mut self) -> Result<usize, EncryptorError> {
        let mut encrypted_count = 0;

        for entry in fs::read_dir(&self.output_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == self.file_format.as_str()).unwrap_or(false) {
                if !self.known_files.contains(&path) {
                    match self.encrypt_file(&path) {
                        Ok(()) => {
                            self.known_files.insert(path);
                            encrypted_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to encrypt {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(encrypted_count)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaiju_encryption::{open_with_hex_key, X25519KeyPair};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_file_roundtrip() {
        let dir = tempdir().unwrap();
        let keypair = X25519KeyPair::generate();

        // Create a test "recording"
        let test_file = dir.path().join("2024-01-01_12-00-00.mp4");
        let test_data = b"fake video content for testing";
        fs::write(&test_file, test_data).unwrap();

        // Create encryptor and process
        let mut encryptor = SegmentEncryptor::new(
            dir.path().to_path_buf(),
            "mp4".to_string(),
            keypair.public_hex(),
        );

        // Simulate a second file being written (so first is "complete")
        let current_file = dir.path().join("2024-01-01_12-00-30.mp4");
        fs::write(&current_file, b"current file").unwrap();

        let count = encryptor.process_completed().unwrap();
        assert_eq!(count, 1);

        // Original should be deleted
        assert!(!test_file.exists());

        // Encrypted file should exist
        let encrypted_file = dir.path().join("2024-01-01_12-00-00.mp4.enc");
        assert!(encrypted_file.exists());

        // Decrypt and verify
        let ciphertext = fs::read(&encrypted_file).unwrap();
        let decrypted = open_with_hex_key(&ciphertext, &keypair.secret_hex()).unwrap();
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_finalize_encrypts_remaining() {
        let dir = tempdir().unwrap();
        let keypair = X25519KeyPair::generate();

        // Create a test "recording"
        let test_file = dir.path().join("final-segment.mp4");
        fs::write(&test_file, b"final segment data").unwrap();

        let mut encryptor = SegmentEncryptor::new(
            dir.path().to_path_buf(),
            "mp4".to_string(),
            keypair.public_hex(),
        );

        // Finalize should encrypt even single files
        let count = encryptor.finalize().unwrap();
        assert_eq!(count, 1);

        assert!(!test_file.exists());
        assert!(dir.path().join("final-segment.mp4.enc").exists());
    }

    #[test]
    fn test_scan_existing_cleans_orphaned_plaintext() {
        let dir = tempdir().unwrap();
        let keypair = X25519KeyPair::generate();

        // Simulate crash scenario: both .mp4 and .mp4.enc exist
        let plaintext_file = dir.path().join("orphan.mp4");
        let encrypted_file = dir.path().join("orphan.mp4.enc");
        fs::write(&plaintext_file, b"orphaned plaintext").unwrap();
        fs::write(&encrypted_file, b"encrypted data").unwrap();

        let mut encryptor = SegmentEncryptor::new(
            dir.path().to_path_buf(),
            "mp4".to_string(),
            keypair.public_hex(),
        );

        // scan_existing should clean up the orphaned plaintext
        encryptor.scan_existing().unwrap();

        // Plaintext should be deleted, encrypted should remain
        assert!(!plaintext_file.exists(), "Orphaned plaintext should be deleted");
        assert!(encrypted_file.exists(), "Encrypted file should remain");
    }

    #[test]
    fn test_scan_existing_cleans_temp_files() {
        let dir = tempdir().unwrap();
        let keypair = X25519KeyPair::generate();

        // Simulate interrupted encryption: .enc.tmp file exists
        let temp_file = dir.path().join("interrupted.mp4.enc.tmp");
        fs::write(&temp_file, b"incomplete encryption").unwrap();

        let mut encryptor = SegmentEncryptor::new(
            dir.path().to_path_buf(),
            "mp4".to_string(),
            keypair.public_hex(),
        );

        encryptor.scan_existing().unwrap();

        // Temp file should be cleaned up
        assert!(!temp_file.exists(), "Temp file should be deleted");
    }

    #[test]
    fn test_scan_existing_preserves_unencrypted_without_pair() {
        let dir = tempdir().unwrap();
        let keypair = X25519KeyPair::generate();

        // Normal unencrypted file (no .enc pair)
        let plaintext_file = dir.path().join("normal.mp4");
        fs::write(&plaintext_file, b"normal recording").unwrap();

        let mut encryptor = SegmentEncryptor::new(
            dir.path().to_path_buf(),
            "mp4".to_string(),
            keypair.public_hex(),
        );

        encryptor.scan_existing().unwrap();

        // Should NOT be deleted (no encrypted version exists)
        assert!(plaintext_file.exists(), "Normal plaintext should be preserved");
    }
}
