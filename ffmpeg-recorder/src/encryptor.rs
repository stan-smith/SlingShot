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
    pub fn scan_existing(&mut self) -> Result<(), EncryptorError> {
        for entry in fs::read_dir(&self.output_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == self.file_format.as_str()).unwrap_or(false) {
                self.known_files.insert(path);
            }
        }
        // Also track existing encrypted files
        for entry in fs::read_dir(&self.output_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == ENCRYPTED_EXT).unwrap_or(false) {
                // Track the original name so we don't try to re-encrypt
                let original = path.with_extension("");
                self.known_files.insert(original);
            }
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

    /// Encrypt a single file and delete the original
    fn encrypt_file(&self, path: &Path) -> Result<(), EncryptorError> {
        // Read plaintext
        let plaintext = fs::read(path)?;

        // Encrypt
        let ciphertext = seal_with_hex_key(&plaintext, &self.pubkey_hex)?;

        // Write encrypted file with .enc extension appended
        let encrypted_path = PathBuf::from(format!("{}.{}", path.display(), ENCRYPTED_EXT));
        fs::write(&encrypted_path, &ciphertext)?;

        // Verify encrypted file was written
        let written_size = fs::metadata(&encrypted_path)?.len();
        if written_size != ciphertext.len() as u64 {
            fs::remove_file(&encrypted_path)?;
            return Err(EncryptorError::VerificationFailed(
                "encrypted file size mismatch".into(),
            ));
        }

        // Delete original
        fs::remove_file(path)?;

        println!(
            "Encrypted: {} ({} bytes) -> {} ({} bytes)",
            path.display(),
            plaintext.len(),
            encrypted_path.display(),
            ciphertext.len()
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
}
