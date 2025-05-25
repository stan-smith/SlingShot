use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),
}
