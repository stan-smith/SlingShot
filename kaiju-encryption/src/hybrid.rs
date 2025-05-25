//! Hybrid encryption using X25519 + AES-256-GCM
//!
//! Implements a sealed-box style encryption scheme:
//! - Sender generates ephemeral X25519 keypair
//! - Derives shared secret via ECDH with recipient's public key
//! - Derives AES key via HKDF-SHA256
//! - Encrypts data with AES-256-GCM
//!
//! File format: [ephemeral_pubkey:32][nonce:12][ciphertext][tag:16]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::EncryptionError;
use crate::x25519::{X25519KeyPair, X25519_KEY_LEN};

/// Size of the ephemeral public key prefix
pub const EPHEMERAL_KEY_LEN: usize = X25519_KEY_LEN; // 32 bytes
/// Size of the AES-GCM nonce
pub const NONCE_LEN: usize = 12;
/// Size of the AES-GCM authentication tag
pub const TAG_LEN: usize = 16;
/// Minimum ciphertext size (ephemeral key + nonce + tag, no plaintext)
pub const MIN_CIPHERTEXT_LEN: usize = EPHEMERAL_KEY_LEN + NONCE_LEN + TAG_LEN;

/// HKDF info string for key derivation
const HKDF_INFO: &[u8] = b"kaiju-recording-encryption";

/// Derive an AES-256 key from a shared secret using HKDF-SHA256
fn derive_aes_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut aes_key)
        .expect("HKDF expand should not fail with valid length");
    aes_key
}

/// Seal (encrypt) data for a recipient using their public key.
///
/// This is a "sealed box" style encryption:
/// 1. Generates an ephemeral X25519 keypair
/// 2. Computes shared secret: ephemeral_secret × recipient_pubkey
/// 3. Derives AES-256 key via HKDF-SHA256
/// 4. Encrypts with AES-256-GCM using random nonce
///
/// Returns: `[ephemeral_pubkey:32][nonce:12][ciphertext][tag:16]`
pub fn seal(plaintext: &[u8], recipient_pubkey: &PublicKey) -> Result<Vec<u8>, EncryptionError> {
    // Generate ephemeral keypair
    let ephemeral = X25519KeyPair::generate();

    // Compute shared secret via ECDH
    let shared_secret = ephemeral.secret().diffie_hellman(recipient_pubkey);

    // Derive AES key
    let aes_key = derive_aes_key(shared_secret.as_bytes());

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // Build output: ephemeral_pubkey || nonce || ciphertext (includes tag)
    let mut output = Vec::with_capacity(EPHEMERAL_KEY_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&ephemeral.public_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Open (decrypt) sealed data using the recipient's secret key.
///
/// Expects input format: `[ephemeral_pubkey:32][nonce:12][ciphertext][tag:16]`
///
/// 1. Extracts ephemeral public key from ciphertext
/// 2. Computes shared secret: recipient_secret × ephemeral_pubkey
/// 3. Derives AES-256 key via HKDF-SHA256
/// 4. Decrypts with AES-256-GCM
pub fn open(ciphertext: &[u8], recipient_secret: &StaticSecret) -> Result<Vec<u8>, EncryptionError> {
    // Validate minimum length
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(EncryptionError::InvalidCiphertext(format!(
            "ciphertext too short: {} bytes (minimum {})",
            ciphertext.len(),
            MIN_CIPHERTEXT_LEN
        )));
    }

    // Extract components
    let ephemeral_pubkey_bytes: [u8; EPHEMERAL_KEY_LEN] = ciphertext[..EPHEMERAL_KEY_LEN]
        .try_into()
        .map_err(|_| EncryptionError::InvalidCiphertext("invalid ephemeral key".into()))?;

    let nonce_bytes: [u8; NONCE_LEN] = ciphertext[EPHEMERAL_KEY_LEN..EPHEMERAL_KEY_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| EncryptionError::InvalidCiphertext("invalid nonce".into()))?;

    let encrypted_data = &ciphertext[EPHEMERAL_KEY_LEN + NONCE_LEN..];

    // Reconstruct ephemeral public key
    let ephemeral_pubkey = PublicKey::from(ephemeral_pubkey_bytes);

    // Compute shared secret via ECDH
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_pubkey);

    // Derive AES key
    let aes_key = derive_aes_key(shared_secret.as_bytes());

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| EncryptionError::DecryptionFailed("authentication failed".into()))?;

    Ok(plaintext)
}

/// Convenience function to seal data using a hex-encoded public key
pub fn seal_with_hex_key(plaintext: &[u8], pubkey_hex: &str) -> Result<Vec<u8>, EncryptionError> {
    let pubkey = crate::x25519::public_key_from_hex(pubkey_hex)?;
    seal(plaintext, &pubkey)
}

/// Convenience function to open data using a hex-encoded secret key
pub fn open_with_hex_key(ciphertext: &[u8], secret_hex: &str) -> Result<Vec<u8>, EncryptionError> {
    let keypair = X25519KeyPair::from_secret_hex(secret_hex)?;
    open(ciphertext, keypair.secret())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let recipient = X25519KeyPair::generate();
        let plaintext = b"Hello, encrypted world!";

        let ciphertext = seal(plaintext, recipient.public()).unwrap();

        // Verify ciphertext structure
        assert!(ciphertext.len() >= MIN_CIPHERTEXT_LEN);
        assert_eq!(
            ciphertext.len(),
            EPHEMERAL_KEY_LEN + NONCE_LEN + plaintext.len() + TAG_LEN
        );

        let decrypted = open(&ciphertext, recipient.secret()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_seal_open_large_data() {
        let recipient = X25519KeyPair::generate();
        // Simulate a small video segment (1MB)
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

        let ciphertext = seal(&plaintext, recipient.public()).unwrap();
        let decrypted = open(&ciphertext, recipient.secret()).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_seal_open_empty_data() {
        let recipient = X25519KeyPair::generate();
        let plaintext = b"";

        let ciphertext = seal(plaintext, recipient.public()).unwrap();
        assert_eq!(ciphertext.len(), MIN_CIPHERTEXT_LEN);

        let decrypted = open(&ciphertext, recipient.secret()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let recipient = X25519KeyPair::generate();
        let wrong_recipient = X25519KeyPair::generate();
        let plaintext = b"Secret message";

        let ciphertext = seal(plaintext, recipient.public()).unwrap();

        // Trying to decrypt with wrong key should fail
        let result = open(&ciphertext, wrong_recipient.secret());
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let recipient = X25519KeyPair::generate();
        let plaintext = b"Secret message";

        let mut ciphertext = seal(plaintext, recipient.public()).unwrap();

        // Tamper with the ciphertext
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        // Decryption should fail due to authentication
        let result = open(&ciphertext, recipient.secret());
        assert!(result.is_err());
    }

    #[test]
    fn test_short_ciphertext_fails() {
        let recipient = X25519KeyPair::generate();
        let short_data = vec![0u8; MIN_CIPHERTEXT_LEN - 1];

        let result = open(&short_data, recipient.secret());
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_key_convenience() {
        let recipient = X25519KeyPair::generate();
        let plaintext = b"Test with hex keys";

        let ciphertext = seal_with_hex_key(plaintext, &recipient.public_hex()).unwrap();
        let decrypted = open_with_hex_key(&ciphertext, &recipient.secret_hex()).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_each_time() {
        let recipient = X25519KeyPair::generate();
        let plaintext = b"Same plaintext";

        let ct1 = seal(plaintext, recipient.public()).unwrap();
        let ct2 = seal(plaintext, recipient.public()).unwrap();

        // Ciphertexts should be different (different ephemeral keys and nonces)
        assert_ne!(ct1, ct2);

        // But both should decrypt to same plaintext
        assert_eq!(open(&ct1, recipient.secret()).unwrap(), plaintext);
        assert_eq!(open(&ct2, recipient.secret()).unwrap(), plaintext);
    }
}
