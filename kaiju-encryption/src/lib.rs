//! Encryption utilities for kaiju
//!
//! Provides X25519 key management and hybrid encryption for recordings.
//! Central generates unique keypairs per remote, remotes store only the public key.
//!
//! # Hybrid Encryption
//!
//! The `hybrid` module provides sealed-box style encryption:
//! - `seal()` encrypts data using recipient's public key
//! - `open()` decrypts data using recipient's secret key
//!
//! File format: `[ephemeral_pubkey:32][nonce:12][ciphertext][tag:16]`

mod error;
pub mod hybrid;
mod x25519;

pub use error::EncryptionError;
pub use hybrid::{open, open_with_hex_key, seal, seal_with_hex_key};
pub use hybrid::{EPHEMERAL_KEY_LEN, MIN_CIPHERTEXT_LEN, NONCE_LEN, TAG_LEN};
pub use x25519::{
    public_key_from_hex, public_key_to_hex, X25519KeyPair, X25519_HEX_LEN, X25519_KEY_LEN,
};
