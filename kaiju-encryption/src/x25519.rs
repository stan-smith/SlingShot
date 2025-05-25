//! X25519 key exchange utilities

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::EncryptionError;

/// X25519 key length in bytes
pub const X25519_KEY_LEN: usize = 32;
/// X25519 key length as hex string
pub const X25519_HEX_LEN: usize = 64;

/// X25519 keypair for encryption
#[derive(Clone)]
pub struct X25519KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random X25519 keypair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create keypair from existing secret key bytes
    pub fn from_secret_bytes(secret_bytes: [u8; X25519_KEY_LEN]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create keypair from hex-encoded secret key
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, EncryptionError> {
        let bytes = hex::decode(secret_hex)?;
        let secret_bytes: [u8; X25519_KEY_LEN] = bytes.try_into().map_err(|v: Vec<u8>| {
            EncryptionError::InvalidKeyLength {
                expected: X25519_KEY_LEN,
                actual: v.len(),
            }
        })?;
        Ok(Self::from_secret_bytes(secret_bytes))
    }

    /// Get the secret key as bytes
    pub fn secret_bytes(&self) -> [u8; X25519_KEY_LEN] {
        self.secret.to_bytes()
    }

    /// Get the secret key as hex string
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret.to_bytes())
    }

    /// Get the public key as bytes
    pub fn public_bytes(&self) -> [u8; X25519_KEY_LEN] {
        self.public.to_bytes()
    }

    /// Get the public key as hex string
    pub fn public_hex(&self) -> String {
        hex::encode(self.public.to_bytes())
    }

    /// Get reference to the underlying StaticSecret (for Diffie-Hellman)
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    /// Get reference to the underlying PublicKey
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// Parse a public key from hex string
pub fn public_key_from_hex(hex_str: &str) -> Result<PublicKey, EncryptionError> {
    let bytes = hex::decode(hex_str)?;
    let key_bytes: [u8; X25519_KEY_LEN] = bytes.try_into().map_err(|v: Vec<u8>| {
        EncryptionError::InvalidKeyLength {
            expected: X25519_KEY_LEN,
            actual: v.len(),
        }
    })?;
    Ok(PublicKey::from(key_bytes))
}

/// Encode a public key to hex string
pub fn public_key_to_hex(key: &PublicKey) -> String {
    hex::encode(key.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = X25519KeyPair::generate();
        assert_eq!(kp.secret_bytes().len(), X25519_KEY_LEN);
        assert_eq!(kp.public_bytes().len(), X25519_KEY_LEN);
        assert_eq!(kp.secret_hex().len(), X25519_HEX_LEN);
        assert_eq!(kp.public_hex().len(), X25519_HEX_LEN);
    }

    #[test]
    fn test_roundtrip_from_secret() {
        let kp1 = X25519KeyPair::generate();
        let kp2 = X25519KeyPair::from_secret_hex(&kp1.secret_hex()).unwrap();
        assert_eq!(kp1.public_hex(), kp2.public_hex());
    }

    #[test]
    fn test_public_key_from_hex() {
        let kp = X25519KeyPair::generate();
        let pubkey = public_key_from_hex(&kp.public_hex()).unwrap();
        assert_eq!(pubkey.to_bytes(), kp.public_bytes());
    }
}
