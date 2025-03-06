//! Device authentication using Ed25519 fingerprints
//!
//! Provides Ed25519-based device identity for QUIC connections.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;

/// Device identity with Ed25519 keypair
pub struct DeviceIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    fingerprint: String,
}

impl DeviceIdentity {
    /// Generate a new random device identity
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        Self::from_secret(secret_bytes)
    }

    /// Create identity from existing secret bytes
    pub fn from_secret(secret_bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let fingerprint = hex::encode(verifying_key.as_bytes());

        Self {
            signing_key,
            verifying_key,
            fingerprint,
        }
    }

    /// Get the full fingerprint (64 hex chars)
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Get shortened fingerprint for display (first 16 chars)
    pub fn fingerprint_short(&self) -> &str {
        &self.fingerprint[..16]
    }

    /// Get the signing key (for future signing operations)
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the verifying key (public key)
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the secret bytes (for persistence)
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = DeviceIdentity::generate();
        assert_eq!(id.fingerprint().len(), 64);
        assert_eq!(id.fingerprint_short().len(), 16);
    }

    #[test]
    fn test_deterministic_from_secret() {
        let secret = [42u8; 32];
        let id1 = DeviceIdentity::from_secret(secret);
        let id2 = DeviceIdentity::from_secret(secret);
        assert_eq!(id1.fingerprint(), id2.fingerprint());
    }
}
