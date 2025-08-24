//! WS-Security password digest computation
//!
//! Implements the OASIS WS-Security UsernameToken Profile 1.1 password digest:
//! `digest = base64(sha1(nonce + created + password))`

use base64::{engine::general_purpose::STANDARD, Engine};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;

use crate::error::WsSecurityError;

/// Compute the WS-Security password digest
///
/// Formula: `base64(sha1(nonce_bytes || created_bytes || password_bytes))`
///
/// # Arguments
/// * `nonce_b64` - Base64-encoded nonce from the UsernameToken
/// * `created` - ISO 8601 timestamp string from the UsernameToken
/// * `password` - Plaintext password to compute digest for
///
/// # Returns
/// Base64-encoded SHA1 digest
pub fn compute_digest(
    nonce_b64: &str,
    created: &str,
    password: &str,
) -> Result<String, WsSecurityError> {
    // Decode the nonce from Base64
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|_| WsSecurityError::InvalidNonce)?;

    // Concatenate: nonce || created || password
    let mut hasher = Sha1::new();
    hasher.update(&nonce_bytes);
    hasher.update(created.as_bytes());
    hasher.update(password.as_bytes());

    // Compute SHA1 hash and Base64 encode
    let hash = hasher.finalize();
    Ok(STANDARD.encode(hash))
}

/// Verify a password digest using constant-time comparison
///
/// # Arguments
/// * `expected` - The password digest from the UsernameToken
/// * `actual` - The computed digest to compare against
///
/// # Returns
/// `true` if digests match, `false` otherwise
pub fn verify_digest(expected: &str, actual: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let actual_bytes = actual.as_bytes();

    // Use constant-time comparison to prevent timing attacks
    expected_bytes.ct_eq(actual_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_digest() {
        // Test that digest computation is deterministic
        let nonce = "LKqI6G/AikKCQrN0zqZFlg==";
        let created = "2010-09-16T07:50:45.000Z";
        let password = "userPassword";

        let digest1 = compute_digest(nonce, created, password).unwrap();
        let digest2 = compute_digest(nonce, created, password).unwrap();
        assert_eq!(digest1, digest2);

        // Different password should produce different digest
        let digest3 = compute_digest(nonce, created, "differentPassword").unwrap();
        assert_ne!(digest1, digest3);
    }

    #[test]
    fn test_verify_digest_match() {
        let a = "tuOSpGlFlIXsozq4HFNeeGeFLEI=";
        let b = "tuOSpGlFlIXsozq4HFNeeGeFLEI=";
        assert!(verify_digest(a, b));
    }

    #[test]
    fn test_verify_digest_mismatch() {
        let a = "tuOSpGlFlIXsozq4HFNeeGeFLEI=";
        let b = "different_digest_value";
        assert!(!verify_digest(a, b));
    }

    #[test]
    fn test_invalid_nonce() {
        let result = compute_digest("not_valid_base64!!!", "2024-01-01T00:00:00Z", "password");
        assert!(matches!(result, Err(WsSecurityError::InvalidNonce)));
    }
}
