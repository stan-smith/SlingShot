//! Command authentication using Ed25519 signatures
//!
//! Signs commands from central with timestamp for replay protection.
//! Remote verifies signature before executing commands.

use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum age of a command before it's considered expired (30 seconds)
const MAX_COMMAND_AGE_MS: u64 = 30_000;

/// Errors that can occur during command authentication
#[derive(Debug)]
pub enum CommandAuthError {
    /// Message doesn't match expected CMD|timestamp|command|signature format
    InvalidFormat,
    /// Timestamp couldn't be parsed
    InvalidTimestamp,
    /// Command is too old (replay protection)
    Expired,
    /// Signature hex couldn't be decoded or is wrong length
    InvalidSignature,
    /// Signature verification failed
    VerificationFailed,
}

impl std::fmt::Display for CommandAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid command format"),
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::Expired => write!(f, "command expired"),
            Self::InvalidSignature => write!(f, "invalid signature encoding"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for CommandAuthError {}

/// Sign a command with the central's signing key
///
/// Returns: `CMD|<timestamp_ms>|<command>|<signature_hex>`
///
/// The signature covers `timestamp|command` (pipe-separated).
pub fn sign_command(signing_key: &SigningKey, command: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let message = format!("{}|{}", timestamp, command);
    let signature = signing_key.sign(message.as_bytes());

    format!(
        "CMD|{}|{}|{}",
        timestamp,
        command,
        hex::encode(signature.to_bytes())
    )
}

/// Verify a signed command and extract the command if valid
///
/// Input format: `CMD|<timestamp_ms>|<command>|<signature_hex>`
///
/// Returns the command string if verification succeeds.
pub fn verify_command(
    verifying_key: &VerifyingKey,
    signed_message: &str,
) -> Result<String, CommandAuthError> {
    // Parse: CMD|timestamp|command|signature
    let parts: Vec<&str> = signed_message.splitn(4, '|').collect();
    if parts.len() != 4 || parts[0] != "CMD" {
        return Err(CommandAuthError::InvalidFormat);
    }

    let timestamp: u64 = parts[1]
        .parse()
        .map_err(|_| CommandAuthError::InvalidTimestamp)?;
    let command = parts[2];
    let sig_hex = parts[3];

    // Replay protection: reject commands older than MAX_COMMAND_AGE_MS
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    if now.saturating_sub(timestamp) > MAX_COMMAND_AGE_MS {
        return Err(CommandAuthError::Expired);
    }

    // Decode and verify signature
    let sig_bytes = hex::decode(sig_hex).map_err(|_| CommandAuthError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| CommandAuthError::InvalidSignature)?;

    let message = format!("{}|{}", timestamp, command);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| CommandAuthError::VerificationFailed)?;

    Ok(command.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = VerifyingKey::from(&signing_key);
        (signing_key, verifying_key)
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = test_keypair();
        let command = "resolution 1920 1080";

        let signed = sign_command(&signing_key, command);
        assert!(signed.starts_with("CMD|"));

        let verified = verify_command(&verifying_key, &signed).unwrap();
        assert_eq!(verified, command);
    }

    #[test]
    fn test_invalid_format() {
        let (_, verifying_key) = test_keypair();

        // Missing CMD prefix
        let err = verify_command(&verifying_key, "1234|test|sig").unwrap_err();
        assert!(matches!(err, CommandAuthError::InvalidFormat));

        // Too few parts
        let err = verify_command(&verifying_key, "CMD|1234|test").unwrap_err();
        assert!(matches!(err, CommandAuthError::InvalidFormat));
    }

    #[test]
    fn test_invalid_timestamp() {
        let (_, verifying_key) = test_keypair();

        let err = verify_command(&verifying_key, "CMD|notanumber|test|abcd").unwrap_err();
        assert!(matches!(err, CommandAuthError::InvalidTimestamp));
    }

    #[test]
    fn test_expired_command() {
        let (signing_key, verifying_key) = test_keypair();

        // Manually create an expired command (timestamp from 60 seconds ago)
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 60_000;

        let command = "test";
        let message = format!("{}|{}", old_timestamp, command);
        let signature = signing_key.sign(message.as_bytes());
        let signed = format!(
            "CMD|{}|{}|{}",
            old_timestamp,
            command,
            hex::encode(signature.to_bytes())
        );

        let err = verify_command(&verifying_key, &signed).unwrap_err();
        assert!(matches!(err, CommandAuthError::Expired));
    }

    #[test]
    fn test_invalid_signature() {
        let (_, verifying_key) = test_keypair();

        // Use a fresh timestamp so we don't hit expiration first
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Valid format but garbage signature
        let msg = format!("CMD|{}|test|notvalidhex", now);
        let err = verify_command(&verifying_key, &msg).unwrap_err();
        assert!(matches!(err, CommandAuthError::InvalidSignature));

        // Valid hex but wrong length
        let msg = format!("CMD|{}|test|abcd1234", now);
        let err = verify_command(&verifying_key, &msg).unwrap_err();
        assert!(matches!(err, CommandAuthError::InvalidSignature));
    }

    #[test]
    fn test_wrong_key_verification_fails() {
        let (signing_key, _) = test_keypair();

        // Create a different keypair
        let other_secret: [u8; 32] = [0xff; 32];
        let other_signing = SigningKey::from_bytes(&other_secret);
        let other_verifying = VerifyingKey::from(&other_signing);

        let signed = sign_command(&signing_key, "test");

        // Verification with wrong key should fail
        let err = verify_command(&other_verifying, &signed).unwrap_err();
        assert!(matches!(err, CommandAuthError::VerificationFailed));
    }

    #[test]
    fn test_tampered_command() {
        let (signing_key, verifying_key) = test_keypair();

        let signed = sign_command(&signing_key, "safe command");

        // Tamper with the command portion
        let tampered = signed.replace("safe command", "evil command");

        let err = verify_command(&verifying_key, &tampered).unwrap_err();
        assert!(matches!(err, CommandAuthError::VerificationFailed));
    }
}
