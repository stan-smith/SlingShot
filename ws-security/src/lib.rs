//! WS-Security UsernameToken authentication
//!
//! Implements the OASIS WS-Security UsernameToken Profile 1.1 for ONVIF authentication.
//!
//! # Example
//!
//! ```rust,ignore
//! use ws_security::{authenticate, Credentials};
//!
//! let credentials = Credentials {
//!     username: "onvif".to_string(),
//!     password: "secret".to_string(),
//! };
//!
//! // Authenticate a SOAP request
//! match authenticate(soap_xml, &credentials, 300) {
//!     Ok(()) => println!("Authenticated!"),
//!     Err(e) => println!("Auth failed: {}", e),
//! }
//! ```

mod digest;
mod error;
mod parse;

pub use error::WsSecurityError;
pub use parse::UsernameToken;

use chrono::{DateTime, Utc};

/// Credentials for validating WS-Security tokens
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Extract UsernameToken from SOAP XML
///
/// Parses the SOAP envelope and extracts the Security/UsernameToken element.
pub fn extract_token(xml: &str) -> Result<UsernameToken, WsSecurityError> {
    parse::parse_username_token(xml)
}

/// Validate a UsernameToken against credentials
///
/// Checks:
/// 1. Username matches
/// 2. Password digest is correct
/// 3. Timestamp is not expired
///
/// # Arguments
/// * `token` - The parsed UsernameToken
/// * `credentials` - Expected username and password
/// * `max_age_secs` - Maximum age of request in seconds (typically 300 = 5 minutes)
pub fn validate_token(
    token: &UsernameToken,
    credentials: &Credentials,
    max_age_secs: u64,
) -> Result<(), WsSecurityError> {
    // Check username
    if token.username != credentials.username {
        return Err(WsSecurityError::InvalidCredentials);
    }

    // Check timestamp
    let created = DateTime::parse_from_rfc3339(&token.created)
        .map_err(|_| WsSecurityError::InvalidTimestamp)?
        .with_timezone(&Utc);

    let now = Utc::now();
    let age = now.signed_duration_since(created);

    // Reject if timestamp is in the future (with small tolerance for clock skew)
    if age.num_seconds() < -30 {
        return Err(WsSecurityError::InvalidTimestamp);
    }

    // Reject if too old
    let age_secs = age.num_seconds().max(0) as u64;
    if age_secs > max_age_secs {
        return Err(WsSecurityError::Expired {
            age_secs,
            max_secs: max_age_secs,
        });
    }

    // Compute expected digest and compare
    let expected_digest =
        digest::compute_digest(&token.nonce, &token.created, &credentials.password)?;

    if !digest::verify_digest(&token.password_digest, &expected_digest) {
        return Err(WsSecurityError::InvalidCredentials);
    }

    Ok(())
}

/// Extract and validate UsernameToken in one call
///
/// Convenience function that combines `extract_token` and `validate_token`.
///
/// # Arguments
/// * `xml` - SOAP envelope XML containing Security header
/// * `credentials` - Expected username and password
/// * `max_age_secs` - Maximum age of request in seconds
pub fn authenticate(
    xml: &str,
    credentials: &Credentials,
    max_age_secs: u64,
) -> Result<(), WsSecurityError> {
    let token = extract_token(xml)?;
    validate_token(&token, credentials, max_age_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make_soap(username: &str, password_digest: &str, nonce: &str, created: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security>
      <UsernameToken>
        <Username>{}</Username>
        <Password>{}</Password>
        <Nonce>{}</Nonce>
        <Created>{}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body><GetDeviceInformation/></s:Body>
</s:Envelope>"#,
            username, password_digest, nonce, created
        )
    }

    #[test]
    fn test_authenticate_success() {
        // Generate a fresh token
        let password = "userPassword";
        let nonce_bytes: [u8; 16] = rand_nonce();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
        let created = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let digest =
            digest::compute_digest(&nonce_b64, &created, password).expect("compute digest");

        let xml = make_soap("onvif_user", &digest, &nonce_b64, &created);

        let credentials = Credentials {
            username: "onvif_user".to_string(),
            password: password.to_string(),
        };

        assert!(authenticate(&xml, &credentials, 300).is_ok());
    }

    #[test]
    fn test_authenticate_wrong_password() {
        let password = "wrongPassword";
        let nonce_bytes: [u8; 16] = rand_nonce();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
        let created = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let digest =
            digest::compute_digest(&nonce_b64, &created, password).expect("compute digest");

        let xml = make_soap("onvif_user", &digest, &nonce_b64, &created);

        let credentials = Credentials {
            username: "onvif_user".to_string(),
            password: "correctPassword".to_string(), // Different from what was used
        };

        let result = authenticate(&xml, &credentials, 300);
        assert!(matches!(result, Err(WsSecurityError::InvalidCredentials)));
    }

    #[test]
    fn test_authenticate_wrong_username() {
        let password = "userPassword";
        let nonce_bytes: [u8; 16] = rand_nonce();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
        let created = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let digest =
            digest::compute_digest(&nonce_b64, &created, password).expect("compute digest");

        let xml = make_soap("wrong_user", &digest, &nonce_b64, &created);

        let credentials = Credentials {
            username: "onvif_user".to_string(),
            password: password.to_string(),
        };

        let result = authenticate(&xml, &credentials, 300);
        assert!(matches!(result, Err(WsSecurityError::InvalidCredentials)));
    }

    #[test]
    fn test_authenticate_expired() {
        let password = "userPassword";
        let nonce_bytes: [u8; 16] = rand_nonce();
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
        // Timestamp from 10 minutes ago
        let created = (Utc::now() - chrono::Duration::seconds(600))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let digest =
            digest::compute_digest(&nonce_b64, &created, password).expect("compute digest");

        let xml = make_soap("onvif_user", &digest, &nonce_b64, &created);

        let credentials = Credentials {
            username: "onvif_user".to_string(),
            password: password.to_string(),
        };

        // Max age 5 minutes, request is 10 minutes old
        let result = authenticate(&xml, &credentials, 300);
        assert!(matches!(result, Err(WsSecurityError::Expired { .. })));
    }

    fn rand_nonce() -> [u8; 16] {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&t.to_le_bytes()[..8]);
        bytes[8..].copy_from_slice(&(t >> 64).to_le_bytes()[..8]);
        bytes
    }
}
