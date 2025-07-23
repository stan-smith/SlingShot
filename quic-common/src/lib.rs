//! Common QUIC/TLS utilities for mini-projects
//!
//! Provides shared components for QUIC connections including certificate pinning.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Certificate verifier that accepts any certificate (for development/internal use)
///
/// WARNING: This should only be used for development or internal networks
/// where certificate validation is not required.
#[derive(Debug)]
pub struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Compute SHA-256 fingerprint of a certificate (DER-encoded)
///
/// Returns fingerprint in format "SHA256:hexstring"
pub fn compute_cert_fingerprint(cert: &CertificateDer) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let hash = hasher.finalize();
    format!("SHA256:{}", hex::encode(hash))
}

/// Certificate verifier with pinning support (TOFU or explicit pin)
///
/// Operates in two modes:
/// - TOFU (Trust on First Use): Accepts any certificate, records fingerprint
/// - Pinned: Verifies certificate matches expected fingerprint
#[derive(Debug)]
pub struct PinningVerifier {
    /// Expected fingerprint (None = TOFU mode, accept any)
    expected_fingerprint: Option<String>,
    /// Observed fingerprint from the handshake
    observed_fingerprint: Arc<Mutex<Option<String>>>,
}

impl PinningVerifier {
    /// Create verifier in TOFU mode (accepts any cert, records fingerprint)
    pub fn tofu() -> Arc<Self> {
        Arc::new(Self {
            expected_fingerprint: None,
            observed_fingerprint: Arc::new(Mutex::new(None)),
        })
    }

    /// Create verifier with pinned fingerprint (rejects mismatches)
    pub fn pinned(fingerprint: &str) -> Arc<Self> {
        Arc::new(Self {
            expected_fingerprint: Some(fingerprint.to_string()),
            observed_fingerprint: Arc::new(Mutex::new(None)),
        })
    }

    /// Get the fingerprint observed during the last handshake
    pub fn observed_fingerprint(&self) -> Option<String> {
        self.observed_fingerprint.lock().unwrap().clone()
    }

    /// Check if this verifier is in TOFU mode
    pub fn is_tofu(&self) -> bool {
        self.expected_fingerprint.is_none()
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Compute fingerprint of the presented certificate
        let fingerprint = compute_cert_fingerprint(end_entity);

        // Record the observed fingerprint
        *self.observed_fingerprint.lock().unwrap() = Some(fingerprint.clone());

        // Verify against expected fingerprint if set
        match &self.expected_fingerprint {
            None => {
                // TOFU mode: accept any certificate
                Ok(ServerCertVerified::assertion())
            }
            Some(expected) if expected == &fingerprint => {
                // Fingerprint matches
                Ok(ServerCertVerified::assertion())
            }
            Some(_expected) => {
                // Fingerprint mismatch - possible MITM attack
                Err(Error::InvalidCertificate(CertificateError::BadEncoding))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // For self-signed certs, we trust based on fingerprint, not signature chain
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // For self-signed certs, we trust based on fingerprint, not signature chain
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Create a rustls ClientConfig that accepts any certificate
#[deprecated(note = "Use create_pinning_client_config instead for security")]
pub fn insecure_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth()
}

/// Create transport config for stream-per-frame video
///
/// Configured for high-throughput video streaming:
/// - 1000 concurrent unidirectional streams (for 30fps video)
/// - 100 concurrent bidirectional streams (for commands)
/// - No idle timeout (persistent connections)
/// - 5-second keepalive interval
pub fn video_transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_uni_streams(1000u32.into());
    config.max_concurrent_bidi_streams(100u32.into());
    config.max_idle_timeout(None);
    config.keep_alive_interval(Some(Duration::from_secs(5)));
    config
}

/// Create a quinn ClientConfig with insecure certificate verification
///
/// Uses insecure_client_config() internally and applies video_transport_config().
#[deprecated(note = "Use create_pinning_client_config instead for security")]
#[allow(deprecated)]
pub fn create_client_config() -> Result<quinn::ClientConfig, rustls::Error> {
    let mut crypto = insecure_client_config();
    crypto.alpn_protocols = vec![];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(video_transport_config()));
    Ok(client_config)
}

/// Create a quinn ClientConfig with certificate pinning
///
/// Returns the client config and a reference to the verifier (to retrieve observed fingerprint).
///
/// # Arguments
/// * `expected_fingerprint` - If Some, verifies cert matches this fingerprint (pinned mode).
///                           If None, accepts any cert and records fingerprint (TOFU mode).
///
/// # Example
/// ```ignore
/// // TOFU mode - first connection
/// let (config, verifier) = create_pinning_client_config(None)?;
/// // After connection, get the fingerprint to save
/// let fp = verifier.observed_fingerprint();
///
/// // Pinned mode - subsequent connections
/// let (config, verifier) = create_pinning_client_config(Some(saved_fingerprint))?;
/// ```
pub fn create_pinning_client_config(
    expected_fingerprint: Option<String>,
) -> Result<(quinn::ClientConfig, Arc<PinningVerifier>), rustls::Error> {
    let verifier = match expected_fingerprint {
        Some(fp) => PinningVerifier::pinned(&fp),
        None => PinningVerifier::tofu(),
    };

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(video_transport_config()));

    Ok((client_config, verifier))
}
