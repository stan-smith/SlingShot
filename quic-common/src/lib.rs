//! Common QUIC/TLS utilities for mini-projects
//!
//! Provides shared components for QUIC connections.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::sync::Arc;
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

/// Create a rustls ClientConfig that accepts any certificate
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
pub fn create_client_config() -> Result<quinn::ClientConfig, rustls::Error> {
    let mut crypto = insecure_client_config();
    crypto.alpn_protocols = vec![];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(video_transport_config()));
    Ok(client_config)
}
