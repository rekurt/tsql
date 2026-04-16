//! TLS/SSL configuration for database connections.
//!
//! Provides two modes:
//! - **Insecure**: Encryption without certificate validation (sslmode=require/prefer)
//! - **Verified**: Full certificate validation against Mozilla's root CA store (sslmode=verify-ca/verify-full)

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_postgres_rustls_improved::MakeRustlsConnect;
use webpki_roots::TLS_SERVER_ROOTS;

/// Certificate verifier that skips all validation.
/// Used for sslmode=require/prefer where we want encryption without cert validation.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS connector WITHOUT certificate validation (for sslmode=require/prefer).
/// Provides encryption but accepts any server certificate including self-signed.
pub(crate) fn make_rustls_connect_insecure() -> MakeRustlsConnect {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    MakeRustlsConnect::new(config)
}

/// TLS connector WITH certificate validation (for sslmode=verify-ca/verify-full).
/// Validates server certificate against Mozilla's root CA store.
///
/// Note: rustls performs hostname verification by default, so both verify-ca and
/// verify-full currently have identical behavior (full verification). In libpq,
/// verify-ca only validates the CA chain without hostname checking, while verify-full
/// adds hostname verification. A future enhancement could implement a custom verifier
/// to disable hostname checking for verify-ca mode.
pub(crate) fn make_rustls_connect_verified() -> MakeRustlsConnect {
    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    MakeRustlsConnect::new(config)
}
