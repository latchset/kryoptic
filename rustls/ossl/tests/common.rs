use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::sync::Arc;

#[derive(Debug)]
pub struct PinnedSelfSignedVerifier {
    pinned_cert: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl PinnedSelfSignedVerifier {
    pub fn new(pinned_cert: CertificateDer<'static>) -> Self {
        Self {
            pinned_cert,
            // Pull standard crypto provider signature schemes (e.g., ring or aws-lc)
            provider: Arc::new(rustls_ossl::default_provider()),
        }
    }
}

impl ServerCertVerifier for PinnedSelfSignedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. STRICT CHECK: Ensure the presented cert matches exactly our pinned cert bytes
        if end_entity.as_ref() != self.pinned_cert.as_ref() {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
