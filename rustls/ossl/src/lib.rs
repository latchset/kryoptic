pub mod pkey;

use ossl::rand::get_random;
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, SecureRandom, WebPkiSupportedAlgorithms,
};

#[derive(Debug)]
pub struct OsslSecureRandom;

impl SecureRandom for OsslSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        get_random(buf, true).map_err(|_| GetRandomFailed)
    }
}

pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![],
        kx_groups: vec![],
        signature_verification_algorithms: WebPkiSupportedAlgorithms {
            all: &[],
            mapping: &[],
        },
        secure_random: &OsslSecureRandom,
        key_provider: &pkey::OsslKeyProvider,
    }
}
