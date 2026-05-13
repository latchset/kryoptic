pub mod pkey;
pub mod signer;
pub mod verify;

use ossl::rand::get_random;
use ossl::OsslContext;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};

static OSSL_CONTEXT: std::sync::OnceLock<OsslContext> =
    std::sync::OnceLock::new();

pub fn osslctx() -> &'static OsslContext {
    OSSL_CONTEXT.get_or_init(|| {
        let mut ctx = OsslContext::new_lib_ctx();
        let _ = ctx.load_default_configuration();
        ctx
    })
}

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
        signature_verification_algorithms: verify::supported_algorithms(),
        secure_random: &OsslSecureRandom,
        key_provider: &pkey::OsslKeyProvider,
    }
}
