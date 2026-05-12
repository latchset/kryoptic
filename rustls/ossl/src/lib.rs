pub mod cipher;
pub mod hash;
pub mod hmac;
pub mod kdf;
pub mod keyex;
pub mod pkey;
pub mod signer;
#[cfg(feature = "tls12")]
pub mod tls12;
pub mod tls13;
pub mod verify;

use ossl::rand::get_random;
use ossl::OsslContext;
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, KeyExchangeAlgorithm, SecureRandom,
};
use rustls::{CipherSuite, CipherSuiteCommon, SupportedCipherSuite};

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

    fn fips(&self) -> bool {
        fips()
    }
}

pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: supported_cipher_suites(),
        kx_groups: keyex::supported_kx_groups(),
        signature_verification_algorithms: verify::supported_algorithms(),
        secure_random: &OsslSecureRandom,
        key_provider: &pkey::OsslKeyProvider,
    }
}

#[cfg(feature = "tls12")]
static SUPPORTED_TLS12_CIPHER_SUITE: std::sync::OnceLock<
    Vec<rustls::Tls12CipherSuite>,
> = std::sync::OnceLock::new();

#[cfg(feature = "tls12")]
fn tls12_cipher_suites() -> &'static [rustls::Tls12CipherSuite] {
    let suites = SUPPORTED_TLS12_CIPHER_SUITE.get_or_init(|| {
        let mut v = Vec::with_capacity(4);

        let rsa_schemes = signer::supported_rsa_sig_schemes();
        if !rsa_schemes.is_empty() {
            /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: rsa_schemes,
                aead_alg: &cipher::AES_128_GCM,
                prf_provider: &kdf::PRF_SHA256,
            });

            /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    hash_provider: &hash::SHA384,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: rsa_schemes,
                aead_alg: &cipher::AES_256_GCM,
                prf_provider: &kdf::PRF_SHA384,
            });
        }

        let ecc_schemes = signer::supported_ecc_sig_schemes();
        if !ecc_schemes.is_empty() {
            /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: ecc_schemes,
                aead_alg: &cipher::AES_128_GCM,
                prf_provider: &kdf::PRF_SHA256,
            });

            /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    hash_provider: &hash::SHA384,
                    confidentiality_limit: 1 << 23,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: ecc_schemes,
                aead_alg: &cipher::AES_256_GCM,
                prf_provider: &kdf::PRF_SHA384,
            });
        }

        v
    });
    &suites
}

static SUPPORTED_TLS13_CIPHER_SUITE: std::sync::OnceLock<
    Vec<rustls::Tls13CipherSuite>,
> = std::sync::OnceLock::new();

fn tls13_cipher_suites() -> &'static [rustls::Tls13CipherSuite] {
    let suites = SUPPORTED_TLS13_CIPHER_SUITE.get_or_init(|| {
        let mut v = Vec::with_capacity(2);

        /* TLS_AES_256_GCM_SHA384 */
        v.push(rustls::Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
                hash_provider: &hash::SHA384,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &kdf::HKDF_SHA384,
            aead_alg: &cipher::AES_256_GCM,
            quic: None, /* TODO */
        });

        /* TLS_AES_128_GCM_SHA256 */
        v.push(rustls::Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &hash::SHA256,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &kdf::HKDF_SHA256,
            aead_alg: &cipher::AES_128_GCM,
            quic: None, /* TODO */
        });

        v
    });
    &suites
}

fn supported_cipher_suites() -> Vec<SupportedCipherSuite> {
    let mut suites = Vec::with_capacity(6);

    for suite in tls13_cipher_suites() {
        suites.push(SupportedCipherSuite::Tls13(&suite));
    }

    #[cfg(feature = "tls12")]
    {
        for suite in tls12_cipher_suites() {
            suites.push(SupportedCipherSuite::Tls12(&suite));
        }
    }

    suites
}

pub(crate) fn fips() -> bool {
    osslctx().fips_is_enabled()
}
