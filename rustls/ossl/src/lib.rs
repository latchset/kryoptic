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
        let mut ctx = OsslContext::new_lib_ctx_checked().unwrap();
        ctx.load_default_configuration().unwrap();
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
        let mut v = Vec::with_capacity(6);

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

            /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: u64::MAX,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: rsa_schemes,
                aead_alg: &cipher::CHACHA20_POLY1305,
                prf_provider: &kdf::PRF_SHA256,
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

            /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
            v.push(rustls::Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    hash_provider: &hash::SHA256,
                    confidentiality_limit: u64::MAX,
                },
                kx: KeyExchangeAlgorithm::ECDHE,
                sign: ecc_schemes,
                aead_alg: &cipher::CHACHA20_POLY1305,
                prf_provider: &kdf::PRF_SHA256,
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
        let mut v = Vec::with_capacity(3);

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

        /* TLS13_CHACHA20_POLY1305_SHA256 */
        v.push(rustls::Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                hash_provider: &hash::SHA256,
                confidentiality_limit: u64::MAX,
            },
            hkdf_provider: &kdf::HKDF_SHA256,
            aead_alg: &cipher::CHACHA20_POLY1305,
            quic: None, /* TODO */
        });

        v
    });
    &suites
}

fn supported_cipher_suites() -> Vec<SupportedCipherSuite> {
    let mut suites = Vec::with_capacity(9);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_fips() {
        use rustls::crypto::cipher::Tls13AeadAlgorithm;
        assert_eq!(Tls13AeadAlgorithm::fips(&cipher::AES_128_GCM), fips());
        assert_eq!(Tls13AeadAlgorithm::fips(&cipher::AES_256_GCM), fips());
        assert!(!Tls13AeadAlgorithm::fips(&cipher::CHACHA20_POLY1305));
        #[cfg(feature = "tls12")]
        {
            use rustls::crypto::cipher::Tls12AeadAlgorithm;
            assert_eq!(Tls12AeadAlgorithm::fips(&cipher::AES_128_GCM), fips());
            assert_eq!(Tls12AeadAlgorithm::fips(&cipher::AES_256_GCM), fips());
            assert!(!Tls12AeadAlgorithm::fips(&cipher::CHACHA20_POLY1305));
        }
    }

    #[test]
    fn test_crypto_traits_fips() {
        use rustls::crypto::hash::Hash;
        assert_eq!(Hash::fips(&hash::SHA256), fips());
        assert_eq!(Hash::fips(&hash::SHA384), fips());

        use rustls::crypto::hmac::Hmac;
        assert_eq!(Hmac::fips(&hmac::HMAC_SHA256), fips());
        assert_eq!(Hmac::fips(&hmac::HMAC_SHA384), fips());

        use rustls::crypto::tls13::Hkdf;
        assert_eq!(Hkdf::fips(&kdf::HKDF_SHA256), fips());
        assert_eq!(Hkdf::fips(&kdf::HKDF_SHA384), fips());

        #[cfg(feature = "tls12")]
        {
            use rustls::crypto::tls12::Prf;
            assert_eq!(Prf::fips(&kdf::PRF_SHA256), fips());
            assert_eq!(Prf::fips(&kdf::PRF_SHA384), fips());
        }

        use rustls::crypto::SupportedKxGroup;
        assert_eq!(SupportedKxGroup::fips(&keyex::SECP256R1), fips());
        assert_eq!(SupportedKxGroup::fips(&keyex::SECP384R1), fips());
        assert_eq!(SupportedKxGroup::fips(&keyex::SECP521R1), fips());
        assert_eq!(
            SupportedKxGroup::fips(&keyex::X25519),
            fips()
                && ossl::pkey::EvpPkey::available(
                    osslctx(),
                    ossl::pkey::EvpPkeyType::X25519
                )
        );
        assert_eq!(
            SupportedKxGroup::fips(&keyex::MLKEM768),
            fips()
                && ossl::pkey::EvpPkey::available(
                    osslctx(),
                    ossl::pkey::EvpPkeyType::MlKem768
                )
        );
        assert_eq!(
            SupportedKxGroup::fips(&keyex::MLKEM1024),
            fips()
                && ossl::pkey::EvpPkey::available(
                    osslctx(),
                    ossl::pkey::EvpPkeyType::MlKem1024
                )
        );
    }
}
