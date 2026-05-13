use std::sync::Arc;

use ossl::pkey::{EvpPkey, EvpPkeyType};
use ossl::signature::SigAlg;
use rustls::crypto::KeyProvider;
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

use crate::osslctx;
use crate::signer::OsslSigner;

#[derive(Debug)]
pub struct OsslKeyProvider;

impl KeyProvider for OsslKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn SigningKey>, Error> {
        let priv_key = EvpPkey::from_der(osslctx(), key_der.secret_der())
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        let key_type = priv_key
            .get_type()
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        Ok(Arc::new(OsslSigningKey::new(priv_key, key_type)))
    }
}

#[derive(Debug)]
struct OsslSigningKey {
    key_type: EvpPkeyType,
    priv_key: EvpPkey,
}

impl OsslSigningKey {
    fn new(p: EvpPkey, t: EvpPkeyType) -> OsslSigningKey {
        OsslSigningKey {
            key_type: t,
            priv_key: p,
        }
    }
}

impl SigningKey for OsslSigningKey {
    fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
    ) -> Option<Box<dyn Signer>> {
        for scheme in offered {
            if let Some(sigalg) = match (&self.key_type, scheme) {
                (EvpPkeyType::Mldsa44, SignatureScheme::ML_DSA_44) => {
                    Some(SigAlg::Mldsa44)
                }
                (EvpPkeyType::Mldsa65, SignatureScheme::ML_DSA_65) => {
                    Some(SigAlg::Mldsa65)
                }
                (EvpPkeyType::Mldsa87, SignatureScheme::ML_DSA_87) => {
                    Some(SigAlg::Mldsa87)
                }
                (EvpPkeyType::Ed448, SignatureScheme::ED448) => {
                    Some(SigAlg::Ed448)
                }
                (EvpPkeyType::Ed25519, SignatureScheme::ED25519) => {
                    Some(SigAlg::Ed25519)
                }
                (EvpPkeyType::P521, SignatureScheme::ECDSA_NISTP521_SHA512) => {
                    Some(SigAlg::EcdsaSha2_512)
                }
                (EvpPkeyType::P384, SignatureScheme::ECDSA_NISTP384_SHA384) => {
                    Some(SigAlg::EcdsaSha2_384)
                }
                (EvpPkeyType::P256, SignatureScheme::ECDSA_NISTP256_SHA256) => {
                    Some(SigAlg::EcdsaSha2_256)
                }
                (EvpPkeyType::Rsa(..), SignatureScheme::RSA_PSS_SHA512) => {
                    Some(SigAlg::RsaPssSha2_512)
                }
                (EvpPkeyType::Rsa(..), SignatureScheme::RSA_PSS_SHA384) => {
                    Some(SigAlg::RsaPssSha2_384)
                }
                (EvpPkeyType::Rsa(..), SignatureScheme::RSA_PSS_SHA256) => {
                    Some(SigAlg::RsaPssSha2_256)
                }
                (EvpPkeyType::Rsa(..), SignatureScheme::RSA_PKCS1_SHA512) => {
                    Some(SigAlg::RsaSha2_512)
                }
                (EvpPkeyType::Rsa(..), SignatureScheme::RSA_PKCS1_SHA384) => {
                    Some(SigAlg::RsaSha2_384)
                }
                (EvpPkeyType::Rsa(..), SignatureScheme::RSA_PKCS1_SHA256) => {
                    Some(SigAlg::RsaSha2_256)
                }
                _ => None,
            } {
                match OsslSigner::new(*scheme, sigalg, &self.priv_key) {
                    Ok(s) => return Some(Box::new(s)),
                    Err(_) => continue,
                }
            }
        }

        None
    }

    /* This is only for TLS1.2 which will never get ML-DSA or any PQ algorithm */
    fn algorithm(&self) -> SignatureAlgorithm {
        match self.key_type {
            EvpPkeyType::Rsa(_, _) => SignatureAlgorithm::RSA,
            EvpPkeyType::P256 | EvpPkeyType::P384 | EvpPkeyType::P521 => {
                SignatureAlgorithm::ECDSA
            }
            EvpPkeyType::Ed25519 => SignatureAlgorithm::ED25519,
            EvpPkeyType::Ed448 => SignatureAlgorithm::ED448,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let spki = self.priv_key.spki_der().ok()?;
        Some(SubjectPublicKeyInfoDer::from(spki))
    }
}
