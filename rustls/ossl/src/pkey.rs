use std::sync::Arc;

use ossl::pkey::{EvpPkey, EvpPkeyType};
use rustls::crypto::KeyProvider;
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

use crate::osslctx;

#[derive(Debug)]
pub struct OsslKeyProvider;

impl KeyProvider for OsslKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn SigningKey>, Error> {
        let pkey = EvpPkey::from_der(osslctx(), key_der.secret_der())
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        let pkey_type = pkey
            .get_type()
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        let algorithm = match pkey_type {
            EvpPkeyType::Rsa(_, _) => SignatureAlgorithm::RSA,
            EvpPkeyType::P256 | EvpPkeyType::P384 | EvpPkeyType::P521 => {
                SignatureAlgorithm::ECDSA
            }
            EvpPkeyType::Ed25519 => SignatureAlgorithm::ED25519,
            EvpPkeyType::Ed448 => SignatureAlgorithm::ED448,
            _ => {
                return Err(Error::General(format!(
                    "Invalid key type: {:?}",
                    pkey_type
                )))
            }
        };
        Ok(Arc::new(OsslSigningKey::new(pkey, algorithm)))
    }
}

#[derive(Debug)]
struct OsslSigningKey {
    algorithm: SignatureAlgorithm,
    ossl_pkey: EvpPkey,
}

impl OsslSigningKey {
    fn new(p: EvpPkey, a: SignatureAlgorithm) -> OsslSigningKey {
        OsslSigningKey {
            algorithm: a,
            ossl_pkey: p,
        }
    }
}

impl SigningKey for OsslSigningKey {
    fn choose_scheme(
        &self,
        _offered: &[SignatureScheme],
    ) -> Option<Box<dyn Signer>> {
        unimplemented!()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let spki = self.ossl_pkey.spki_der().ok()?;
        Some(SubjectPublicKeyInfoDer::from(spki))
    }
}
