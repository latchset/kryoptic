use std::sync::Mutex;

use ossl::digest::DigestAlg;
use ossl::pkey::EvpPkey;
use ossl::signature::{OsslSignature, RsaPssParams, SigAlg, SigOp};
use rustls::sign::Signer;
use rustls::{Error, SignatureScheme};

use crate::osslctx;

#[derive(Debug)]
pub struct OsslSigner {
    scheme: SignatureScheme,
    signature: Mutex<OsslSignature>,
}

impl OsslSigner {
    pub fn new(
        scheme: SignatureScheme,
        sigalg: SigAlg,
        key: &EvpPkey,
    ) -> Result<OsslSigner, Error> {
        let params = match sigalg {
            SigAlg::EcdsaSha2_512
            | SigAlg::EcdsaSha2_384
            | SigAlg::EcdsaSha2_256 => Ok(None),
            SigAlg::Ed25519 | SigAlg::Ed448 => {
                ossl::signature::eddsa_params(sigalg, None)
            }
            SigAlg::RsaPssSha2_512 => ossl::signature::rsa_sig_params(
                SigAlg::RsaPssSha2_512,
                &Some(RsaPssParams {
                    digest: DigestAlg::Sha2_512,
                    mgf1: DigestAlg::Sha2_512,
                    saltlen: 64,
                }),
            ),
            SigAlg::RsaPssSha2_384 => ossl::signature::rsa_sig_params(
                SigAlg::RsaPssSha2_384,
                &Some(RsaPssParams {
                    digest: DigestAlg::Sha2_384,
                    mgf1: DigestAlg::Sha2_384,
                    saltlen: 48,
                }),
            ),
            SigAlg::RsaPssSha2_256 => ossl::signature::rsa_sig_params(
                SigAlg::RsaPssSha2_256,
                &Some(RsaPssParams {
                    digest: DigestAlg::Sha2_256,
                    mgf1: DigestAlg::Sha2_256,
                    saltlen: 32,
                }),
            ),
            SigAlg::RsaSha2_512 => {
                ossl::signature::rsa_sig_params(SigAlg::RsaSha2_512, &None)
            }
            SigAlg::RsaSha2_384 => {
                ossl::signature::rsa_sig_params(SigAlg::RsaSha2_384, &None)
            }
            SigAlg::RsaSha2_256 => {
                ossl::signature::rsa_sig_params(SigAlg::RsaSha2_256, &None)
            }
            _ => Ok(None),
        }
        .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;

        let signature = OsslSignature::new(
            osslctx(),
            SigOp::Sign,
            sigalg,
            key,
            params.as_ref(),
        )
        .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;

        Ok(OsslSigner {
            scheme,
            signature: Mutex::new(signature),
        })
    }
}

impl Signer for OsslSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = self
            .signature
            .lock()
            .map_err(|_| Error::General("Lock poisoned".to_string()))?;

        let len = sig
            .sign(message, None)
            .map_err(|e| Error::General(format!("OpenSSL sign error: {e}")))?;
        let mut buf = vec![0u8; len];
        let actual_len = sig
            .sign(message, Some(&mut buf))
            .map_err(|e| Error::General(format!("OpenSSL sign error: {e}")))?;
        buf.truncate(actual_len);
        Ok(buf)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
