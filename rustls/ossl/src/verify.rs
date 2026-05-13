use ossl::digest::DigestAlg;
use ossl::pkey::{EccData, EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::signature::{
    available, rsa_sig_params, OsslSignature, RsaPssParams, SigAlg, SigOp,
};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature,
    SignatureVerificationAlgorithm,
};
use rustls::SignatureScheme;
use std::sync::OnceLock;

use crate::osslctx;

#[derive(Debug)]
pub struct OsslSigVerAlgorithm {
    pub public_key: AlgorithmIdentifier,
    pub signature: AlgorithmIdentifier,
    pub sig_alg: SigAlg,
}

impl SignatureVerificationAlgorithm for OsslSigVerAlgorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let ctx = osslctx();
        let mut params = None;
        let pub_key = match self.public_key {
            alg_id::ML_DSA_44 | alg_id::ML_DSA_65 | alg_id::ML_DSA_87 => {
                EvpPkey::import(
                    osslctx(),
                    match self.public_key {
                        alg_id::ML_DSA_44 => EvpPkeyType::Mldsa44,
                        alg_id::ML_DSA_65 => EvpPkeyType::Mldsa65,
                        alg_id::ML_DSA_87 => EvpPkeyType::Mldsa87,
                        _ => return Err(InvalidSignature),
                    },
                    PkeyData::Mlkey(MlkeyData {
                        pubkey: Some(public_key.to_vec()),
                        prikey: None,
                        seed: None,
                    }),
                )
                .map_err(|_| InvalidSignature)?
            }
            alg_id::ED25519
            | alg_id::ED448
            | alg_id::ECDSA_P256
            | alg_id::ECDSA_P384
            | alg_id::ECDSA_P521 => EvpPkey::import(
                osslctx(),
                match self.public_key {
                    alg_id::ED25519 => EvpPkeyType::Ed25519,
                    alg_id::ED448 => EvpPkeyType::Ed448,
                    alg_id::ECDSA_P256 => EvpPkeyType::P256,
                    alg_id::ECDSA_P384 => EvpPkeyType::P384,
                    alg_id::ECDSA_P521 => EvpPkeyType::P521,
                    _ => return Err(InvalidSignature),
                },
                PkeyData::Ecc(EccData {
                    pubkey: Some(public_key.to_vec()),
                    prikey: None,
                }),
            )
            .map_err(|_| InvalidSignature)?,
            alg_id::RSA_ENCRYPTION => {
                let pkey = EvpPkey::from_pubkey_der(
                    osslctx(),
                    self.sig_alg,
                    public_key,
                )
                .map_err(|_| InvalidSignature)?;

                params = match self.sig_alg {
                    SigAlg::RsaPssSha2_256 => rsa_sig_params(
                        SigAlg::RsaPssSha2_256,
                        &Some(RsaPssParams {
                            digest: DigestAlg::Sha2_256,
                            mgf1: DigestAlg::Sha2_256,
                            saltlen: 32,
                        }),
                    )
                    .map_err(|_| InvalidSignature)?,
                    SigAlg::RsaPssSha2_384 => rsa_sig_params(
                        SigAlg::RsaPssSha2_384,
                        &Some(RsaPssParams {
                            digest: DigestAlg::Sha2_384,
                            mgf1: DigestAlg::Sha2_384,
                            saltlen: 48,
                        }),
                    )
                    .map_err(|_| InvalidSignature)?,
                    SigAlg::RsaPssSha2_512 => rsa_sig_params(
                        SigAlg::RsaPssSha2_512,
                        &Some(RsaPssParams {
                            digest: DigestAlg::Sha2_512,
                            mgf1: DigestAlg::Sha2_512,
                            saltlen: 64,
                        }),
                    )
                    .map_err(|_| InvalidSignature)?,
                    SigAlg::RsaSha2_256
                    | SigAlg::RsaSha2_384
                    | SigAlg::RsaSha2_512 => {
                        rsa_sig_params(self.sig_alg, &None)
                            .map_err(|_| InvalidSignature)?
                    }
                    _ => None,
                };

                pkey
            }
            _ => return Err(InvalidSignature),
        };

        let mut sig_ctx = OsslSignature::new(
            ctx,
            SigOp::Verify,
            self.sig_alg,
            &pub_key,
            params.as_ref(),
        )
        .map_err(|_| InvalidSignature)?;

        sig_ctx
            .verify(message, Some(signature))
            .map_err(|_| InvalidSignature)?;

        Ok(())
    }
}

static ALL_ALGS: [OsslSigVerAlgorithm; 20] = [
    OsslSigVerAlgorithm {
        public_key: alg_id::ML_DSA_44,
        signature: alg_id::ML_DSA_44,
        sig_alg: SigAlg::Mldsa44,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ML_DSA_65,
        signature: alg_id::ML_DSA_65,
        sig_alg: SigAlg::Mldsa65,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ML_DSA_87,
        signature: alg_id::ML_DSA_87,
        sig_alg: SigAlg::Mldsa87,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ED25519,
        signature: alg_id::ED25519,
        sig_alg: SigAlg::Ed25519,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ED448,
        signature: alg_id::ED448,
        sig_alg: SigAlg::Ed448,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P256,
        signature: alg_id::ECDSA_SHA256,
        sig_alg: SigAlg::EcdsaSha2_256,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P384,
        signature: alg_id::ECDSA_SHA256,
        sig_alg: SigAlg::EcdsaSha2_256,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P521,
        signature: alg_id::ECDSA_SHA256,
        sig_alg: SigAlg::EcdsaSha2_256,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P384,
        signature: alg_id::ECDSA_SHA384,
        sig_alg: SigAlg::EcdsaSha2_384,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P256,
        signature: alg_id::ECDSA_SHA384,
        sig_alg: SigAlg::EcdsaSha2_384,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P521,
        signature: alg_id::ECDSA_SHA384,
        sig_alg: SigAlg::EcdsaSha2_384,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P521,
        signature: alg_id::ECDSA_SHA512,
        sig_alg: SigAlg::EcdsaSha2_512,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P256,
        signature: alg_id::ECDSA_SHA512,
        sig_alg: SigAlg::EcdsaSha2_512,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::ECDSA_P384,
        signature: alg_id::ECDSA_SHA512,
        sig_alg: SigAlg::EcdsaSha2_512,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: alg_id::RSA_PSS_SHA256,
        sig_alg: SigAlg::RsaPssSha2_256,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: alg_id::RSA_PSS_SHA384,
        sig_alg: SigAlg::RsaPssSha2_384,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: alg_id::RSA_PSS_SHA512,
        sig_alg: SigAlg::RsaPssSha2_512,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: alg_id::RSA_PKCS1_SHA256,
        sig_alg: SigAlg::RsaSha2_256,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: alg_id::RSA_PKCS1_SHA384,
        sig_alg: SigAlg::RsaSha2_384,
    },
    OsslSigVerAlgorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: alg_id::RSA_PKCS1_SHA512,
        sig_alg: SigAlg::RsaSha2_512,
    },
];

static AVAILABLE: OnceLock<Vec<&'static dyn SignatureVerificationAlgorithm>> =
    OnceLock::new();

static MAPPING: OnceLock<
    Vec<(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )>,
> = OnceLock::new();

static SUPPORTED: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();

pub fn supported_algorithms() -> WebPkiSupportedAlgorithms {
    let algs = AVAILABLE.get_or_init(|| {
        let ctx = osslctx();

        let mut available_algs: Vec<
            &'static dyn SignatureVerificationAlgorithm,
        > = Vec::new();
        /* OpenSSL up to 3.5 does not have signature names for RSA_PSS,
         * so we just assume PSS is possible when the corresponding PKCS15
         * algorithm is available */
        for alg in &ALL_ALGS {
            match alg.sig_alg {
                SigAlg::Mldsa44
                | SigAlg::Mldsa65
                | SigAlg::Mldsa87
                | SigAlg::Ed25519
                | SigAlg::Ed448
                | SigAlg::EcdsaSha2_256
                | SigAlg::EcdsaSha2_384
                | SigAlg::EcdsaSha2_512
                | SigAlg::RsaSha2_256
                | SigAlg::RsaSha2_384
                | SigAlg::RsaSha2_512 => {
                    if available(ctx, alg.sig_alg) {
                        available_algs.push(alg);
                    }
                }
                SigAlg::RsaPssSha2_256 => {
                    if available(ctx, SigAlg::RsaSha2_256) {
                        available_algs.push(alg);
                    }
                }
                SigAlg::RsaPssSha2_384 => {
                    if available(ctx, SigAlg::RsaSha2_384) {
                        available_algs.push(alg);
                    }
                }
                SigAlg::RsaPssSha2_512 => {
                    if available(ctx, SigAlg::RsaSha2_512) {
                        available_algs.push(alg);
                    }
                }
                _ => (),
            }
        }
        available_algs
    });

    let mapping = MAPPING.get_or_init(|| {
        let mut ecdsa_sha256: Option<usize> = None;
        let mut ecdsa_sha384: Option<usize> = None;
        let mut ecdsa_sha512: Option<usize> = None;

        let mut map: Vec<(
            SignatureScheme,
            &'static [&'static dyn SignatureVerificationAlgorithm],
        )> = Vec::new();

        // enumerate here
        for (index, alg) in algs.iter().enumerate() {
            match alg.signature_alg_id() {
                alg_id::ECDSA_SHA256 => {
                    if ecdsa_sha256.is_none() {
                        ecdsa_sha256 = Some(index);
                    }
                }
                alg_id::ECDSA_SHA384 => {
                    if ecdsa_sha384.is_none() {
                        ecdsa_sha384 = Some(index);
                    }
                }
                alg_id::ECDSA_SHA512 => {
                    if ecdsa_sha512.is_none() {
                        ecdsa_sha512 = Some(index);
                    }
                }
                alg_id::ED25519 => {
                    map.push((
                        SignatureScheme::ED25519,
                        &algs[index..index + 1],
                    ));
                }
                alg_id::ED448 => {
                    map.push((SignatureScheme::ED448, &algs[index..index + 1]));
                }
                alg_id::RSA_PSS_SHA256 => {
                    map.push((
                        SignatureScheme::RSA_PSS_SHA256,
                        &algs[index..index + 1],
                    ));
                }
                alg_id::RSA_PSS_SHA384 => {
                    map.push((
                        SignatureScheme::RSA_PSS_SHA384,
                        &algs[index..index + 1],
                    ));
                }
                alg_id::RSA_PSS_SHA512 => {
                    map.push((
                        SignatureScheme::RSA_PSS_SHA512,
                        &algs[index..index + 1],
                    ));
                }
                alg_id::RSA_PKCS1_SHA256 => {
                    map.push((
                        SignatureScheme::RSA_PKCS1_SHA256,
                        &algs[index..index + 1],
                    ));
                }
                alg_id::RSA_PKCS1_SHA384 => {
                    map.push((
                        SignatureScheme::RSA_PKCS1_SHA384,
                        &algs[index..index + 1],
                    ));
                }
                alg_id::RSA_PKCS1_SHA512 => {
                    map.push((
                        SignatureScheme::RSA_PKCS1_SHA512,
                        &algs[index..index + 1],
                    ));
                }
                _ => (),
            }
        }

        if let Some(i) = ecdsa_sha256 {
            let mut end = i + 1;
            while end < algs.len()
                && algs[end].signature_alg_id() == alg_id::ECDSA_SHA256
            {
                end += 1;
            }
            map.push((SignatureScheme::ECDSA_NISTP256_SHA256, &algs[i..end]));
        }

        if let Some(i) = ecdsa_sha384 {
            let mut end = i + 1;
            while end < algs.len()
                && algs[end].signature_alg_id() == alg_id::ECDSA_SHA384
            {
                end += 1;
            }
            map.push((SignatureScheme::ECDSA_NISTP384_SHA384, &algs[i..end]));
        }

        if let Some(i) = ecdsa_sha512 {
            let mut end = i + 1;
            while end < algs.len()
                && algs[end].signature_alg_id() == alg_id::ECDSA_SHA512
            {
                end += 1;
            }
            map.push((SignatureScheme::ECDSA_NISTP521_SHA512, &algs[i..end]));
        }

        map
    });

    *SUPPORTED.get_or_init(|| WebPkiSupportedAlgorithms {
        all: algs,
        mapping: mapping,
    })
}
