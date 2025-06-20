// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements PKCS#11 mechanisms for RSA, including PKCS#1 v1.5,
//! PSS, and OAEP padding schemes, using the OpenSSL EVP interface. It handles
//! key generation, encryption, decryption, signing, verification, and wrapping.

use crate::attribute::Attribute;
use crate::error::{Error, Result};
use crate::hash::{hash_size, INVALID_HASH_SIZE};
use crate::mechanism::{
    Decryption, Encryption, MechOperation, Sign, Verify, VerifySignature,
};
use crate::misc::{bytes_to_vec, cast_params, zeromem};
use crate::object::Object;
use crate::ossl::common::{
    mech_type_to_digest_alg, osslctx, privkey_from_object, pubkey_from_object,
};

use ossl::asymcipher::{rsa_enc_params, EncAlg, OsslAsymcipher, RsaOaepParams};
use ossl::digest::DigestAlg;
use ossl::pkey::{EvpPkey, EvpPkeyType, PkeyData, RsaData};
use ossl::signature::{rsa_sig_params, OsslSignature, RsaPssParams, SigAlg};
use pkcs11::*;

#[cfg(feature = "fips")]
use ossl::fips::FipsApproval;

pub const MIN_RSA_SIZE_BITS: usize =
    if cfg!(feature = "fips") { 2048 } else { 1024 };

pub const MAX_RSA_SIZE_BITS: usize = 16384;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

/// Converts a PKCS#11 RSA key `Object` into an `EvpPkey`.
///
/// Extracts RSA key components (N, E, D, P, Q, DP, DQ, QInv) based on the
/// object `class` (public/private) and populates a `RsaData` structure.
pub fn rsa_object_to_pkey(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<EvpPkey> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }

    let n = key.get_attr_as_bytes(CKA_MODULUS)?.clone();
    let e = key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?.clone();
    let (d, p, q, a, b, c) = match kclass {
        CKO_PUBLIC_KEY => (None, None, None, None, None, None),
        CKO_PRIVATE_KEY => {
            let d = Some(key.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?.clone());
            let pa = key.get_attr(CKA_PRIME_1);
            let qa = key.get_attr(CKA_PRIME_1);
            /* OpenSSL can compute a,b,c with just p,q */
            let (p, q) = if pa.is_some() && qa.is_some() {
                (
                    Some(pa.unwrap().get_value().clone()),
                    Some(qa.unwrap().get_value().clone()),
                )
            } else {
                (None, None)
            };
            let aa = key.get_attr(CKA_EXPONENT_1);
            let ba = key.get_attr(CKA_EXPONENT_2);
            let ca = key.get_attr(CKA_COEFFICIENT);
            let (a, b, c) = if aa.is_some() && ba.is_some() && ca.is_some() {
                (
                    Some(aa.unwrap().get_value().clone()),
                    Some(ba.unwrap().get_value().clone()),
                    Some(ca.unwrap().get_value().clone()),
                )
            } else {
                (None, None, None)
            };
            (d, p, q, a, b, c)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT)?,
    };
    Ok(EvpPkey::import(
        osslctx(),
        EvpPkeyType::Rsa(n.len() * 8, e),
        PkeyData::Rsa(RsaData {
            n: n,
            d: d,
            p: p,
            q: q,
            a: a,
            b: b,
            c: c,
        }),
    )?)
}

/// Maps a PKCS#11 MGF type (`CK_RSA_PKCS_MGF_TYPE`) to the corresponding
/// OpenSSL digest name used within MGF1.
fn mgf1_to_digest_alg(mech: CK_MECHANISM_TYPE) -> Result<DigestAlg> {
    Ok(match mech {
        #[cfg(not(feature = "no_sha1"))]
        CKG_MGF1_SHA1 => DigestAlg::Sha1,
        CKG_MGF1_SHA224 => DigestAlg::Sha2_224,
        CKG_MGF1_SHA256 => DigestAlg::Sha2_256,
        CKG_MGF1_SHA384 => DigestAlg::Sha2_384,
        CKG_MGF1_SHA512 => DigestAlg::Sha2_512,
        CKG_MGF1_SHA3_224 => DigestAlg::Sha3_224,
        CKG_MGF1_SHA3_256 => DigestAlg::Sha3_256,
        CKG_MGF1_SHA3_384 => DigestAlg::Sha3_384,
        CKG_MGF1_SHA3_512 => DigestAlg::Sha3_512,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    })
}

/// Helper function to parse signature parameters from `CK_MECHANISM`.
///
/// Returns a `RsaPssParams` structure for the PSS mechanisms.
fn parse_sig_params(
    mech: &CK_MECHANISM,
) -> Result<(SigAlg, Option<RsaPssParams>)> {
    let (alg, pss) = match mech.mechanism {
        CKM_RSA_X_509 => (SigAlg::RsaNoPad, false),
        CKM_RSA_PKCS => (SigAlg::Rsa, false),
        CKM_RSA_PKCS_PSS => (SigAlg::RsaPss, true),
        #[cfg(not(feature = "no_sha1"))]
        CKM_SHA1_RSA_PKCS => (SigAlg::RsaSha1, false),
        CKM_SHA224_RSA_PKCS => (SigAlg::RsaSha2_224, false),
        CKM_SHA256_RSA_PKCS => (SigAlg::RsaSha2_256, false),
        CKM_SHA384_RSA_PKCS => (SigAlg::RsaSha2_384, false),
        CKM_SHA512_RSA_PKCS => (SigAlg::RsaSha2_512, false),
        CKM_SHA3_224_RSA_PKCS => (SigAlg::RsaSha3_224, false),
        CKM_SHA3_256_RSA_PKCS => (SigAlg::RsaSha3_256, false),
        CKM_SHA3_384_RSA_PKCS => (SigAlg::RsaSha3_384, false),
        CKM_SHA3_512_RSA_PKCS => (SigAlg::RsaSha3_512, false),
        #[cfg(not(feature = "no_sha1"))]
        CKM_SHA1_RSA_PKCS_PSS => (SigAlg::RsaPssSha1, true),
        CKM_SHA224_RSA_PKCS_PSS => (SigAlg::RsaPssSha2_224, true),
        CKM_SHA256_RSA_PKCS_PSS => (SigAlg::RsaPssSha2_256, true),
        CKM_SHA384_RSA_PKCS_PSS => (SigAlg::RsaPssSha2_384, true),
        CKM_SHA512_RSA_PKCS_PSS => (SigAlg::RsaPssSha2_512, true),
        CKM_SHA3_224_RSA_PKCS_PSS => (SigAlg::RsaPssSha3_224, true),
        CKM_SHA3_256_RSA_PKCS_PSS => (SigAlg::RsaPssSha3_256, true),
        CKM_SHA3_384_RSA_PKCS_PSS => (SigAlg::RsaPssSha3_384, true),
        CKM_SHA3_512_RSA_PKCS_PSS => (SigAlg::RsaPssSha3_512, true),
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    if pss {
        let params = cast_params!(mech, CK_RSA_PKCS_PSS_PARAMS);
        let mdname = mech_type_to_digest_alg(params.hashAlg)?;
        if mech.mechanism != CKM_RSA_PKCS_PSS {
            if mech_type_to_digest_alg(mech.mechanism)? != mdname {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
        }
        Ok((
            alg,
            Some(RsaPssParams {
                digest: mdname,
                mgf1: mgf1_to_digest_alg(params.mgf)?,
                saltlen: usize::try_from(params.sLen)?,
            }),
        ))
    } else {
        Ok((alg, None))
    }
}

/// Helper function to parse encryption parameters from `CK_MECHANISM`.
///
/// Returns a `RsaOaepParams` structure for the CKM_RSA_PKCS_OAEP
/// mechanism.
fn parse_enc_params(
    mech: &CK_MECHANISM,
) -> Result<(EncAlg, Option<RsaOaepParams>)> {
    match mech.mechanism {
        CKM_RSA_X_509 => Ok((EncAlg::RsaNoPad, None)),
        CKM_RSA_PKCS => Ok((EncAlg::RsaPkcs1_5, None)),
        CKM_RSA_PKCS_OAEP => {
            let params = cast_params!(mech, CK_RSA_PKCS_OAEP_PARAMS);
            let label = match params.source {
                0 => {
                    if params.ulSourceDataLen != 0 {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    None
                }
                CKZ_DATA_SPECIFIED => match params.ulSourceDataLen {
                    0 => None,
                    _ => Some(bytes_to_vec!(
                        params.pSourceData,
                        params.ulSourceDataLen
                    )),
                },
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            };
            let oaep = RsaOaepParams {
                digest: mech_type_to_digest_alg(params.hashAlg)?,
                mgf1: mgf1_to_digest_alg(params.mgf)?,
                label: label,
            };
            Ok((EncAlg::RsaOaep, Some(oaep)))
        }
        _ => Err(CKR_MECHANISM_INVALID)?,
    }
}

/// Represents an active RSA cryptographic operation.
#[derive(Debug)]
pub struct RsaPKCSOperation {
    /// The specific RSA mechanism being used (e.g., `CKM_SHA256_RSA_PKCS`).
    mech: CK_MECHANISM_TYPE,
    /// Maximum input data length for this operation/padding mode.
    max_input: usize,
    /// Expected output length (typically key size in bytes).
    output_len: usize,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The OpenSSL Wrapper Signature Context
    sigctx: Option<OsslSignature>,
    /// The OpenSSL Wrapper Encryption Context
    encctx: Option<OsslAsymcipher>,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

impl RsaPKCSOperation {
    /// Helper to get the hash output length in bytes for a given mechanism.
    fn hash_len(hash: CK_MECHANISM_TYPE) -> Result<usize> {
        match hash_size(hash) {
            INVALID_HASH_SIZE => Err(CKR_MECHANISM_INVALID)?,
            x => Ok(x),
        }
    }

    /// Helper to get and validate the RSA key size from an `Object`.
    fn get_key_size(key: &Object, info: &CK_MECHANISM_INFO) -> Result<usize> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: CK_ULONG = modulus.len() as CK_ULONG * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        Ok(modulus.len())
    }

    /// Calculates the maximum message length for encryption/decryption based
    /// on modulus size, padding mode (PKCS#1 v1.5, OAEP), and hash algorithm.
    fn max_message_len(modulus: usize, mech: &CK_MECHANISM) -> Result<usize> {
        match mech.mechanism {
            CKM_RSA_X_509 => Ok(modulus),
            CKM_RSA_PKCS => Ok(modulus - 11),
            CKM_RSA_PKCS_PSS => {
                let params = cast_params!(mech, CK_RSA_PKCS_PSS_PARAMS);
                Ok(Self::hash_len(params.hashAlg)?)
            }
            CKM_RSA_PKCS_OAEP => {
                let params = cast_params!(mech, CK_RSA_PKCS_OAEP_PARAMS);
                let hs = Self::hash_len(params.hashAlg)?;
                Ok(modulus - 2 * hs - 2)
            }
            _ => Ok(0),
        }
    }

    /// Internal constructor for encryption/decryption operations.
    /// Parses OAEP parameters if applicable.
    fn encdec_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
        flag: CK_FLAGS,
    ) -> Result<RsaPKCSOperation> {
        #[cfg(feature = "fips")]
        let mut fips_approval = FipsApproval::init();

        let (alg, params) = parse_enc_params(mech)?;
        let encctx = match flag {
            CKF_ENCRYPT => OsslAsymcipher::message_encrypt_new(
                osslctx(),
                &mut pubkey_from_object(key)?,
                &rsa_enc_params(alg, params.as_ref())?,
            )?,
            CKF_DECRYPT => OsslAsymcipher::message_decrypt_new(
                osslctx(),
                &mut privkey_from_object(key)?,
                &rsa_enc_params(alg, params.as_ref())?,
            )?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let keysize = Self::get_key_size(key, info)?;
        let maxinput = Self::max_message_len(keysize, mech)?;

        #[cfg(feature = "fips")]
        fips_approval.update();

        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: maxinput,
            output_len: keysize,
            finalized: false,
            in_use: false,
            sigctx: None,
            encctx: Some(encctx),
            #[cfg(feature = "fips")]
            fips_approval: fips_approval,
        })
    }

    /// Creates a new `RsaPKCSOperation` for encryption.
    pub fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::encdec_new(mech, key, info, CKF_ENCRYPT)
    }

    /// Creates a new `RsaPKCSOperation` for decryption.
    pub fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::encdec_new(mech, key, info, CKF_DECRYPT)
    }

    /// Internal constructor for signing/verification operations.
    /// Parses PSS parameters if applicable and initializes the appropriate
    /// signature context
    fn sigver_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
        flag: CK_FLAGS,
        signature: Option<&[u8]>,
    ) -> Result<RsaPKCSOperation> {
        #[cfg(feature = "fips")]
        let mut fips_approval = FipsApproval::init();

        let (alg, params) = parse_sig_params(mech)?;
        let mut sigctx = match flag {
            CKF_SIGN => OsslSignature::message_sign_new(
                osslctx(),
                alg,
                &mut privkey_from_object(key)?,
                rsa_sig_params(alg, &params)?.as_ref(),
            )?,
            CKF_VERIFY => OsslSignature::message_verify_new(
                osslctx(),
                alg,
                &mut pubkey_from_object(key)?,
                rsa_sig_params(alg, &params)?.as_ref(),
            )?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let keysize = Self::get_key_size(key, info)?;
        let maxinput = Self::max_message_len(keysize, mech)?;
        if let Some(sig) = &signature {
            if sig.len() != keysize {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }
            sigctx.set_signature(sig)?;
        }

        #[cfg(feature = "fips")]
        fips_approval.update();

        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: maxinput,
            output_len: keysize,
            finalized: false,
            in_use: false,
            sigctx: Some(sigctx),
            encctx: None,
            #[cfg(feature = "fips")]
            fips_approval: fips_approval,
        })
    }

    /// Creates a new `RsaPKCSOperation` for signing.
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::sigver_new(mech, key, info, CKF_SIGN, None)
    }

    /// Creates a new `RsaPKCSOperation` for verification.
    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::sigver_new(mech, key, info, CKF_VERIFY, None)
    }

    /// Creates a new `RsaPKCSOperation` for verification with a pre-supplied
    /// signature.
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<RsaPKCSOperation> {
        Self::sigver_new(mech, key, info, CKF_VERIFY, Some(signature))
    }

    /// Generates an RSA key pair using OpenSSL.
    ///
    /// Takes the desired public exponent and modulus bit size. Populates the
    /// public key (`CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`) and private key
    /// (`CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`, `CKA_PRIVATE_EXPONENT`, CRT
    /// params) attributes.
    pub fn generate_keypair(
        exponent: Vec<u8>,
        bits: usize,
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        if bits < MIN_RSA_SIZE_BITS || bits > MAX_RSA_SIZE_BITS {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }

        let pkey = EvpPkey::generate(
            osslctx(),
            EvpPkeyType::Rsa(bits, exponent.clone()),
        )?;
        let rsa = match pkey.export()? {
            PkeyData::Rsa(r) => r,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        /* Public Key (has E already set) */
        pubkey.set_attr(Attribute::from_bytes(CKA_MODULUS, rsa.n.clone()))?;

        /* Private Key */
        privkey.set_attr(Attribute::from_bytes(CKA_MODULUS, rsa.n))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_PUBLIC_EXPONENT,
            exponent.clone(),
        ))?;
        if let Some(d) = rsa.d {
            privkey.set_attr(Attribute::from_bytes(CKA_PRIVATE_EXPONENT, d))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if let Some(p) = rsa.p {
            privkey.set_attr(Attribute::from_bytes(CKA_PRIME_1, p))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if let Some(q) = rsa.q {
            privkey.set_attr(Attribute::from_bytes(CKA_PRIME_2, q))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if let Some(a) = rsa.a {
            privkey.set_attr(Attribute::from_bytes(CKA_EXPONENT_1, a))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if let Some(b) = rsa.b {
            privkey.set_attr(Attribute::from_bytes(CKA_EXPONENT_2, b))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if let Some(c) = rsa.c {
            privkey.set_attr(Attribute::from_bytes(CKA_COEFFICIENT, c))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }

    /// Performs a one-shot RSA key wrapping operation (PKCS#1 v1.5 or OAEP).
    ///
    /// Initializes an encryption operation internally using the `wrapping_key`.
    /// Encrypts the `keydata` (which should be the DER-encoded key to wrap)
    /// and writes the result to `output`. Zeroizes `keydata` afterwards.
    pub fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: &mut [u8],
        info: &CK_MECHANISM_INFO,
    ) -> Result<usize> {
        let mut op = match Self::encrypt_new(mech, wrapping_key, info) {
            Ok(o) => o,
            Err(e) => {
                zeromem(keydata.as_mut_slice());
                return Err(e);
            }
        };
        let needed_len = op.encryption_len(keydata.len(), true)?;
        if output.len() == 0 {
            zeromem(keydata.as_mut_slice());
            return Ok(needed_len);
        }
        if output.len() < needed_len {
            zeromem(keydata.as_mut_slice());
            return Err(Error::buf_too_small(needed_len));
        }
        let result = op.encrypt(&keydata, output);
        zeromem(keydata.as_mut_slice());
        result
    }

    /// Performs a one-shot RSA key unwrapping operation (PKCS#1 v1.5 or OAEP).
    ///
    /// Initializes a decryption operation internally using the `wrapping_key`.
    /// Decrypts the wrapped `data` and returns the raw key bytes (expected to
    /// be in a format like DER-encoded PKCS#8 for the target key factory to
    /// parse).
    pub fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
        info: &CK_MECHANISM_INFO,
    ) -> Result<Vec<u8>> {
        let mut op = Self::decrypt_new(mech, wrapping_key, info)?;
        let outlen = op.decrypt(data, &mut [])?;
        let mut result = vec![0u8; outlen];
        let outlen = op.decrypt(data, result.as_mut_slice())?;
        result.resize(outlen, 0);
        Ok(result)
    }
}

impl MechOperation for RsaPKCSOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approval.approval()
    }
}

impl Encryption for RsaPKCSOperation {
    fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let len = if let Some(ctx) = &mut self.encctx {
            let outlen = ctx.message_encrypt(plain, None)?;
            if cipher.len() == 0 {
                return Ok(outlen);
            } else {
                if cipher.len() < outlen {
                    return Err(Error::buf_too_small(outlen));
                }
            }

            self.finalized = true;

            ctx.message_encrypt(plain, Some(cipher))?
        } else {
            self.finalized = true;
            return Err(CKR_GENERAL_ERROR)?;
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(len)
    }

    fn encrypt_update(
        &mut self,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn encrypt_final(&mut self, _cipher: &mut [u8]) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn encryption_len(&mut self, _: usize, _: bool) -> Result<usize> {
        match self.mech {
            CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP => Ok(self.output_len),
            _ => Err(CKR_GENERAL_ERROR)?,
        }
    }
}

impl Decryption for RsaPKCSOperation {
    fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let len = if let Some(ctx) = &mut self.encctx {
            let mut outlen = ctx.message_decrypt(cipher, None)?;
            if plain.len() == 0 {
                return Ok(outlen);
            }

            if plain.len() < outlen && plain.len() < self.output_len {
                return Err(CKR_BUFFER_TOO_SMALL)?;
            }
            self.finalized = true;

            if outlen > plain.len() {
                /* the PKCS#11 documentation allows modules to pass
                 * in a buffer that is shorter than modulus by the
                 * amount taken by padding, while openssl requires
                 * a full modulus long buffer, so we need to use a
                 * temporary buffer here to bridge this mismatch */
                let mut tmp = vec![0u8; outlen];
                let len =
                    ctx.message_decrypt(cipher, Some(tmp.as_mut_slice()))?;
                if len <= plain.len() {
                    plain[..len].copy_from_slice(&tmp[..len]);
                }
                zeromem(tmp.as_mut_slice());
                outlen = len;
            } else {
                outlen = ctx.message_decrypt(cipher, Some(plain))?;
            }
            if outlen > plain.len() {
                return Err(CKR_GENERAL_ERROR)?;
            }
            outlen
        } else {
            self.finalized = true;
            return Err(CKR_GENERAL_ERROR)?;
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(len)
    }

    fn decrypt_update(
        &mut self,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn decrypt_final(&mut self, _plain: &mut [u8]) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn decryption_len(&mut self, _: usize, _: bool) -> Result<usize> {
        match self.mech {
            CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP => Ok(self.output_len),
            _ => Err(CKR_GENERAL_ERROR)?,
        }
    }
}

impl Sign for RsaPKCSOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_RSA_X_509 | CKM_RSA_PKCS | CKM_RSA_PKCS_PSS => {
                #[cfg(feature = "fips")]
                self.fips_approval.clear();

                self.finalized = true;
                if match self.mech {
                    CKM_RSA_X_509 | CKM_RSA_PKCS => data.len() > self.max_input,
                    CKM_RSA_PKCS_PSS => data.len() != self.max_input,
                    _ => return Err(CKR_GENERAL_ERROR)?,
                } {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                if signature.len() != self.output_len {
                    return Err(CKR_GENERAL_ERROR)?;
                }

                if let Some(ctx) = &mut self.sigctx {
                    if ctx.message_sign(data, None)? != signature.len() {
                        return Err(CKR_GENERAL_ERROR)?;
                    }
                    let _ = ctx.message_sign(data, Some(signature))?;
                } else {
                    return Err(CKR_GENERAL_ERROR)?;
                }

                #[cfg(feature = "fips")]
                self.fips_approval.finalize();

                Ok(())
            }
            _ => {
                self.sign_update(data)?;
                self.sign_final(signature)
            }
        }
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            match self.mech {
                CKM_RSA_X_509 | CKM_RSA_PKCS | CKM_RSA_PKCS_PSS => {
                    return Err(CKR_OPERATION_NOT_INITIALIZED)?;
                }
                _ => (),
            }
            self.in_use = true;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        if let Some(ctx) = &mut self.sigctx {
            ctx.message_sign_update(data)?;
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(())
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        if let Some(ctx) = &mut self.sigctx {
            let len = ctx.message_sign_final(signature)?;
            if len != signature.len() {
                return Err(CKR_DEVICE_ERROR)?;
            }
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl RsaPKCSOperation {
    /// Internal helper for performing one-shot or final verification step.
    fn verify_internal(
        &mut self,
        data: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        match self.mech {
            CKM_RSA_X_509 | CKM_RSA_PKCS | CKM_RSA_PKCS_PSS => {
                #[cfg(feature = "fips")]
                self.fips_approval.clear();

                self.finalized = true;
                if data.len() > self.max_input {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                if let Some(sig) = &signature {
                    if sig.len() != self.output_len {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                }
                if let Some(ctx) = &mut self.sigctx {
                    ctx.message_verify(data, signature)?;
                } else {
                    return Err(CKR_GENERAL_ERROR)?;
                }

                #[cfg(feature = "fips")]
                self.fips_approval.finalize();

                Ok(())
            }
            _ => {
                self.verify_int_update(data)?;
                self.verify_int_final(signature)
            }
        }
    }

    /// Internal helper for updating a multi-part verification.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            match self.mech {
                CKM_RSA_X_509 | CKM_RSA_PKCS | CKM_RSA_PKCS_PSS => {
                    return Err(CKR_OPERATION_NOT_INITIALIZED)?;
                }
                _ => (),
            }
            self.in_use = true;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        if let Some(ctx) = &mut self.sigctx {
            ctx.message_verify_update(data)?;
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(())
    }

    /// Internal helper for the final step of multi-part verification.
    fn verify_int_final(&mut self, signature: Option<&[u8]>) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        if let Some(ctx) = &mut self.sigctx {
            ctx.message_verify_final(signature)?;
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(())
    }
}

impl Verify for RsaPKCSOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.verify_internal(data, Some(signature))
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.verify_int_update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        self.verify_int_final(Some(signature))
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl VerifySignature for RsaPKCSOperation {
    fn verify(&mut self, data: &[u8]) -> Result<()> {
        self.verify_internal(data, None)
    }
    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.verify_int_update(data)
    }
    fn verify_final(&mut self) -> Result<()> {
        self.verify_int_final(None)
    }
}
