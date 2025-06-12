// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements PKCS#11 mechanisms for RSA, including PKCS#1 v1.5,
//! PSS, and OAEP padding schemes, using the OpenSSL EVP interface. It handles
//! key generation, encryption, decryption, signing, verification, and wrapping.

use core::ffi::{c_int, c_uint, CStr};

use crate::attribute::Attribute;
use crate::error::some_or_err;
use crate::error::{Error, Result};
use crate::hash::{hash_size, INVALID_HASH_SIZE};
use crate::mechanism::*;
use crate::misc::{bytes_to_vec, cast_params, zeromem};
use crate::object::Object;
use crate::ossl::common::*;

use ossl::bindings::*;
use ossl::{
    rsa_sig_params, EvpPkey, OsslParam, OsslSignature, RsaPssParams, SigAlg,
};
use pkcs11::*;

#[cfg(not(feature = "fips"))]
pub const MIN_RSA_SIZE_BITS: usize = 1024;
#[cfg(feature = "fips")]
pub const MIN_RSA_SIZE_BITS: usize = 2048;

pub const MAX_RSA_SIZE_BITS: usize = 16384;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

static RSA_NAME: &CStr = c"RSA";

/// Converts a PKCS#11 RSA key `Object` into OpenSSL parameters (`OsslParam`).
///
/// Extracts RSA key components (N, E, D, P, Q, DP, DQ, QInv) based on the
/// object `class` (public/private) and populates an `OsslParam` structure.
pub fn rsa_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(&'static CStr, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    let mut params = match class {
        CKO_PUBLIC_KEY => OsslParam::with_capacity(2),
        CKO_PRIVATE_KEY => {
            if kclass == CKO_PUBLIC_KEY {
                return Err(CKR_KEY_TYPE_INCONSISTENT)?;
            }
            OsslParam::with_capacity(9)
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    };
    params.zeroize = true;
    params.add_bn(
        cstr!(OSSL_PKEY_PARAM_RSA_N),
        key.get_attr_as_bytes(CKA_MODULUS)?,
    )?;
    params.add_bn(
        cstr!(OSSL_PKEY_PARAM_RSA_E),
        key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?,
    )?;

    if class == CKO_PRIVATE_KEY {
        params.add_bn(
            cstr!(OSSL_PKEY_PARAM_RSA_D),
            key.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?,
        )?;

        /* OpenSSL can compute a,b,c with just p,q */
        if key.get_attr(CKA_PRIME_1).is_some()
            && key.get_attr(CKA_PRIME_2).is_some()
        {
            params.add_bn(
                cstr!(OSSL_PKEY_PARAM_RSA_FACTOR1),
                key.get_attr_as_bytes(CKA_PRIME_1)?,
            )?;
            params.add_bn(
                cstr!(OSSL_PKEY_PARAM_RSA_FACTOR2),
                key.get_attr_as_bytes(CKA_PRIME_2)?,
            )?;
        }

        if key.get_attr(CKA_EXPONENT_1).is_some()
            && key.get_attr(CKA_EXPONENT_2).is_some()
            && key.get_attr(CKA_COEFFICIENT).is_some()
        {
            params.add_bn(
                cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT1),
                key.get_attr_as_bytes(CKA_EXPONENT_1)?,
            )?;
            params.add_bn(
                cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT2),
                key.get_attr_as_bytes(CKA_EXPONENT_2)?,
            )?;
            params.add_bn(
                cstr!(OSSL_PKEY_PARAM_RSA_COEFFICIENT1),
                key.get_attr_as_bytes(CKA_COEFFICIENT)?,
            )?;
        }
    }
    params.finalize();

    Ok((RSA_NAME, params))
}

/// Maps a PKCS#11 MGF type (`CK_RSA_PKCS_MGF_TYPE`) to the corresponding
/// OpenSSL digest name used within MGF1.
fn mgf1_to_digest_name(mech: CK_MECHANISM_TYPE) -> Result<&'static CStr> {
    Ok(match mech {
        CKG_MGF1_SHA1 => cstr!(OSSL_DIGEST_NAME_SHA1),
        CKG_MGF1_SHA224 => cstr!(OSSL_DIGEST_NAME_SHA2_224),
        CKG_MGF1_SHA256 => cstr!(OSSL_DIGEST_NAME_SHA2_256),
        CKG_MGF1_SHA384 => cstr!(OSSL_DIGEST_NAME_SHA2_384),
        CKG_MGF1_SHA512 => cstr!(OSSL_DIGEST_NAME_SHA2_512),
        CKG_MGF1_SHA3_224 => cstr!(OSSL_DIGEST_NAME_SHA3_224),
        CKG_MGF1_SHA3_256 => cstr!(OSSL_DIGEST_NAME_SHA3_256),
        CKG_MGF1_SHA3_384 => cstr!(OSSL_DIGEST_NAME_SHA3_384),
        CKG_MGF1_SHA3_512 => cstr!(OSSL_DIGEST_NAME_SHA3_512),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    })
}

/// Helper function to parse signature parameters from `CK_MECHANISM`.
///
/// Returns a `RsaPssParams` structure for the PSS mechanisms.
fn parse_pss_params(
    mech: &CK_MECHANISM,
) -> Result<(Option<RsaPssParams>, usize)> {
    match mech.mechanism {
        CKM_RSA_PKCS_PSS
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_512_RSA_PKCS_PSS => {
            let params = cast_params!(mech, CK_RSA_PKCS_PSS_PARAMS);
            let mdname = mech_type_to_digest_name(params.hashAlg)?;
            let hash_len = hash_size(params.hashAlg);
            if hash_len == INVALID_HASH_SIZE {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            if mech.mechanism != CKM_RSA_PKCS_PSS {
                if mech_type_to_digest_name(mech.mechanism)? != mdname {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
            }
            Ok((
                Some(RsaPssParams {
                    digest: mdname,
                    mgf1: mgf1_to_digest_name(params.mgf)?,
                    saltlen: c_int::try_from(params.sLen)?,
                }),
                hash_len,
            ))
        }
        _ => Ok((None, 0)),
    }
}

/// Holds parameters specific to an RSA-OAEP operation.
#[derive(Debug)]
struct RsaOaepParams {
    /// Hash algorithm mechanism identifier (e.g., `CKM_SHA256`).
    hash: CK_ULONG,
    /// Mask Generation Function identifier (e.g., `CKG_MGF1_SHA256`).
    mgf: CK_ULONG,
    /// Optional source/label data.
    source: Option<Vec<u8>>,
}

/// Helper function to create default (empty) `RsaOaepParams`.
fn no_oaep_params() -> RsaOaepParams {
    RsaOaepParams {
        hash: 0,
        mgf: 0,
        source: None,
    }
}

/// Helper function to parse OAEP parameters from `CK_MECHANISM`.
///
/// Returns a `RsaOaepParams` structure with the fields.
fn parse_oaep_params(mech: &CK_MECHANISM) -> Result<RsaOaepParams> {
    if mech.mechanism != CKM_RSA_PKCS_OAEP {
        return Ok(no_oaep_params());
    }
    let params = cast_params!(mech, CK_RSA_PKCS_OAEP_PARAMS);
    let source = match params.source {
        0 => {
            if params.ulSourceDataLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            None
        }
        CKZ_DATA_SPECIFIED => match params.ulSourceDataLen {
            0 => None,
            _ => {
                Some(bytes_to_vec!(params.pSourceData, params.ulSourceDataLen))
            }
        },
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    };

    Ok(RsaOaepParams {
        hash: params.hashAlg,
        mgf: params.mgf,
        source: source,
    })
}

/// Helper function to convert PKCS#11 mechanism type to name
/// understood by the ossl package.
pub fn rsa_type_to_ossl_alg(mech: CK_MECHANISM_TYPE) -> Result<SigAlg> {
    Ok(match mech {
        CKM_RSA_X_509 => SigAlg::RsaNoPad,
        CKM_RSA_PKCS => SigAlg::Rsa,
        CKM_RSA_PKCS_PSS => SigAlg::RsaPss,
        CKM_SHA1_RSA_PKCS => SigAlg::RsaSha1,
        CKM_SHA224_RSA_PKCS => SigAlg::RsaSha2_224,
        CKM_SHA256_RSA_PKCS => SigAlg::RsaSha2_256,
        CKM_SHA384_RSA_PKCS => SigAlg::RsaSha2_384,
        CKM_SHA512_RSA_PKCS => SigAlg::RsaSha2_512,
        CKM_SHA3_224_RSA_PKCS => SigAlg::RsaSha3_224,
        CKM_SHA3_256_RSA_PKCS => SigAlg::RsaSha3_256,
        CKM_SHA3_384_RSA_PKCS => SigAlg::RsaSha3_384,
        CKM_SHA3_512_RSA_PKCS => SigAlg::RsaSha3_512,
        CKM_SHA1_RSA_PKCS_PSS => SigAlg::RsaPssSha1,
        CKM_SHA224_RSA_PKCS_PSS => SigAlg::RsaPssSha2_224,
        CKM_SHA256_RSA_PKCS_PSS => SigAlg::RsaPssSha2_256,
        CKM_SHA384_RSA_PKCS_PSS => SigAlg::RsaPssSha2_384,
        CKM_SHA512_RSA_PKCS_PSS => SigAlg::RsaPssSha2_512,
        CKM_SHA3_224_RSA_PKCS_PSS => SigAlg::RsaPssSha3_224,
        CKM_SHA3_256_RSA_PKCS_PSS => SigAlg::RsaPssSha3_256,
        CKM_SHA3_384_RSA_PKCS_PSS => SigAlg::RsaPssSha3_384,
        CKM_SHA3_512_RSA_PKCS_PSS => SigAlg::RsaPssSha3_512,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
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
    /// The public key (`EvpPkey`) if needed for the operation.
    public_key: Option<EvpPkey>,
    /// The private key (`EvpPkey`) if needed for the operation.
    private_key: Option<EvpPkey>,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The OpenSSL Wrapper Signature Context
    sigctx: Option<OsslSignature>,
    /// Parsed OAEP parameters, if applicable.
    oaep: RsaOaepParams,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
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
    fn max_message_len(
        modulus: usize,
        mech: CK_MECHANISM_TYPE,
        hash: CK_MECHANISM_TYPE,
    ) -> Result<usize> {
        match mech {
            CKM_RSA_X_509 => Ok(modulus),
            CKM_RSA_PKCS => Ok(modulus - 11),
            CKM_RSA_PKCS_OAEP => {
                let hs = Self::hash_len(hash)?;
                Ok(modulus - 2 * hs - 2)
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    /// Internal constructor for encryption/decryption operations.
    /// Parses OAEP parameters if applicable.
    fn encdec_new(
        mech: &CK_MECHANISM,
        pubkey: Option<EvpPkey>,
        privkey: Option<EvpPkey>,
        keysize: usize,
    ) -> Result<RsaPKCSOperation> {
        let oaep_params = parse_oaep_params(mech)?;
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: Self::max_message_len(
                keysize,
                mech.mechanism,
                oaep_params.hash,
            )?,
            output_len: keysize,
            public_key: pubkey,
            private_key: privkey,
            finalized: false,
            in_use: false,
            sigctx: None,
            oaep: oaep_params,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Creates a new `RsaPKCSOperation` for encryption.
    pub fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let keysize = Self::get_key_size(key, info)?;
        let pubkey = pubkey_from_object(key)?;
        Self::encdec_new(mech, Some(pubkey), None, keysize)
    }

    /// Creates a new `RsaPKCSOperation` for decryption.
    pub fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let keysize = Self::get_key_size(key, info)?;
        let pubkey = pubkey_from_object(key)?;
        let privkey = privkey_from_object(key)?;
        Self::encdec_new(mech, Some(pubkey), Some(privkey), keysize)
    }

    /// Internal constructor for signing/verification operations.
    /// Parses PSS parameters if applicable and initializes the appropriate
    /// signature context
    fn sigver_new(
        mech: &CK_MECHANISM,
        mut pubkey: Option<EvpPkey>,
        mut privkey: Option<EvpPkey>,
        keysize: usize,
        signature: Option<&[u8]>,
    ) -> Result<RsaPKCSOperation> {
        let sigalg = rsa_type_to_ossl_alg(mech.mechanism)?;
        let (pss_params, hash_len) = parse_pss_params(mech)?;
        let params = rsa_sig_params(sigalg, &pss_params)?;
        let mut sigctx = if let Some(pkey) = &mut privkey {
            OsslSignature::message_sign_new(
                osslctx(),
                sigalg,
                pkey,
                params.as_ref(),
            )?
        } else if let Some(pkey) = &mut pubkey {
            OsslSignature::message_verify_new(
                osslctx(),
                sigalg,
                pkey,
                params.as_ref(),
            )?
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        };
        if let Some(sig) = &signature {
            sigctx.set_signature(sig)?;
        }
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: match mech.mechanism {
                CKM_RSA_X_509 => keysize,
                CKM_RSA_PKCS => keysize - 11,
                CKM_RSA_PKCS_PSS => hash_len,
                _ => 0,
            },
            output_len: keysize,
            public_key: pubkey,
            private_key: privkey,
            finalized: false,
            in_use: false,
            sigctx: Some(sigctx),
            oaep: no_oaep_params(),
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Creates a new `RsaPKCSOperation` for signing.
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let keysize = Self::get_key_size(key, info)?;
        let pubkey = pubkey_from_object(key)?;
        let privkey = privkey_from_object(key)?;
        Self::sigver_new(mech, Some(pubkey), Some(privkey), keysize, None)
    }

    /// Creates a new `RsaPKCSOperation` for verification.
    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let keysize = Self::get_key_size(key, info)?;
        let pubkey = pubkey_from_object(key)?;
        Self::sigver_new(mech, Some(pubkey), None, keysize, None)
    }

    /// Creates a new `RsaPKCSOperation` for verification with a pre-supplied
    /// signature.
    #[cfg(feature = "pkcs11_3_2")]
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<RsaPKCSOperation> {
        let keysize = Self::get_key_size(key, info)?;
        if signature.len() != keysize {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }
        let pubkey = pubkey_from_object(key)?;
        Self::sigver_new(mech, Some(pubkey), None, keysize, Some(signature))
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
        let c_bits = bits as c_uint;
        let mut params = OsslParam::with_capacity(2);
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_E), &exponent)?;
        params.add_uint(cstr!(OSSL_PKEY_PARAM_RSA_BITS), &c_bits)?;
        params.finalize();

        let evp_pkey = EvpPkey::generate(osslctx(), RSA_NAME, &params)?;
        let params = evp_pkey.todata(EVP_PKEY_KEYPAIR)?;

        /* Public Key (has E already set) */
        pubkey.set_attr(Attribute::from_bytes(
            CKA_MODULUS,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_N))?,
        ))?;

        /* Private Key */
        privkey.set_attr(Attribute::from_bytes(
            CKA_MODULUS,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_N))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_PUBLIC_EXPONENT,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_E))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_PRIVATE_EXPONENT,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_D))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_PRIME_1,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR1))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_PRIME_2,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR2))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_EXPONENT_1,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT1))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_EXPONENT_2,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT2))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_COEFFICIENT,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_COEFFICIENT1))?,
        ))?;
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

    /// Creates an `OSSL_PARAM` array containing RSA padding and digest
    /// parameters suitable for OpenSSL's EVP encryption/decryption functions
    /// (PKCS#1 v1.5 or OAEP). Includes OAEP hash, MGF, and label parameters
    /// if applicable.
    fn rsa_enc_params(&self) -> Result<OsslParam> {
        let mut params = OsslParam::new();
        match self.mech {
            CKM_RSA_X_509 => {
                params.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_PAD_MODE),
                    cstr!(OSSL_PKEY_RSA_PAD_MODE_NONE),
                )?;
            }
            CKM_RSA_PKCS => {
                params.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_PAD_MODE),
                    cstr!(OSSL_PKEY_RSA_PAD_MODE_PKCSV15),
                )?;
            }
            CKM_RSA_PKCS_OAEP => {
                params.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_PAD_MODE),
                    cstr!(OSSL_PKEY_RSA_PAD_MODE_OAEP),
                )?;
                params.add_const_c_string(
                    cstr!(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST),
                    mech_type_to_digest_name(self.oaep.hash)?,
                )?;
                params.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_MGF1_DIGEST),
                    mgf1_to_digest_name(self.oaep.mgf)?,
                )?;
                match &self.oaep.source {
                    None => (),
                    Some(source) => params.add_octet_string(
                        cstr!(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL),
                        source,
                    )?,
                }
            }
            _ => (),
        }
        params.finalize();
        Ok(params)
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
        self.fips_approved
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
        let mut ctx = some_or_err!(mut self.public_key).new_ctx(osslctx())?;
        if unsafe { EVP_PKEY_encrypt_init(ctx.as_mut_ptr()) } != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let ret = unsafe {
            EVP_PKEY_CTX_set_params(
                ctx.as_mut_ptr(),
                self.rsa_enc_params()?.as_ptr(),
            )
        };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let mut outlen = 0;
        let outlen_ptr: *mut usize = &mut outlen;
        if unsafe {
            EVP_PKEY_encrypt(
                ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                outlen_ptr,
                plain.as_ptr(),
                plain.len(),
            )
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if cipher.len() == 0 {
            return Ok(outlen);
        } else {
            if cipher.len() < outlen {
                return Err(Error::buf_too_small(outlen));
            }
        }

        self.finalized = true;

        if unsafe {
            EVP_PKEY_encrypt(
                ctx.as_mut_ptr(),
                cipher.as_mut_ptr(),
                outlen_ptr,
                plain.as_ptr(),
                plain.len(),
            )
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(outlen)
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
        let mut ctx = some_or_err!(mut self.private_key).new_ctx(osslctx())?;
        let ret = unsafe { EVP_PKEY_decrypt_init(ctx.as_mut_ptr()) };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let ret = unsafe {
            EVP_PKEY_CTX_set_params(
                ctx.as_mut_ptr(),
                self.rsa_enc_params()?.as_ptr(),
            )
        };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let mut outlen = 0usize;
        let outlen_ptr: *mut usize = &mut outlen;
        let ret = unsafe {
            EVP_PKEY_decrypt(
                ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                outlen_ptr,
                cipher.as_ptr(),
                cipher.len(),
            )
        };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if plain.len() == 0 {
            return Ok(outlen);
        }
        let mut tmp_plain: Option<Vec<u8>> = None;
        let plain_ptr = if plain.len() < outlen {
            if plain.len() < self.output_len {
                return Err(CKR_BUFFER_TOO_SMALL)?;
            }
            /* the PKCS#11 documentation allows modules to pass
             * in a buffer that is shorter than modulus by the
             * amount taken by padding, while openssl requires
             * a full modulus long buffer, so we need to use a
             * temporary buffer here to bridge this mismatch */
            tmp_plain = Some(vec![0u8; outlen]);
            if let Some(ref mut p) = tmp_plain.as_mut() {
                p.as_mut_ptr()
            } else {
                return Err(CKR_GENERAL_ERROR)?;
            }
        } else {
            plain.as_mut_ptr()
        };

        self.finalized = true;

        let ret = unsafe {
            EVP_PKEY_decrypt(
                ctx.as_mut_ptr(),
                plain_ptr,
                outlen_ptr,
                cipher.as_ptr(),
                cipher.len(),
            )
        };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        match tmp_plain {
            Some(p) => {
                plain[..outlen].copy_from_slice(&p[..outlen]);
            }
            None => (),
        }
        Ok(outlen)
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

                self.finalized = true;

                if let Some(ctx) = &mut self.sigctx {
                    if ctx.message_sign(data, None)? != signature.len() {
                        return Err(CKR_GENERAL_ERROR)?;
                    }
                    let _ = ctx.message_sign(data, Some(signature))?;
                } else {
                    return Err(CKR_GENERAL_ERROR)?;
                }
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

        if let Some(ctx) = &mut self.sigctx {
            Ok(ctx.message_sign_update(data)?)
        } else {
            Err(CKR_GENERAL_ERROR)?
        }
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        if let Some(ctx) = &mut self.sigctx {
            let len = ctx.message_sign_final(signature)?;
            if len != signature.len() {
                return Err(CKR_DEVICE_ERROR)?;
            }
            Ok(())
        } else {
            Err(CKR_GENERAL_ERROR)?
        }
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
                    Ok(ctx.message_verify(data, signature)?)
                } else {
                    Err(CKR_GENERAL_ERROR)?
                }
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

        if let Some(ctx) = &mut self.sigctx {
            Ok(ctx.message_verify_update(data)?)
        } else {
            Err(CKR_GENERAL_ERROR)?
        }
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

        if let Some(ctx) = &mut self.sigctx {
            Ok(ctx.message_verify_final(signature)?)
        } else {
            Err(CKR_GENERAL_ERROR)?
        }
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

#[cfg(feature = "pkcs11_3_2")]
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
