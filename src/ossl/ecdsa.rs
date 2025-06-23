// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements ECDSA (Elliptic Curve Digital Signature Algorithm)
//! functionalities using the OpenSSL EVP interface, including key generation,
//! signing, verification, and signature format conversions.

use crate::attribute::Attribute;
use crate::ec::ecdsa::*;
use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::kasn1::DerEncBigUint;
use crate::mechanism::*;
use crate::misc::zeromem;
use crate::object::Object;
use crate::ossl::common::*;

use ossl::pkey::{EccData, EvpPkey, PkeyData};
use ossl::signature::{OsslSignature, SigAlg};
use pkcs11::*;

/// Converts a PKCS#11 EC key `Object` into an `EvpPkey`.
///
/// Extracts the curve type and relevant key components (public point or private
/// value) based on the object `class` and populates an `EccData` structure
/// suitable for creating an `EvpPkey`.
pub fn ecc_object_to_pkey(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<EvpPkey> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    match kclass {
        CKO_PUBLIC_KEY => Ok(EvpPkey::import(
            osslctx(),
            get_evp_pkey_type_from_obj(key)?,
            PkeyData::Ecc(EccData {
                pubkey: Some(get_ec_point_from_obj(key)?),
                prikey: None,
            }),
        )?),
        CKO_PRIVATE_KEY => Ok(EvpPkey::import(
            osslctx(),
            get_evp_pkey_type_from_obj(key)?,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(key.get_attr_as_bytes(CKA_VALUE)?.clone()),
            }),
        )?),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }
}

/// ASN.1 structure for an ECDSA signature value (SEQUENCE of two INTEGERs).
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct EcdsaSignature<'a> {
    r: DerEncBigUint<'a>,
    s: DerEncBigUint<'a>,
}

/// Copies one half (r or s) of an ECDSA signature from an input slice `hin`
/// to an output slice `hout` of potentially different (but sufficient) length,
/// handling necessary padding or truncation of leading zeros.
fn slice_to_sig_half(hin: &[u8], hout: &mut [u8]) -> Result<()> {
    let mut len = hin.len();
    if len > hout.len() {
        /* check for leading zeros */
        for i in 0..hin.len() {
            if hin[i] != 0 {
                break;
            }
            len -= 1;
        }
        if len == 0 || len > hout.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
    }
    let ipad = hin.len() - len;
    let opad = hout.len() - len;
    if opad > 0 {
        hout[0..opad].fill(0);
    }
    hout[opad..].copy_from_slice(&hin[ipad..]);
    Ok(())
}

/// Convert OpenSSL ECDSA signature to PKCS #11 format
///
/// The OpenSSL ECDSA signature is DER encoded SEQUENCE of r and s values.
/// The PKCS #11 is representing the signature only using the two concatenated bignums
/// padded with zeroes to the fixed length.
/// This means we here parse the numbers from the DER encoding and construct fixed length
/// buffer with padding if needed.
/// Do not care if the first bit is 1 as in PKCS #11 we interpret the number always positive
fn ossl_to_pkcs11_signature(
    ossl_sign: &Vec<u8>,
    signature: &mut [u8],
) -> Result<()> {
    let sig = match asn1::parse_single::<EcdsaSignature>(ossl_sign.as_slice()) {
        Ok(a) => a,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let bn_len = signature.len() / 2;
    slice_to_sig_half(sig.r.as_bytes(), &mut signature[..bn_len])?;
    slice_to_sig_half(sig.s.as_bytes(), &mut signature[bn_len..])
}

/// Convert PKCS #11 ECDSA signature to OpenSSL format
///
/// The PKCS #11 represents the ECDSA signature only as a two padded values of fixed length.
/// The OpenSSL expects the signature to be DER encoded SEQUENCE of two bignums so
/// we split here the provided buffer and wrap it with the DER encoding.
fn pkcs11_to_ossl_signature(signature: &[u8]) -> Result<Vec<u8>> {
    let bn_len = signature.len() / 2;
    let sig = EcdsaSignature {
        r: DerEncBigUint::new(&signature[..bn_len])?,
        s: DerEncBigUint::new(&signature[bn_len..])?,
    };
    let ossl_sign = match asn1::write_single(&sig) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(ossl_sign)
}

/// Helper function to convert PKCS#11 mechanism type to name
/// understood by the ossl package.
pub fn ecdsa_type_to_ossl_alg(mech: CK_MECHANISM_TYPE) -> Result<SigAlg> {
    Ok(match mech {
        CKM_ECDSA => SigAlg::Ecdsa,
        CKM_ECDSA_SHA1 => SigAlg::EcdsaSha1,
        CKM_ECDSA_SHA224 => SigAlg::EcdsaSha2_224,
        CKM_ECDSA_SHA256 => SigAlg::EcdsaSha2_256,
        CKM_ECDSA_SHA384 => SigAlg::EcdsaSha2_384,
        CKM_ECDSA_SHA512 => SigAlg::EcdsaSha2_512,
        CKM_ECDSA_SHA3_224 => SigAlg::EcdsaSha3_224,
        CKM_ECDSA_SHA3_256 => SigAlg::EcdsaSha3_256,
        CKM_ECDSA_SHA3_384 => SigAlg::EcdsaSha3_384,
        CKM_ECDSA_SHA3_512 => SigAlg::EcdsaSha3_512,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

/// Represents an active ECDSA signing or verification operation.
#[derive(Debug)]
pub struct EcdsaOperation {
    /// The specific ECDSA mechanism type (e.g., CKM_ECDSA_SHA256).
    mech: CK_MECHANISM_TYPE,
    /// Expected output length of the signature in bytes (2 * field size).
    output_len: usize,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress.
    in_use: bool,
    /// The OpenSSL Wrapper Signature Context
    sigctx: OsslSignature,
}

impl EcdsaOperation {
    /// Helper function to create a new boxed `EcdsaMechanism`.
    fn new_mechanism() -> Box<dyn Mechanism> {
        Box::new(EcdsaMechanism::new(
            CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
            CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
            CKF_SIGN | CKF_VERIFY,
        ))
    }

    /// Registers all supported ECDSA mechanisms with the `Mechanisms` registry.
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[
            CKM_ECDSA,
            CKM_ECDSA_SHA1,
            CKM_ECDSA_SHA224,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
            CKM_ECDSA_SHA3_224,
            CKM_ECDSA_SHA3_256,
            CKM_ECDSA_SHA3_384,
            CKM_ECDSA_SHA3_512,
        ] {
            mechs.add_mechanism(*ckm, Self::new_mechanism());
        }

        mechs.add_mechanism(
            CKM_EC_KEY_PAIR_GEN,
            Box::new(EcdsaMechanism::new(
                CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
                CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
                CKF_GENERATE_KEY_PAIR,
            )),
        );
    }

    /// Internal constructor to create a new `EcdsaOperation`.
    ///
    /// Sets up the internal state based on whether it's a signature or
    /// verification operation, imports the provided key, and calculates
    /// the expected signature length.
    fn new_op(
        flag: CK_FLAGS,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<Vec<u8>>,
    ) -> Result<EcdsaOperation> {
        let output_len: usize;
        let mut sigctx = match flag {
            CKF_SIGN => {
                let mut pkey = privkey_from_object(key)?;
                output_len = 2 * ((pkey.get_bits()? + 7) / 8);
                OsslSignature::message_sign_new(
                    osslctx(),
                    ecdsa_type_to_ossl_alg(mech.mechanism)?,
                    &mut pkey,
                    None,
                )?
            }
            CKF_VERIFY => {
                let mut pkey = pubkey_from_object(key)?;
                output_len = 2 * ((pkey.get_bits()? + 7) / 8);
                if let Some(s) = &signature {
                    if s.len() != output_len {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                }
                OsslSignature::message_verify_new(
                    osslctx(),
                    ecdsa_type_to_ossl_alg(mech.mechanism)?,
                    &mut pkey,
                    None,
                )?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        if let Some(s) = &signature {
            if s.len() != output_len {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }
            let mut sig = pkcs11_to_ossl_signature(s)?;
            sigctx.set_signature(sig.as_slice())?;
            zeromem(sig.as_mut_slice());
        }
        Ok(EcdsaOperation {
            mech: mech.mechanism,
            output_len: output_len,
            finalized: false,
            in_use: false,
            sigctx: sigctx,
        })
    }

    /// Creates a new `EcdsaOperation` for signing.
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EcdsaOperation> {
        Self::new_op(CKF_SIGN, mech, key, None)
    }

    /// Creates a new `EcdsaOperation` for verification.
    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EcdsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, None)
    }

    /// Creates a new `EcdsaOperation` for verification with a pre-supplied
    /// signature.
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<EcdsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, Some(signature.to_vec()))
    }

    /// Generates an EC key pair using OpenSSL.
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s (which contain the desired curve in CKA_EC_PARAMS),
    /// generates the key pair, and populates the CKA_EC_POINT and CKA_VALUE
    /// attributes.
    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let pkey =
            EvpPkey::generate(osslctx(), get_evp_pkey_type_from_obj(pubkey)?)?;
        let ecc = match pkey.export()? {
            PkeyData::Ecc(e) => e,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        /* Set Public Key */
        if let Some(key) = ecc.pubkey {
            let point_encoded = match asn1::write_single(&key.as_slice()) {
                Ok(b) => b,
                Err(_) => return Err(CKR_GENERAL_ERROR)?,
            };
            pubkey
                .set_attr(Attribute::from_bytes(CKA_EC_POINT, point_encoded))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        /* Set Private Key */
        if let Some(key) = ecc.prikey {
            privkey.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }
}

impl MechOperation for EcdsaOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for EcdsaOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.mech == CKM_ECDSA {
            self.finalized = true;
            if signature.len() != self.output_len {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }

            let mut sig = vec![0u8; self.sigctx.message_sign(data, None)?];
            let len =
                self.sigctx.message_sign(data, Some(sig.as_mut_slice()))?;
            sig.resize(len, 0);
            let ret = ossl_to_pkcs11_signature(&sig, signature);
            zeromem(sig.as_mut_slice());
            return ret;
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.mech == CKM_ECDSA {
            self.finalized = true;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        Ok(self.sigctx.message_sign_update(data)?)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        let mut sig = vec![0u8; signature.len() + 10];

        let len = self.sigctx.message_sign_final(sig.as_mut_slice())?;
        if len > sig.len() {
            return Err(CKR_DEVICE_ERROR)?;
        }

        /* can only shrink */
        sig.resize(len, 0);

        let ret = ossl_to_pkcs11_signature(&sig, signature);
        zeromem(sig.as_mut_slice());
        ret
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl EcdsaOperation {
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
        if self.mech == CKM_ECDSA {
            self.finalized = true;
            if let Some(s) = &signature {
                if s.len() != self.output_len {
                    return Err(CKR_SIGNATURE_LEN_RANGE)?;
                }
                let mut sig = pkcs11_to_ossl_signature(s)?;
                let ret =
                    self.sigctx.message_verify(data, Some(sig.as_slice()));
                zeromem(sig.as_mut_slice());
                return Ok(ret?);
            } else {
                return Ok(self.sigctx.message_verify(data, None)?);
            }
        }
        self.verify_int_update(data)?;
        self.verify_int_final(signature)
    }

    /// Internal helper for updating a multi-part verification.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.mech == CKM_ECDSA {
            self.finalized = true;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        Ok(self.sigctx.message_verify_update(data)?)
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

        // convert PKCS #11 signature to OpenSSL format
        if let Some(s) = &signature {
            if s.len() != self.output_len {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }
            let mut sig = pkcs11_to_ossl_signature(s)?;
            let ret = self.sigctx.message_verify_final(Some(sig.as_slice()));
            zeromem(sig.as_mut_slice());
            Ok(ret?)
        } else {
            Ok(self.sigctx.message_verify_final(None)?)
        }
    }
}

impl Verify for EcdsaOperation {
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

impl VerifySignature for EcdsaOperation {
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
