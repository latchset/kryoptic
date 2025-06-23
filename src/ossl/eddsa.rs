// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements EdDSA (Edwards-curve Digital Signature Algorithm)
//! functionalities (Ed25519, Ed448) using the OpenSSL EVP interface,
//! handling key generation, signing, verification, and parameter parsing.

use crate::attribute::Attribute;
use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::mechanism::*;
use crate::misc::{bytes_to_vec, cast_params};
use crate::object::Object;
use crate::ossl::common::*;

use ossl::pkey::{EccData, EvpPkey, PkeyData};
use ossl::signature::{eddsa_params, OsslSignature, SigAlg};
use ossl::ErrorKind;
use pkcs11::*;

/// Expected signature length for Ed25519 in bytes.
pub const OUTLEN_ED25519: usize = 64;
/// Expected signature length for Ed448 in bytes.
pub const OUTLEN_ED448: usize = 114;

/// Parses mechanism parameters for EdDSA operations.
/// Handles both bare CKM_EDDSA and mechanisms with `CK_EDDSA_PARAMS`.
fn parse_params(
    mech: &CK_MECHANISM,
    outlen: usize,
) -> Result<(SigAlg, Option<Vec<u8>>)> {
    if mech.mechanism != CKM_EDDSA {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    if mech.ulParameterLen == 0 {
        if outlen == OUTLEN_ED448 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        } else {
            return Ok((SigAlg::Ed25519, None));
        }
    }

    let params = cast_params!(mech, CK_EDDSA_PARAMS);
    let ctx = match params.ulContextDataLen {
        0 => None,
        _ => Some(bytes_to_vec!(params.pContextData, params.ulContextDataLen)),
    };
    if outlen == OUTLEN_ED25519 {
        if params.phFlag == CK_TRUE {
            return Ok((SigAlg::Ed25519ph, ctx));
        } else {
            return Ok((SigAlg::Ed25519ctx, ctx));
        }
    }
    if outlen == OUTLEN_ED448 {
        if params.phFlag == CK_TRUE {
            return Ok((SigAlg::Ed448ph, ctx));
        } else {
            return Ok((SigAlg::Ed448, ctx));
        }
    }
    return Err(CKR_MECHANISM_PARAM_INVALID)?;
}

/// Converts a PKCS#11 EdDSA key `Object` into an `EvpPkey`.
///
/// Extracts the curve type and relevant key components (public point or
/// private value) based on the object `class` and populates an `EccData`
/// structure suitable for creating an `EvpPkey`.
pub fn eddsa_object_to_pkey(
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

/// Represents an active EdDSA signing or verification operation.
#[derive(Debug)]
pub struct EddsaOperation {
    /// The specific EdDSA mechanism type (always CKM_EDDSA).
    mech: CK_MECHANISM_TYPE,
    /// Expected signature length (depends on the curve Ed25519/Ed448).
    output_len: usize,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress.
    in_use: bool,
    /// The OpenSSL Wrapper Signature Context
    sigctx: OsslSignature,
}

impl EddsaOperation {
    /// Internal constructor to create a new `EddsaOperation`.
    ///
    /// Sets up the internal state based on whether it's a signature or
    /// verification operation, imports the provided key, calculates the
    /// expected signature length, and parses mechanism parameters.
    fn new_op(
        flag: CK_FLAGS,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<Vec<u8>>,
    ) -> Result<EddsaOperation> {
        let output_len: usize;
        let mut sigctx = match flag {
            CKF_SIGN => {
                let mut pkey = privkey_from_object(key)?;
                output_len = 2 * ((pkey.get_bits()? + 7) / 8);
                let (sigalg, context) = parse_params(mech, output_len)?;
                let params = eddsa_params(sigalg, context)?;
                OsslSignature::message_sign_new(
                    osslctx(),
                    sigalg,
                    &mut pkey,
                    params.as_ref(),
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
                let (sigalg, context) = parse_params(mech, output_len)?;
                let params = eddsa_params(sigalg, context)?;
                OsslSignature::message_verify_new(
                    osslctx(),
                    sigalg,
                    &mut pkey,
                    params.as_ref(),
                )?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        if let Some(sig) = &signature {
            sigctx.set_signature(sig)?;
        }
        Ok(EddsaOperation {
            mech: mech.mechanism,
            output_len: output_len,
            finalized: false,
            in_use: false,
            sigctx: sigctx,
        })
    }

    /// Creates a new `EddsaOperation` for signing.
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        Self::new_op(CKF_SIGN, mech, key, None)
    }

    /// Creates a new `EddsaOperation` for verification.
    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, None)
    }

    /// Creates a new `EddsaOperation` for verification with a pre-supplied
    /// signature.
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<EddsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, Some(signature.to_vec()))
    }

    /// Generates an EdDSA key pair (Ed25519 or Ed448) using OpenSSL.
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
            pubkey.set_attr(Attribute::from_bytes(CKA_EC_POINT, key))?;
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

impl MechOperation for EddsaOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for EddsaOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        match self.sigctx.message_sign_update(data) {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.kind() == ErrorKind::BufferSize {
                    Err(CKR_TOKEN_RESOURCE_EXCEEDED)?
                } else {
                    Err(e)?
                }
            }
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

        let siglen = self.sigctx.message_sign_final(signature)?;
        if siglen != signature.len() {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl EddsaOperation {
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
        self.verify_int_update(data)?;
        self.verify_int_final(signature)
    }

    /// Internal helper for updating a multi-part verification. Accumulates
    /// data.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        match self.sigctx.message_verify_update(data) {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.kind() == ErrorKind::BufferSize {
                    Err(CKR_TOKEN_RESOURCE_EXCEEDED)?
                } else {
                    Err(e)?
                }
            }
        }
    }

    /// Internal helper for the final step of multi-part verification using
    /// accumulated data.
    fn verify_int_final(&mut self, signature: Option<&[u8]>) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        self.finalized = true;

        if self.sigctx.message_verify_final(signature).is_ok() {
            return Ok(());
        }

        return Err(CKR_SIGNATURE_INVALID)?;
    }
}

impl Verify for EddsaOperation {
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

impl VerifySignature for EddsaOperation {
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
