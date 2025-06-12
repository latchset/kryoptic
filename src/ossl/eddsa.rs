// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements EdDSA (Edwards-curve Digital Signature Algorithm)
//! functionalities (Ed25519, Ed448) using the OpenSSL EVP interface,
//! handling key generation, signing, verification, and parameter parsing.

use std::ffi::{c_int, CStr};

use crate::attribute::Attribute;
use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::mechanism::*;
use crate::misc::{bytes_to_vec, cast_params};
use crate::object::Object;
use crate::ossl::common::*;

use ossl::bindings::*;
use ossl::{
    eddsa_params, ErrorKind, EvpPkey, OsslParam, OsslSignature, SigAlg,
};
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

/// Converts a PKCS#11 EdDSA key `Object` into OpenSSL parameters (`OsslParam`).
///
/// Extracts the curve name (Ed25519/Ed448) and relevant key components
/// (public point or private value) based on the object `class` and populates
/// an `OsslParam` structure suitable for creating an OpenSSL `EvpPkey`.
pub fn eddsa_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(&'static CStr, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    let mut params = OsslParam::with_capacity(1);
    params.zeroize = true;

    let name = get_ossl_name_from_obj(key)?;

    match kclass {
        CKO_PUBLIC_KEY => {
            params.add_owned_octet_string(
                cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                get_ec_point_from_obj(key)?,
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_octet_string(
                cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?,
            )?;
        }

        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    Ok((name, params))
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
    #[cfg(feature = "pkcs11_3_2")]
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
        let evp_pkey = EvpPkey::generate(
            osslctx(),
            get_ossl_name_from_obj(pubkey)?,
            &OsslParam::empty(),
        )?;

        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_todata(
                evp_pkey.as_ptr(),
                c_int::try_from(EVP_PKEY_KEYPAIR)?,
                &mut params,
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let params = OsslParam::from_ptr(params)?;
        /* Public Key */
        let point = params
            .get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY))?
            .to_vec();
        pubkey.set_attr(Attribute::from_bytes(CKA_EC_POINT, point))?;

        /* Private Key */
        let value = params
            .get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY))?
            .to_vec();
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, value))?;
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

#[cfg(feature = "pkcs11_3_2")]
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
