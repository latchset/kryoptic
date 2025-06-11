// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements EdDSA (Edwards-curve Digital Signature Algorithm)
//! functionalities (Ed25519, Ed448) using the OpenSSL EVP interface,
//! handling key generation, signing, verification, and parameter parsing.

use std::ffi::{c_int, CStr};

use crate::attribute::Attribute;
use crate::ec::get_ec_point_from_obj;
use crate::error::{some_or_err, Result};
use crate::mechanism::*;
use crate::misc::{bytes_to_vec, cast_params};
use crate::object::Object;
use crate::ossl::common::*;

use ossl::bindings::*;
use ossl::{EvpMdCtx, EvpPkey, OsslParam};
use pkcs11::*;

#[cfg(feature = "fips")]
use ossl::fips::ProviderSignatureCtx;

/// Expected signature length for Ed25519 in bytes.
pub const OUTLEN_ED25519: usize = 64;
/// Expected signature length for Ed448 in bytes.
pub const OUTLEN_ED448: usize = 114;

/// Parses mechanism parameters for EdDSA operations.
/// Handles both bare CKM_EDDSA and mechanisms with `CK_EDDSA_PARAMS`.
fn parse_params(mech: &CK_MECHANISM, outlen: usize) -> Result<EddsaParams> {
    if mech.mechanism != CKM_EDDSA {
        return Err(CKR_MECHANISM_INVALID)?;
    }
    match mech.ulParameterLen {
        0 => {
            if outlen == OUTLEN_ED448 {
                Err(CKR_MECHANISM_PARAM_INVALID)?
            } else {
                Ok(no_params())
            }
        }
        _ => {
            let params = cast_params!(mech, CK_EDDSA_PARAMS);
            Ok(EddsaParams {
                ph_flag: Some(if params.phFlag == CK_TRUE {
                    true
                } else {
                    false
                }),
                context_data: match params.ulContextDataLen {
                    0 => None,
                    _ => Some(bytes_to_vec!(
                        params.pContextData,
                        params.ulContextDataLen
                    )),
                },
            })
        }
    }
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

/// Helper function to create default (empty) `EddsaParams`.
fn no_params() -> EddsaParams {
    EddsaParams {
        ph_flag: None,
        context_data: None,
    }
}

/// Macro to get the appropriate OpenSSL signature context based on whether
/// the FIPS feature is enabled.
macro_rules! get_sig_ctx {
    ($key:ident) => {
        /* needless match, but otherwise rust complains about experimental attributes on
         * expressions */
        match $key {
            #[cfg(feature = "fips")]
            _ => Some(ProviderSignatureCtx::new(get_ossl_name_from_obj($key)?)?),
            #[cfg(not(feature = "fips"))]
            _ => Some(EvpMdCtx::new()?),
        }
    };
}

/// Holds parsed parameters specific to an EdDSA operation instance.
#[derive(Debug)]
struct EddsaParams {
    /// Optional pre-hashing flag (phFlag from `CK_EDDSA_PARAMS`).
    ph_flag: Option<bool>,
    /// Optional context data (from `CK_EDDSA_PARAMS`).
    context_data: Option<Vec<u8>>,
}

/// Represents an active EdDSA signing or verification operation.
#[derive(Debug)]
pub struct EddsaOperation {
    /// The specific EdDSA mechanism type (always CKM_EDDSA).
    mech: CK_MECHANISM_TYPE,
    /// Expected signature length (depends on the curve Ed25519/Ed448).
    output_len: usize,
    /// The public key used for verification (wrapped `EvpPkey`).
    public_key: Option<EvpPkey>,
    /// The private key used for signing (wrapped `EvpPkey`).
    private_key: Option<EvpPkey>,
    /// Parsed EdDSA parameters (context, ph_flag).
    params: EddsaParams,
    /// Buffer to accumulate data for multi-part operation emulation.
    data: Vec<u8>,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress.
    in_use: bool,
    /// The underlying EVP MD CTX (non fips builds)
    #[cfg(not(feature = "fips"))]
    sigctx: Option<EvpMdCtx>,
    /// The underlying wrapped `EVP_SIGNATURE` context (fips builds)
    #[cfg(feature = "fips")]
    sigctx: Option<ProviderSignatureCtx>,
    /// Optional storage for signatures, used when the signature to verify
    /// is provided at initialization
    signature: Option<Vec<u8>>,
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
        let public_key: Option<EvpPkey>;
        let private_key: Option<EvpPkey>;
        let output_len: usize;
        match flag {
            CKF_SIGN => {
                public_key = None;
                let privkey = privkey_from_object(key)?;
                output_len = 2 * ((privkey.get_bits()? + 7) / 8);
                private_key = Some(privkey);
            }
            CKF_VERIFY => {
                private_key = None;
                let pubkey = pubkey_from_object(key)?;
                output_len = 2 * ((pubkey.get_bits()? + 7) / 8);
                if let Some(s) = &signature {
                    if s.len() != output_len {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                }
                public_key = Some(pubkey);
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
        Ok(EddsaOperation {
            mech: mech.mechanism,
            output_len: output_len,
            public_key: public_key,
            private_key: private_key,
            params: parse_params(mech, output_len)?,
            data: Vec::new(),
            finalized: false,
            in_use: false,
            sigctx: get_sig_ctx!(key),
            signature: signature,
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

/// Creates an `OsslParam` array containing EdDSA-specific parameters
/// (context string, instance name like "Ed25519ph") based on the operation's
/// `EddsaParams` and curve (`outlen`), suitable for passing to OpenSSL's
/// EVP_DigestSign/VerifyInit functions.
fn sig_params<'a>(
    eddsa_params: &'a EddsaParams,
    outlen: usize,
) -> Result<OsslParam<'a>> {
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;
    match &eddsa_params.context_data {
        Some(v) => {
            params.add_octet_string(
                cstr!(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
                &v,
            )?;
        }
        _ => (),
    };

    let instance = match eddsa_params.ph_flag {
        None => match outlen {
            OUTLEN_ED25519 => b"Ed25519\0".to_vec(),
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Some(true) => match outlen {
            OUTLEN_ED448 => b"Ed448ph\0".to_vec(),
            OUTLEN_ED25519 => b"Ed25519ph\0".to_vec(),
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Some(false) => match outlen {
            OUTLEN_ED448 => b"Ed448\0".to_vec(),
            OUTLEN_ED25519 => b"Ed25519ctx\0".to_vec(),
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
    };
    params.add_owned_utf8_string(
        cstr!(OSSL_SIGNATURE_PARAM_INSTANCE),
        instance,
    )?;
    params.finalize();
    Ok(params)
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
        if !self.in_use {
            self.in_use = true;

            let mut params = sig_params(&self.params, self.output_len)?;

            #[cfg(not(feature = "fips"))]
            if unsafe {
                EVP_DigestSignInit_ex(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    osslctx().ptr(),
                    std::ptr::null(),
                    some_or_err!(mut self.private_key).as_mut_ptr(),
                    params.as_mut_ptr(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_sign_init(
                std::ptr::null_mut(),
                some_or_err!(self.private_key),
                params.as_mut_ptr(),
            )?;
        }

        /* OpenSSL API does not support multi-part operation so we need to emulate it as PKCS#11
         * supports it with this mechanism */
        self.data.extend_from_slice(data);
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

        let siglen;

        #[cfg(not(feature = "fips"))]
        {
            let mut slen = signature.len();
            let slen_ptr = &mut slen;
            if unsafe {
                EVP_DigestSign(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    signature.as_mut_ptr(),
                    slen_ptr,
                    self.data.as_ptr() as *const u8,
                    self.data.len(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
            siglen = slen;
        }

        #[cfg(feature = "fips")]
        {
            siglen = self
                .sigctx
                .as_mut()
                .unwrap()
                .digest_sign(signature, &mut self.data.as_slice())?;
        }
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
        if !self.in_use {
            self.in_use = true;

            let mut params = sig_params(&self.params, self.output_len)?;

            #[cfg(not(feature = "fips"))]
            if unsafe {
                EVP_DigestVerifyInit_ex(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    osslctx().ptr(),
                    std::ptr::null(),
                    some_or_err!(mut self.public_key).as_mut_ptr(),
                    params.as_mut_ptr(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_verify_init(
                std::ptr::null_mut(),
                some_or_err!(self.public_key),
                params.as_mut_ptr(),
            )?;
        }

        /* OpenSSL API does not support multi-part operation so we need to emulate it as PKCS#11
         * supports it with this mechanism */
        self.data.extend_from_slice(data);
        Ok(())
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

        let sig = match signature {
            Some(s) => s,
            None => match &self.signature {
                Some(s) => s.as_slice(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };

        #[cfg(not(feature = "fips"))]
        if unsafe {
            EVP_DigestVerify(
                self.sigctx.as_mut().unwrap().as_mut_ptr(),
                sig.as_ptr(),
                sig.len(),
                self.data.as_ptr(),
                self.data.len(),
            )
        } != 1
        {
            return Err(CKR_SIGNATURE_INVALID)?;
        }

        #[cfg(feature = "fips")]
        self.sigctx
            .as_mut()
            .unwrap()
            .digest_verify(sig, &mut self.data.as_slice())?;

        Ok(())
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
