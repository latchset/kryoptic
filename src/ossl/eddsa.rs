// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use std::ffi::{c_char, c_int};

use crate::attribute::Attribute;
use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::*;
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;
use crate::{bytes_to_vec, cast_params, some_or_err};

#[cfg(feature = "fips")]
use crate::ossl::fips::*;

#[cfg(not(feature = "fips"))]
use crate::ossl::get_libctx;

pub const OUTLEN_ED25519: usize = 64;
pub const OUTLEN_ED448: usize = 114;

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

pub fn eddsa_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(*const c_char, OsslParam)> {
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
                name_as_char(OSSL_PKEY_PARAM_PUB_KEY),
                get_ec_point_from_obj(key)?,
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?,
            )?;
        }

        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    Ok((name_as_char(name), params))
}

fn no_params() -> EddsaParams {
    EddsaParams {
        ph_flag: None,
        context_data: None,
    }
}

macro_rules! get_sig_ctx {
    ($key:ident) => {
        /* needless match, but otherwise rust complains about experimental attributes on
         * expressions */
        match $key {
            #[cfg(feature = "fips")]
            _ => Some(ProviderSignatureCtx::new(get_ossl_name_from_obj($key)?.as_ptr() as *const i8)?),
            #[cfg(not(feature = "fips"))]
            _ => Some(EvpMdCtx::new()?),
        }
    };
}

#[derive(Debug)]
struct EddsaParams {
    ph_flag: Option<bool>,
    context_data: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct EddsaOperation {
    mech: CK_MECHANISM_TYPE,
    output_len: usize,
    public_key: Option<EvpPkey>,
    private_key: Option<EvpPkey>,
    params: EddsaParams,
    data: Vec<u8>,
    finalized: bool,
    in_use: bool,
    #[cfg(not(feature = "fips"))]
    sigctx: Option<EvpMdCtx>,
    #[cfg(feature = "fips")]
    sigctx: Option<ProviderSignatureCtx>,
}

impl EddsaOperation {
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        let privkey = EvpPkey::privkey_from_object(key)?;
        let outlen = 2 * ((privkey.get_bits()? + 7) / 8);
        Ok(EddsaOperation {
            mech: mech.mechanism,
            output_len: outlen,
            public_key: None,
            private_key: Some(privkey),
            params: parse_params(mech, outlen)?,
            data: Vec::new(),
            finalized: false,
            in_use: false,
            sigctx: get_sig_ctx!(key),
        })
    }

    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        let pubkey = EvpPkey::pubkey_from_object(key)?;
        let outlen = 2 * ((pubkey.get_bits()? + 7) / 8);
        Ok(EddsaOperation {
            mech: mech.mechanism,
            output_len: outlen,
            public_key: Some(pubkey),
            private_key: None,
            params: parse_params(mech, outlen)?,
            data: Vec::new(),
            finalized: false,
            in_use: false,
            sigctx: get_sig_ctx!(key),
        })
    }

    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let evp_pkey = EvpPkey::generate(
            get_ossl_name_from_obj(pubkey)?.as_ptr() as *const c_char,
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
            .get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?
            .to_vec();
        pubkey.set_attr(Attribute::from_bytes(CKA_EC_POINT, point))?;

        /* Private Key */
        let value = params
            .get_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?
            .to_vec();
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, value))?;
        Ok(())
    }
}

fn sig_params<'a>(
    eddsa_params: &'a EddsaParams,
    outlen: usize,
) -> Result<OsslParam<'a>> {
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;
    match &eddsa_params.context_data {
        Some(v) => {
            params.add_octet_string(
                name_as_char(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
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
        name_as_char(OSSL_SIGNATURE_PARAM_INSTANCE),
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
                    get_libctx(),
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

impl Verify for EddsaOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.verify_update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
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
                    get_libctx(),
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

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        self.finalized = true;

        #[cfg(not(feature = "fips"))]
        if unsafe {
            EVP_DigestVerify(
                self.sigctx.as_mut().unwrap().as_mut_ptr(),
                signature.as_ptr(),
                signature.len(),
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
            .digest_verify(&signature, &mut self.data.as_slice())?;

        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}
