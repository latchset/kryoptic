// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::c_char;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{MechOperation, Sign, Verify, VerifySignature};
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;
use crate::{bytes_to_vec, cast_params};

/* Max buffer size when OpenSSL does not support the
 * message_update() interfaces and we need to accumulate */
const MAX_BUFFER_LEN: usize = 1024 * 1024;

/* Openssl Key types */
static ML_DSA_44_TYPE: &[u8; 10] = b"ML-DSA-44\0";
static ML_DSA_65_TYPE: &[u8; 10] = b"ML-DSA-65\0";
static ML_DSA_87_TYPE: &[u8; 10] = b"ML-DSA-87\0";

const ML_DSA_44_SIG_SIZE: usize = 2420;
const ML_DSA_65_SIG_SIZE: usize = 3309;
const ML_DSA_87_SIG_SIZE: usize = 4627;

pub fn mldsa_param_set_to_name(
    pset: CK_ML_DSA_PARAMETER_SET_TYPE,
) -> Result<*const c_char> {
    match pset {
        CKP_ML_DSA_44 => Ok(name_as_char(ML_DSA_44_TYPE)),
        CKP_ML_DSA_65 => Ok(name_as_char(ML_DSA_65_TYPE)),
        CKP_ML_DSA_87 => Ok(name_as_char(ML_DSA_87_TYPE)),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

pub fn mldsa_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(*const c_char, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    let mut params = OsslParam::with_capacity(3);
    params.zeroize = true;

    match kclass {
        CKO_PUBLIC_KEY => {
            params.add_owned_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PUB_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.to_vec(),
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_owned_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.to_vec(),
            )?;
            match key.get_attr_as_bytes(CKA_SEED) {
                Ok(s) => params.add_owned_octet_string(
                    name_as_char(OSSL_PKEY_PARAM_ML_DSA_SEED),
                    s.to_vec(),
                )?,
                Err(_) => (),
            }
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    let param_set = key.get_attr_as_ulong(CKA_PARAMETER_SET)?;
    Ok((mldsa_param_set_to_name(param_set)?, params))
}

#[derive(Debug)]
struct MlDsaParams {
    param_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    hedge: CK_HEDGE_TYPE,
    context: Option<Vec<u8>>,
    hash: CK_MECHANISM_TYPE,
    sigsize: usize,
}

impl MlDsaParams {
    pub fn new(
        mech: &CK_MECHANISM,
        param_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    ) -> Result<MlDsaParams> {
        let mut mldsa_params = MlDsaParams {
            param_set: param_set,
            hedge: CKH_HEDGE_PREFERRED,
            context: None,
            hash: CK_UNAVAILABLE_INFORMATION,
            sigsize: match param_set {
                CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE,
                CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE,
                CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE,
                _ => return Err(CKR_KEY_INDIGESTIBLE)?,
            },
        };

        if !mech.pParameter.is_null() {
            match mech.mechanism {
                CKM_ML_DSA => {
                    let params = cast_params!(mech, CK_SIGN_ADDITIONAL_CONTEXT);
                    match params.hedgeVariant {
                        CKH_HEDGE_PREFERRED
                        | CKH_HEDGE_REQUIRED
                        | CKH_DETERMINISTIC_REQUIRED => (),
                        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                    }
                    mldsa_params.hedge = params.hedgeVariant;
                    if params.ulContextLen > 0 {
                        mldsa_params.context = Some(bytes_to_vec!(
                            params.pContext,
                            params.ulContextLen
                        ));
                    }
                }
                CKM_HASH_ML_DSA
                | CKM_HASH_ML_DSA_SHA224
                | CKM_HASH_ML_DSA_SHA256
                | CKM_HASH_ML_DSA_SHA384
                | CKM_HASH_ML_DSA_SHA512
                | CKM_HASH_ML_DSA_SHA3_224
                | CKM_HASH_ML_DSA_SHA3_256
                | CKM_HASH_ML_DSA_SHA3_384
                | CKM_HASH_ML_DSA_SHA3_512
                | CKM_HASH_ML_DSA_SHAKE128
                | CKM_HASH_ML_DSA_SHAKE256 => {
                    let params =
                        cast_params!(mech, CK_HASH_SIGN_ADDITIONAL_CONTEXT);
                    match params.hedgeVariant {
                        CKH_HEDGE_PREFERRED
                        | CKH_HEDGE_REQUIRED
                        | CKH_DETERMINISTIC_REQUIRED => (),
                        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                    }
                    mldsa_params.hedge = params.hedgeVariant;
                    if params.ulContextLen > 0 {
                        mldsa_params.context = Some(bytes_to_vec!(
                            params.pContext,
                            params.ulContextLen
                        ));
                    }
                    mldsa_params.hash = params.hash;
                }
                _ => return Err(CKR_MECHANISM_INVALID)?,
            }
        }
        Ok(mldsa_params)
    }

    fn ossl_params(&self, sign: bool) -> Result<OsslParam> {
        let mut params = OsslParam::with_capacity(1);
        if let Some(ctx) = &self.context {
            params.add_octet_string(
                name_as_char(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
                ctx,
            )?;
        }
        /* from the spec:
         * On verification the hedgeVariant parameter is ignored. */
        if sign {
            if self.hedge == CKH_DETERMINISTIC_REQUIRED {
                params.add_owned_int(
                    name_as_char(OSSL_SIGNATURE_PARAM_DETERMINISTIC),
                    1,
                )?;
            }
        }
        params.finalize();

        Ok(params)
    }
}

#[derive(Debug)]
pub struct MlDsaOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    in_use: bool,
    params: MlDsaParams,
    sigctx: EvpPkeyCtx,
    signature: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
}

impl MechOperation for MlDsaOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        Some(true)
    }
}

fn check_signature(
    pset: CK_ML_DSA_PARAMETER_SET_TYPE,
    sig: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    Ok(if let Some(s) = sig {
        if s.len()
            != match pset {
                CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE,
                CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE,
                CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE,
                _ => return Err(CKR_GENERAL_ERROR)?,
            }
        {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        Some(s.to_vec())
    } else {
        None
    })
}

impl MlDsaOperation {
    pub fn sigver_new(
        mech: &CK_MECHANISM,
        key: &Object,
        flag: CK_FLAGS,
        signature: Option<&[u8]>,
    ) -> Result<MlDsaOperation> {
        let param_set = key.get_attr_as_ulong(CKA_PARAMETER_SET)?;
        let mldsa_params = MlDsaParams::new(mech, param_set)?;
        let sigctx = match flag {
            CKF_SIGN => {
                let mut privkey = EvpPkey::privkey_from_object(key)?;
                privkey.new_ctx()?
            }
            CKF_VERIFY => {
                let mut pubkey = EvpPkey::pubkey_from_object(key)?;
                pubkey.new_ctx()?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let sig = check_signature(param_set, signature)?;

        Ok(MlDsaOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            params: mldsa_params,
            sigctx: sigctx,
            signature: sig,
            data: None,
        })
    }

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

    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            self.in_use = true;

            let mut params = OsslParam::with_capacity(1);
            if let Some(ctx) = &self.params.context {
                params.add_octet_string(
                    name_as_char(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
                    ctx,
                )?;
            }
            params.finalize();

            let mut sig_alg = EvpSignature::new(mldsa_param_set_to_name(
                self.params.param_set,
            )?)?;

            let res = unsafe {
                EVP_PKEY_verify_message_init(
                    self.sigctx.as_mut_ptr(),
                    sig_alg.as_mut_ptr(),
                    self.params.ossl_params(false)?.as_ptr(),
                )
            };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }

            /* OpenSSL 3.5 implements only one shot ML-DSA,
             * while later implementations can deal with
             * update()/final() operations. Probe here, and
             * set up a backup buffer if update()s are not
             * supported.
             */
            if unsafe {
                EVP_PKEY_verify_message_update(
                    self.sigctx.as_mut_ptr(),
                    std::ptr::null(),
                    0,
                )
            } != 1
            {
                self.data = Some(Vec::<u8>::new());
            }
        }

        if let Some(buffer) = &mut self.data {
            /* No support for update()s, try to accumulate */
            if buffer.len() + data.len() > MAX_BUFFER_LEN {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
            buffer.extend_from_slice(data);
        } else {
            if unsafe {
                EVP_PKEY_verify_message_update(
                    self.sigctx.as_mut_ptr(),
                    data.as_ptr(),
                    data.len(),
                )
            } != 1
            {
                self.finalized = true;
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        Ok(())
    }

    fn verify_int_final(&mut self, signature: Option<&[u8]>) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        self.finalized = true;

        let sig = match signature {
            Some(s) => match &self.signature {
                Some(_) => return Err(CKR_GENERAL_ERROR)?,
                None => s,
            },
            None => match &self.signature {
                Some(s) => s,
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };

        if let Some(buffer) = &self.data {
            /* No support for final()s, must use EVP_PKEY_verify */
            if unsafe {
                EVP_PKEY_verify(
                    self.sigctx.as_mut_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    buffer.as_ptr(),
                    buffer.len(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        } else {
            if unsafe {
                EVP_PKEY_CTX_set_signature(
                    self.sigctx.as_mut_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
            if unsafe {
                EVP_PKEY_verify_message_final(self.sigctx.as_mut_ptr())
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        Ok(())
    }
}

impl Sign for MlDsaOperation {
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

            let mut sig_alg = EvpSignature::new(mldsa_param_set_to_name(
                self.params.param_set,
            )?)?;

            let res = unsafe {
                EVP_PKEY_sign_message_init(
                    self.sigctx.as_mut_ptr(),
                    sig_alg.as_mut_ptr(),
                    self.params.ossl_params(true)?.as_ptr(),
                )
            };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }

            /* OpenSSL 3.5 implements only one shot ML-DSA,
             * while later implementations can deal with
             * update()/final() operations. Probe here, and
             * set up a backup buffer if update()s are not
             * supported.
             */
            if unsafe {
                EVP_PKEY_sign_message_update(
                    self.sigctx.as_mut_ptr(),
                    std::ptr::null(),
                    0,
                )
            } != 1
            {
                self.data = Some(Vec::<u8>::new());
            }
        }

        if let Some(buffer) = &mut self.data {
            /* No support for update()s, try to accumulate */
            if buffer.len() + data.len() > MAX_BUFFER_LEN {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
            buffer.extend_from_slice(data);
        } else {
            if unsafe {
                EVP_PKEY_sign_message_update(
                    self.sigctx.as_mut_ptr(),
                    data.as_ptr(),
                    data.len(),
                )
            } != 1
            {
                self.finalized = true;
                return Err(CKR_DEVICE_ERROR)?;
            }
        }
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

        let mut siglen = signature.len();
        let siglen_ptr: *mut usize = &mut siglen;

        if let Some(buffer) = &self.data {
            /* No support for final()s, must use EVP_PKEY_sign */
            if unsafe {
                EVP_PKEY_sign(
                    self.sigctx.as_mut_ptr(),
                    signature.as_mut_ptr(),
                    siglen_ptr,
                    buffer.as_ptr(),
                    buffer.len(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        } else {
            if unsafe {
                EVP_PKEY_sign_message_final(
                    self.sigctx.as_mut_ptr(),
                    signature.as_mut_ptr(),
                    siglen_ptr,
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        if siglen != signature.len() {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.params.sigsize)
    }
}

impl Verify for MlDsaOperation {
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
        Ok(self.params.sigsize)
    }
}

impl VerifySignature for MlDsaOperation {
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

pub fn generate_keypair(
    param_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    pubkey: &mut Object,
    privkey: &mut Object,
) -> Result<()> {
    let evp_pkey = EvpPkey::generate(
        mldsa_param_set_to_name(param_set)?,
        &OsslParam::empty(),
    )?;

    let params = evp_pkey.todata(EVP_PKEY_KEYPAIR)?;

    let val = params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?;
    pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, val.to_vec()))?;

    let val =
        params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?;
    privkey.set_attr(Attribute::from_bytes(CKA_VALUE, val.to_vec()))?;

    match params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_ML_DSA_SEED)) {
        Ok(val) => {
            privkey.set_attr(Attribute::from_bytes(CKA_SEED, val.to_vec()))?
        }
        Err(e) => {
            if !e.attr_not_found() {
                return Err(e);
            }
        }
    }
    Ok(())
}
