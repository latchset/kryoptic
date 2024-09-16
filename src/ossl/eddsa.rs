// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

use super::mechanism;
use super::{cast_params, some_or_err};

use mechanism::*;

use std::ffi::{c_char, c_int};

// TODO could probably reuse the ECC one as its the same?
pub fn eddsa_import(obj: &mut Object) -> Result<()> {
    bytes_attr_not_empty!(obj; CKA_EC_PARAMS);
    bytes_attr_not_empty!(obj; CKA_VALUE);
    Ok(())
}

/* confusingly enough, this is not EC for FIPS-level operations  */
#[cfg(feature = "fips")]
static ECDSA_NAME: &[u8; 6] = b"EDDSA\0";

#[derive(Debug)]
struct EddsaParams {
    ph_flag: Option<bool>,
    context_data: Option<Vec<u8>>,
}

#[cfg(not(feature = "fips"))]
#[derive(Debug)]
struct EddsaOperation {
    mech: CK_MECHANISM_TYPE,
    output_len: usize,
    public_key: Option<EvpPkey>,
    private_key: Option<EvpPkey>,
    params: EddsaParams,
    is448: bool,
    data: Vec<u8>,
    finalized: bool,
    in_use: bool,
    sigctx: Option<EvpMdCtx>,
}

#[cfg(feature = "fips")]
#[derive(Debug)]
struct EddsaOperation {
    output_len: usize,
    public_key: Option<EvpPkey>,
    private_key: Option<EvpPkey>,
    params: EddsaParams,
    is448: bool,
    data: Vec<u8>,
    finalized: bool,
    in_use: bool,
    sigctx: Option<ProviderSignatureCtx>,
}

static OSSL_ED25519: &[u8; 8] = b"ED25519\0";
static OSSL_ED448: &[u8; 6] = b"ED448\0";

fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    match make_bits_from_ec_params(key) {
        Ok(BITS_ED25519) => Ok(OSSL_ED25519),
        Ok(BITS_ED448) => Ok(OSSL_ED448),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

fn make_bits_from_ec_params(key: &Object) -> Result<usize> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let bits = match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => oid_to_bits(o)?,
            ECParameters::CurveName(c) => curve_name_to_bits(c)?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(bits)
}

fn make_output_length_from_obj(key: &Object) -> Result<usize> {
    match make_bits_from_ec_params(key) {
        Ok(255) => Ok(64),
        Ok(448) => Ok(114),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

fn parse_params(mech: &CK_MECHANISM, is_448: bool) -> Result<EddsaParams> {
    if mech.mechanism != CKM_EDDSA {
        return Err(CKR_MECHANISM_INVALID)?;
    }
    match mech.ulParameterLen {
        0 => {
            if is_448 {
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

/// Convert the PKCS #11 public key object to OpenSSL EVP_PKEY
fn object_to_ecc_public_key(key: &Object) -> Result<EvpPkey> {
    let ec_point = match key.get_attr_as_bytes(CKA_EC_POINT) {
        Ok(v) => v,
        Err(_) => return Err(CKR_DEVICE_ERROR)?,
    };
    /* The CKA_EC_POINT should be DER encoded */
    let octet = match asn1::parse_single::<&[u8]>(ec_point) {
        Ok(a) => a.to_vec(),
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let mut params = OsslParam::with_capacity(1);
    params.zeroize = true;
    params.add_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY), &octet)?;
    params.finalize();

    EvpPkey::fromdata(
        get_ossl_name_from_obj(key)?.as_ptr() as *const c_char,
        EVP_PKEY_PUBLIC_KEY,
        &params,
    )
}

/// Convert the PKCS #11 private key object to OpenSSL EVP_PKEY
fn object_to_ecc_private_key(key: &Object) -> Result<EvpPkey> {
    let priv_key = match key.get_attr_as_bytes(CKA_VALUE) {
        Ok(v) => v,
        Err(_) => return Err(CKR_DEVICE_ERROR)?,
    };
    let mut priv_key_octet: Vec<u8> = Vec::with_capacity(priv_key.len() + 2);
    priv_key_octet.push(4); /* tag octet string */
    priv_key_octet.push(u8::try_from(priv_key.len())?); /* length */
    priv_key_octet.extend(priv_key);

    let mut params = OsslParam::with_capacity(1);
    params.zeroize = true;
    params
        .add_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY), priv_key)?;
    params.finalize();

    EvpPkey::fromdata(
        get_ossl_name_from_obj(key)?.as_ptr() as *const c_char,
        EVP_PKEY_PRIVATE_KEY,
        &params,
    )
}

fn no_params() -> EddsaParams {
    EddsaParams {
        ph_flag: None,
        context_data: None,
    }
}

fn is_448_curve(key: &Object) -> Result<bool> {
    match make_bits_from_ec_params(key) {
        Ok(BITS_ED25519) => Ok(false),
        Ok(BITS_ED448) => Ok(true),
        _ => return Err(CKR_GENERAL_ERROR)?,
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

impl EddsaOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_EDDSA,
            Box::new(EddsaMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_EDDSA_SIZE_BITS)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_EDDSA_SIZE_BITS)
                        .unwrap(),
                    flags: CKF_SIGN | CKF_VERIFY,
                },
            }),
        );

        mechs.add_mechanism(
            CKM_EC_EDWARDS_KEY_PAIR_GEN,
            Box::new(EddsaMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_EDDSA_SIZE_BITS)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_EDDSA_SIZE_BITS)
                        .unwrap(),
                    flags: CKF_GENERATE_KEY_PAIR,
                },
            }),
        );
    }

    fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        let is_448 = is_448_curve(key)?;
        Ok(EddsaOperation {
            mech: mech.mechanism,
            output_len: make_output_length_from_obj(key)?,
            public_key: None,
            private_key: Some(object_to_ecc_private_key(key)?),
            params: parse_params(mech, is_448)?,
            is448: is_448,
            data: Vec::new(),
            finalized: false,
            in_use: false,
            sigctx: get_sig_ctx!(key),
        })
    }

    fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        let is_448 = is_448_curve(key)?;
        Ok(EddsaOperation {
            mech: mech.mechanism,
            output_len: make_output_length_from_obj(key)?,
            public_key: Some(object_to_ecc_public_key(key)?),
            private_key: None,
            params: parse_params(mech, is_448)?,
            is448: is_448,
            data: Vec::new(),
            finalized: false,
            in_use: false,
            sigctx: get_sig_ctx!(key),
        })
    }

    fn generate_keypair(
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
        let point_encoded = match asn1::write_single(
            &params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?,
        ) {
            Ok(b) => b,
            Err(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        pubkey.set_attr(attribute::from_bytes(CKA_EC_POINT, point_encoded))?;

        /* Private Key */
        let value = params
            .get_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?
            .to_vec();
        privkey.set_attr(attribute::from_bytes(CKA_VALUE, value))?;
        Ok(())
    }
}

macro_rules! sig_params {
    ($op:expr) => {{
        let mut params = OsslParam::with_capacity(2);
        params.zeroize = true;
        match &$op.params.context_data {
            Some(v) => {
                params.add_octet_string(
                    name_as_char(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
                    &v,
                )?;
            }
            _ => (),
        };

        let instance = match $op.params.ph_flag {
            None => {
                if $op.is448 {
                    return Err(CKR_GENERAL_ERROR)?;
                } else {
                    b"Ed25519\0".to_vec()
                }
            }
            Some(true) => {
                if $op.is448 {
                    b"Ed448ph\0".to_vec()
                } else {
                    b"Ed25519ph\0".to_vec()
                }
            }
            Some(false) => {
                if $op.is448 {
                    b"Ed448\0".to_vec()
                } else {
                    b"Ed25519ctx\0".to_vec()
                }
            }
        };
        params.add_owned_utf8_string(
            name_as_char(OSSL_SIGNATURE_PARAM_INSTANCE),
            instance,
        )?;
        params.finalize();
        params
    }};
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

            let mut params = sig_params!(self);

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

            let mut params = sig_params!(self);

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
