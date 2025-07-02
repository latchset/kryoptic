// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction for OpenSSL asymmetric Key
//! management. It handles import/export and key generation

use std::ffi::{c_int, c_uint, CStr};

use crate::bindings::*;
use crate::{
    cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam, OsslSecret,
};

/// Wrapper around OpenSSL's `EVP_PKEY_CTX`, managing its lifecycle.
/// Used for various public key algorithm operations (key generation, signing,
/// encryption context setup, etc.).
#[derive(Debug)]
pub struct EvpPkeyCtx {
    ptr: *mut EVP_PKEY_CTX,
}

/// Methods for creating and accessing `EvpPkeyCtx`.
impl EvpPkeyCtx {
    /// Fetches an algorithm by name and returns a wrapper `EvpPkeyCtx`
    pub fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpPkeyCtx, Error> {
        let ptr = unsafe {
            EVP_PKEY_CTX_new_from_name(
                ctx.ptr(),
                name.as_ptr(),
                std::ptr::null(),
            )
        };
        if ptr.is_null() {
            trace_ossl!("EVP_PKEY_CTX_new_from_name()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    /// Creates an `EvpPkeyCtx` from an existing raw pointer (takes ownership).
    pub unsafe fn from_ptr(
        ptr: *mut EVP_PKEY_CTX,
    ) -> Result<EvpPkeyCtx, Error> {
        if ptr.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    /// Returns a const pointer to the underlying `EVP_PKEY_CTX`.
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const EVP_PKEY_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_PKEY_CTX`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_PKEY_CTX {
        self.ptr
    }
}

impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpPkeyCtx {}
unsafe impl Sync for EvpPkeyCtx {}

#[derive(Clone, Debug)]
pub enum EvpPkeyType {
    /* DH */
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
    Modp2048,
    Modp3072,
    Modp4096,
    Modp6144,
    Modp8192,
    /* Ecc */
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    X25519,
    X448,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    /* ML */
    Mldsa44,
    Mldsa65,
    Mldsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
    /* RSA */
    Rsa(usize, Vec<u8>),
}

/// Adds group name to params if needed, and returns the ossl key type name
fn pkey_type_to_params(
    pt: &EvpPkeyType,
    params: &mut OsslParam,
) -> Result<&'static CStr, Error> {
    let name = match pt {
        EvpPkeyType::Ffdhe2048 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe2048",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe3072 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe3072",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe4096 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe4096",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe6144 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe6144",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe8192 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe8192",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp2048 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_2048",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp3072 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_3072",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp4096 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_4096",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp6144 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_6144",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp8192 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_8192",
            )?;
            c"DH"
        }
        EvpPkeyType::P256 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"prime256v1",
            )?;
            c"EC"
        }
        EvpPkeyType::P384 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"secp384r1",
            )?;
            c"EC"
        }
        EvpPkeyType::P521 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"secp521r1",
            )?;
            c"EC"
        }
        EvpPkeyType::BrainpoolP256r1 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"brainpoolP256r1",
            )?;
            c"EC"
        }
        EvpPkeyType::BrainpoolP384r1 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"brainpoolP384r1",
            )?;
            c"EC"
        }
        EvpPkeyType::BrainpoolP512r1 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"brainpoolP512r1",
            )?;
            c"EC"
        }
        EvpPkeyType::Ed25519 => c"ED25519",
        EvpPkeyType::Ed448 => c"ED448",
        EvpPkeyType::X25519 => c"X25519",
        EvpPkeyType::X448 => c"X448",
        EvpPkeyType::Mldsa44 => c"ML-DSA-44",
        EvpPkeyType::Mldsa65 => c"ML-DSA-65",
        EvpPkeyType::Mldsa87 => c"ML-DSA-87",
        EvpPkeyType::MlKem512 => c"ML-KEM-512",
        EvpPkeyType::MlKem768 => c"ML-KEM-768",
        EvpPkeyType::MlKem1024 => c"ML-KEM-1024",
        EvpPkeyType::Rsa(size, exp) => {
            params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_E), &exp)?;
            params.add_owned_uint(
                cstr!(OSSL_PKEY_PARAM_RSA_BITS),
                c_uint::try_from(*size)?,
            )?;
            c"RSA"
        }
    };
    Ok(name)
}

/* Allocate enough space for a large name */
const MAX_GROUP_NAME_LEN: usize = 128;

/// Helper function to get pkey_type
fn pkey_to_type(
    pkey: &EvpPkey,
    params: &OsslParam,
) -> Result<EvpPkeyType, Error> {
    #[cfg(not(feature = "fips"))]
    let name = unsafe { EVP_PKEY_get0_type_name(pkey.as_ptr()) };
    #[cfg(feature = "fips")]
    let name = crate::fips::pkey_type_name(pkey.as_ptr());
    if name.is_null() {
        return Err(Error::new(ErrorKind::OsslError));
    }
    let type_name = unsafe { CStr::from_ptr(name) };
    match type_name.to_bytes() {
        b"EC" => {
            let group_name =
                params.get_utf8_string(cstr!(OSSL_PKEY_PARAM_GROUP_NAME))?;
            match group_name.to_bytes() {
                b"prime256v1" => Ok(EvpPkeyType::P256),
                b"secp384r1" => Ok(EvpPkeyType::P384),
                b"secp521r1" => Ok(EvpPkeyType::P521),
                b"brainpoolP256r1" => Ok(EvpPkeyType::BrainpoolP256r1),
                b"brainpoolP384r1" => Ok(EvpPkeyType::BrainpoolP384r1),
                b"brainpoolP512r1" => Ok(EvpPkeyType::BrainpoolP512r1),
                _ => Err(Error::new(ErrorKind::WrapperError)),
            }
        }
        b"ED25519" => Ok(EvpPkeyType::Ed25519),
        b"ED448" => Ok(EvpPkeyType::Ed448),
        b"X25519" => Ok(EvpPkeyType::X25519),
        b"X448" => Ok(EvpPkeyType::X448),
        b"DH" => {
            let group_name =
                params.get_utf8_string(cstr!(OSSL_PKEY_PARAM_GROUP_NAME))?;
            match group_name.to_bytes() {
                b"ffdhe2048" => Ok(EvpPkeyType::Ffdhe2048),
                b"ffdhe3072" => Ok(EvpPkeyType::Ffdhe3072),
                b"ffdhe4096" => Ok(EvpPkeyType::Ffdhe4096),
                b"ffdhe6144" => Ok(EvpPkeyType::Ffdhe6144),
                b"ffdhe8192" => Ok(EvpPkeyType::Ffdhe8192),
                b"modp_2048" => Ok(EvpPkeyType::Modp2048),
                b"modp_3072" => Ok(EvpPkeyType::Modp3072),
                b"modp_4096" => Ok(EvpPkeyType::Modp4096),
                b"modp_6144" => Ok(EvpPkeyType::Modp6144),
                b"modp_8192" => Ok(EvpPkeyType::Modp8192),
                _ => Err(Error::new(ErrorKind::WrapperError)),
            }
        }
        b"ML-DSA-44" => Ok(EvpPkeyType::Mldsa44),
        b"ML-DSA-65" => Ok(EvpPkeyType::Mldsa65),
        b"ML-DSA-87" => Ok(EvpPkeyType::Mldsa87),
        b"ML-KEM-512" => Ok(EvpPkeyType::MlKem512),
        b"ML-KEM-768" => Ok(EvpPkeyType::MlKem768),
        b"ML-KEM-1024" => Ok(EvpPkeyType::MlKem1024),
        b"RSA" => {
            let e = params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_E))?;
            let n = params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_N))?;
            let size = n.len() * 8;
            Ok(EvpPkeyType::Rsa(size, e))
        }
        _ => Err(Error::new(ErrorKind::WrapperError)),
    }
}

/// Structure that holds Ecc key data
#[derive(Debug)]
pub struct EccData {
    pub pubkey: Option<Vec<u8>>,
    pub prikey: Option<OsslSecret>,
}

impl Drop for EccData {
    fn drop(&mut self) {
        if let Some(mut v) = self.pubkey.take() {
            unsafe {
                OPENSSL_cleanse(v.as_mut_ptr() as *mut _, v.len());
            }
        }
    }
}

/// Structure that holds Ffdh key data
#[derive(Debug)]
pub struct FfdhData {
    pub pubkey: Option<Vec<u8>>,
    pub prikey: Option<OsslSecret>,
}

impl Drop for FfdhData {
    fn drop(&mut self) {
        if let Some(mut v) = self.pubkey.take() {
            unsafe {
                OPENSSL_cleanse(v.as_mut_ptr() as *mut _, v.len());
            }
        }
    }
}

/// Structure that holds ML Keys data (MlDsa and MlKem)
#[derive(Debug)]
pub struct MlkeyData {
    pub pubkey: Option<Vec<u8>>,
    pub prikey: Option<OsslSecret>,
    pub seed: Option<OsslSecret>,
}

impl Drop for MlkeyData {
    fn drop(&mut self) {
        if let Some(mut v) = self.pubkey.take() {
            unsafe {
                OPENSSL_cleanse(v.as_mut_ptr() as *mut _, v.len());
            }
        }
    }
}

/// Structure that holds RSA key data
#[derive(Debug)]
pub struct RsaData {
    pub n: Vec<u8>,
    pub d: Option<OsslSecret>,
    pub p: Option<OsslSecret>,
    pub q: Option<OsslSecret>,
    pub a: Option<OsslSecret>,
    pub b: Option<OsslSecret>,
    pub c: Option<OsslSecret>,
}

impl Drop for RsaData {
    fn drop(&mut self) {
        unsafe {
            OPENSSL_cleanse(self.n.as_mut_ptr() as *mut _, self.n.len());
        }
    }
}

/// Wrapper to handle import/export data based on the type
#[derive(Debug)]
pub enum PkeyData {
    Ecc(EccData),
    Ffdh(FfdhData),
    Mlkey(MlkeyData),
    Rsa(RsaData),
}

#[cfg(ossl_mldsa)]
fn params_to_mldsa_data(
    pkey: &EvpPkey,
    params: &OsslParam,
) -> Result<PkeyData, Error> {
    Ok(PkeyData::Mlkey(MlkeyData {
        pubkey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
            Ok(p) => Some(p.to_vec()),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => {
                    // OpenSSL does not always provide public key when
                    // asked for key pair here so if it not available,
                    // retry exporting just public key part
                    // https://github.com/openssl/openssl/issues/27542
                    let p2 = pkey.todata(EVP_PKEY_PUBLIC_KEY)?;
                    match p2.get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
                        Ok(p) => Some(p.to_vec()),
                        Err(e) => match e.kind() {
                            ErrorKind::NullPtr => None,
                            _ => return Err(e),
                        },
                    }
                }
                _ => return Err(e),
            },
        },
        prikey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        seed: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_ML_DSA_SEED))
        {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
    }))
}

#[cfg(ossl_mldsa)]
fn params_to_mlkem_data(params: &OsslParam) -> Result<PkeyData, Error> {
    Ok(PkeyData::Mlkey(MlkeyData {
        pubkey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
            Ok(p) => Some(p.to_vec()),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        prikey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        seed: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_ML_KEM_SEED))
        {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
    }))
}

fn params_to_rsa_data(params: &OsslParam) -> Result<PkeyData, Error> {
    Ok(PkeyData::Rsa(RsaData {
        n: params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_N))?,
        d: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_D)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        p: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR1)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        q: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR2)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        a: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT1)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        b: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT2)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        c: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_COEFFICIENT1)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
    }))
}

fn rsa_data_to_params(
    rsa: &RsaData,
    params: &mut OsslParam,
) -> Result<bool, Error> {
    let mut is_priv = false;
    params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_N), rsa.n.as_slice())?;
    if let Some(p) = &rsa.d {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_D), p)?;
    }
    if let Some(p) = &rsa.p {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR1), p)?;
    }
    if let Some(p) = &rsa.q {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR2), p)?;
    }
    if let Some(p) = &rsa.a {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT1), p)?;
    }
    if let Some(p) = &rsa.b {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT2), p)?;
    }
    if let Some(p) = &rsa.c {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_COEFFICIENT1), p)?;
    }
    Ok(is_priv)
}

/// Wrapper around OpenSSL's `EVP_PKEY`, representing a generic public or
/// private key. Manages the key's lifecycle.
#[derive(Debug)]
pub struct EvpPkey {
    ptr: *mut EVP_PKEY,
}

impl EvpPkey {
    /// Creates an `EvpPkey` from key material provided via `OSSL_PARAM`s.
    ///
    /// Used for importing public or private keys based on their components
    /// (e.g., modulus/exponent for RSA, curve/point for EC).
    pub fn fromdata(
        ctx: &OsslContext,
        pkey_name: &CStr,
        pkey_type: u32,
        params: &OsslParam,
    ) -> Result<EvpPkey, Error> {
        let mut pctx = EvpPkeyCtx::new(ctx, pkey_name)?;
        let res = unsafe { EVP_PKEY_fromdata_init(pctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_fromdata(
                pctx.as_mut_ptr(),
                &mut pkey,
                pkey_type as i32,
                params.as_ptr() as *mut OSSL_PARAM,
            )
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Exports key material components into an `OsslParam` structure.
    ///
    /// The `selection` argument specifies which components to export
    /// (e.g., public, private, parameters).
    pub fn todata(&self, selection: u32) -> Result<OsslParam, Error> {
        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();
        let ret = unsafe {
            EVP_PKEY_todata(self.ptr, c_int::try_from(selection)?, &mut params)
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_todata()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        OsslParam::from_ptr(params)
    }

    /// Allow to get parameters from a key.
    /// The caller must preallocate the payloads with enough space to
    /// receive the data, which is copied into the parameters.
    pub fn get_params(&self, params: &mut OsslParam) -> Result<(), Error> {
        if unsafe { EVP_PKEY_get_params(self.ptr, params.as_mut_ptr()) } != 1 {
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Generates a new key pair based on provided algorithm name and
    /// parameters.
    pub fn generate(
        ctx: &OsslContext,
        pkey_type: EvpPkeyType,
    ) -> Result<EvpPkey, Error> {
        let mut params = OsslParam::new();
        let name = pkey_type_to_params(&pkey_type, &mut params)?;
        params.finalize();
        let mut pctx = EvpPkeyCtx::new(ctx, name)?;
        let res = unsafe { EVP_PKEY_keygen_init(pctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_keygen_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let res = unsafe {
            EVP_PKEY_CTX_set_params(pctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_CTX_set_params()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe { EVP_PKEY_generate(pctx.as_mut_ptr(), &mut pkey) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_generate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Creates a new `EvpPkeyCtx` associated with this `EvpPkey`.
    ///
    /// Used to prepare for operations using this specific key.
    pub fn new_ctx(&mut self, ctx: &OsslContext) -> Result<EvpPkeyCtx, Error> {
        /* this function takes care of checking for NULL */
        unsafe {
            EvpPkeyCtx::from_ptr(
                /* this function will use refcounting to keep EVP_PKEY
                 * alive for the lifetime of the context, so it is ok
                 * to not use rust lifetimes here */
                EVP_PKEY_CTX_new_from_pkey(
                    ctx.ptr(),
                    self.as_mut_ptr(),
                    std::ptr::null_mut(),
                ),
            )
        }
    }

    /// Helper to import a public/private pkey */
    pub fn import(
        ctx: &OsslContext,
        pkey_type: EvpPkeyType,
        data: PkeyData,
    ) -> Result<EvpPkey, Error> {
        let mut pkey_class: u32 = 0;
        let mut params = OsslParam::with_capacity(2);
        params.zeroize = true;

        let name = pkey_type_to_params(&pkey_type, &mut params)?;

        match pkey_type {
            EvpPkeyType::P256
            | EvpPkeyType::P384
            | EvpPkeyType::P521
            | EvpPkeyType::BrainpoolP256r1
            | EvpPkeyType::BrainpoolP384r1
            | EvpPkeyType::BrainpoolP512r1 => match &data {
                PkeyData::Ecc(ecc) => {
                    if let Some(p) = &ecc.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &ecc.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params.add_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY), p)?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Ed25519
            | EvpPkeyType::Ed448
            | EvpPkeyType::X25519
            | EvpPkeyType::X448 => match &data {
                PkeyData::Ecc(ecc) => {
                    if let Some(p) = &ecc.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &ecc.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                            p,
                        )?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Ffdhe2048
            | EvpPkeyType::Ffdhe3072
            | EvpPkeyType::Ffdhe4096
            | EvpPkeyType::Ffdhe6144
            | EvpPkeyType::Ffdhe8192
            | EvpPkeyType::Modp2048
            | EvpPkeyType::Modp3072
            | EvpPkeyType::Modp4096
            | EvpPkeyType::Modp6144
            | EvpPkeyType::Modp8192 => match &data {
                PkeyData::Ffdh(ffdh) => {
                    if let Some(p) = &ffdh.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params.add_bn(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &ffdh.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params.add_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY), p)?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Mldsa44
            | EvpPkeyType::Mldsa65
            | EvpPkeyType::Mldsa87 => match &data {
                #[cfg(ossl_mldsa)]
                PkeyData::Mlkey(mlk) => {
                    if let Some(p) = &mlk.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &mlk.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                            p,
                        )?
                    }
                    if let Some(p) = &mlk.seed {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_ML_DSA_SEED),
                            p,
                        )?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::MlKem512
            | EvpPkeyType::MlKem768
            | EvpPkeyType::MlKem1024 => match &data {
                #[cfg(ossl_mlkem)]
                PkeyData::Mlkey(mlk) => {
                    if let Some(p) = &mlk.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &mlk.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                            p,
                        )?
                    }
                    if let Some(p) = &mlk.seed {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_ML_KEM_SEED),
                            p,
                        )?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Rsa(_, _) => match &data {
                PkeyData::Rsa(rsa) => {
                    if rsa_data_to_params(&rsa, &mut params)? {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                    } else {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
        }
        params.finalize();

        EvpPkey::fromdata(ctx, name, pkey_class, &params)
    }

    /// Export public point in encoded form and/or private key
    pub fn export(&self) -> Result<PkeyData, Error> {
        let params = self.todata(EVP_PKEY_KEYPAIR)?;
        let pkey_type = pkey_to_type(&self, &params)?;
        Ok(match pkey_type {
            EvpPkeyType::P256
            | EvpPkeyType::P384
            | EvpPkeyType::P521
            | EvpPkeyType::BrainpoolP256r1
            | EvpPkeyType::BrainpoolP384r1
            | EvpPkeyType::BrainpoolP512r1 => PkeyData::Ecc(EccData {
                pubkey: match params
                    .get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY))
                {
                    Ok(p) => Some(p.to_vec()),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
                prikey: match params.get_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
                    Ok(p) => Some(OsslSecret::from_vec(p)),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
            }),
            EvpPkeyType::Ed25519
            | EvpPkeyType::Ed448
            | EvpPkeyType::X25519
            | EvpPkeyType::X448 => PkeyData::Ecc(EccData {
                pubkey: match params
                    .get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY))
                {
                    Ok(p) => Some(p.to_vec()),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
                prikey: match params
                    .get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY))
                {
                    Ok(p) => Some(OsslSecret::from_slice(p)),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
            }),
            EvpPkeyType::Ffdhe2048
            | EvpPkeyType::Ffdhe3072
            | EvpPkeyType::Ffdhe4096
            | EvpPkeyType::Ffdhe6144
            | EvpPkeyType::Ffdhe8192
            | EvpPkeyType::Modp2048
            | EvpPkeyType::Modp3072
            | EvpPkeyType::Modp4096
            | EvpPkeyType::Modp6144
            | EvpPkeyType::Modp8192 => PkeyData::Ffdh(FfdhData {
                pubkey: match params.get_bn(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
                    Ok(p) => Some(p),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
                prikey: match params.get_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
                    Ok(p) => Some(OsslSecret::from_vec(p)),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
            }),
            EvpPkeyType::Mldsa44
            | EvpPkeyType::Mldsa65
            | EvpPkeyType::Mldsa87 => {
                #[cfg(ossl_mldsa)]
                return params_to_mldsa_data(&self, &params);
                #[cfg(not(ossl_mldsa))]
                return Err(Error::new(ErrorKind::WrapperError));
            }
            EvpPkeyType::MlKem512
            | EvpPkeyType::MlKem768
            | EvpPkeyType::MlKem1024 => {
                #[cfg(ossl_mlkem)]
                return params_to_mlkem_data(&params);
                #[cfg(not(ossl_mlkem))]
                return Err(Error::new(ErrorKind::WrapperError));
            }
            EvpPkeyType::Rsa(_, _) => return params_to_rsa_data(&params),
        })
    }

    /// Creates a new public EvpPkey with this key as template and the provided
    /// slice as as public key value
    pub fn make_peer(
        &self,
        ctx: &OsslContext,
        public: &[u8],
    ) -> Result<EvpPkey, Error> {
        let mut params = OsslParam::with_capacity(1);
        params.add_empty_utf8_string(
            cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
            MAX_GROUP_NAME_LEN + 1,
        )?;
        params.finalize();
        self.get_params(&mut params)?;
        let pkey_type = pkey_to_type(&self, &params)?;
        let data = match pkey_type {
            EvpPkeyType::P256
            | EvpPkeyType::P384
            | EvpPkeyType::P521
            | EvpPkeyType::BrainpoolP256r1
            | EvpPkeyType::BrainpoolP384r1
            | EvpPkeyType::BrainpoolP512r1
            | EvpPkeyType::Ed25519
            | EvpPkeyType::Ed448
            | EvpPkeyType::X25519
            | EvpPkeyType::X448 => PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            }),
            EvpPkeyType::Ffdhe2048
            | EvpPkeyType::Ffdhe3072
            | EvpPkeyType::Ffdhe4096
            | EvpPkeyType::Ffdhe6144
            | EvpPkeyType::Ffdhe8192
            | EvpPkeyType::Modp2048
            | EvpPkeyType::Modp3072
            | EvpPkeyType::Modp4096
            | EvpPkeyType::Modp6144
            | EvpPkeyType::Modp8192 => PkeyData::Ffdh(FfdhData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            }),
            _ => return Err(Error::new(ErrorKind::WrapperError)),
        };
        Self::import(ctx, pkey_type, data)
    }

    /// Returns a const pointer to the underlying `EVP_PKEY`.
    pub fn as_ptr(&self) -> *const EVP_PKEY {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_PKEY`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_PKEY {
        self.ptr
    }

    /// Gets the key size in bits. Handles FIPS provider differences.
    #[cfg(not(feature = "fips"))]
    pub fn get_bits(&self) -> Result<usize, Error> {
        let ret = unsafe { EVP_PKEY_get_bits(self.ptr) };
        if ret == 0 {
            /* TODO: may want to return a special error
             * for unsupported keys */
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(ret)?)
    }
    #[cfg(feature = "fips")]
    pub fn get_bits(&self) -> Result<usize, Error> {
        /* EVP_PKEY_get_bits() not available in libfips.a */
        let mut bits: c_int = 0;
        let name = cstr!(OSSL_PKEY_PARAM_BITS).as_ptr();
        let ret = unsafe { EVP_PKEY_get_int_param(self.ptr, name, &mut bits) };
        if ret == 0 {
            /* TODO: may want to return a special error
             * for unsupported keys */
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(bits)?)
    }

    /// Gets the actual key size by querying the underlying `EVP_PKEY`
    pub fn get_size(&self) -> Result<usize, Error> {
        Ok(usize::try_from(unsafe {
            EVP_PKEY_get_size(self.as_ptr())
        })?)
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpPkey {}
unsafe impl Sync for EvpPkey {}
