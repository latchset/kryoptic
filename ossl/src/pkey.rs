// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction for OpenSSL asymmetric Key
//! management. It handles import/export and key generation

use std::ffi::{c_char, c_int, c_uint, CStr};

use crate::bindings::*;
use crate::{cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam};

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

#[derive(Debug)]
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

fn pkey_type_to_params(
    pt: EvpPkeyType,
) -> Result<(&'static CStr, OsslParam<'static>), Error> {
    let mut params = OsslParam::new();
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
                c_uint::try_from(size)?,
            )?;
            c"RSA"
        }
    };
    params.finalize();
    Ok((name, params))
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
    ///
    /// The parameters (`OsslParam`) specify details like key size or curve
    /// name.
    pub fn generate(
        ctx: &OsslContext,
        pkey_type: EvpPkeyType,
    ) -> Result<EvpPkey, Error> {
        let (name, params) = pkey_type_to_params(pkey_type)?;
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
        let ret = unsafe {
            EVP_PKEY_get_int_param(
                self.ptr,
                OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
                &mut bits,
            )
        };
        if ret == 0 {
            /* TODO: may want to return a special error
             * for unsupported keys */
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(bits)?)
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
