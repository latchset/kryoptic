// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! Helpers to deal with FIPS Provider code in FIPS builds

use std::ffi::CStr;
use std::ffi::{c_char, c_uchar, c_void};
use std::ptr::{null, null_mut};

use crate::bindings::*;
use crate::pkey::EvpPkey;
use crate::signature::SigAlg;
use crate::{Error, ErrorKind, OsslContext};

pub fn set_error_state() {
    unsafe {
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_PCT.as_ptr() as *const c_char)
    };
}

pub fn check_state_ok() -> bool {
    if unsafe { ossl_prov_is_running() } == 0 {
        return false;
    }
    return true;
}

/// Helper function to convert legacy name to ossl name for fetching
fn sigalg_to_legacy_name(alg: SigAlg) -> &'static CStr {
    match alg {
        SigAlg::Ecdsa
        | SigAlg::EcdsaSha1
        | SigAlg::EcdsaSha2_224
        | SigAlg::EcdsaSha2_256
        | SigAlg::EcdsaSha2_384
        | SigAlg::EcdsaSha2_512
        | SigAlg::EcdsaSha3_224
        | SigAlg::EcdsaSha3_256
        | SigAlg::EcdsaSha3_384
        | SigAlg::EcdsaSha3_512 => c"ECDSA",
        SigAlg::Ed25519
        | SigAlg::Ed25519ctx
        | SigAlg::Ed25519ph
        | SigAlg::Ed448
        | SigAlg::Ed448ph => c"EDDSA",
        SigAlg::Rsa
        | SigAlg::RsaNoPad
        | SigAlg::RsaSha1
        | SigAlg::RsaSha2_224
        | SigAlg::RsaSha2_256
        | SigAlg::RsaSha2_384
        | SigAlg::RsaSha2_512
        | SigAlg::RsaSha3_224
        | SigAlg::RsaSha3_256
        | SigAlg::RsaSha3_384
        | SigAlg::RsaSha3_512
        | SigAlg::RsaPss
        | SigAlg::RsaPssSha1
        | SigAlg::RsaPssSha2_224
        | SigAlg::RsaPssSha2_256
        | SigAlg::RsaPssSha2_384
        | SigAlg::RsaPssSha2_512
        | SigAlg::RsaPssSha3_224
        | SigAlg::RsaPssSha3_256
        | SigAlg::RsaPssSha3_384
        | SigAlg::RsaPssSha3_512 => c"RSA",
        SigAlg::Mldsa44 | SigAlg::Mldsa65 | SigAlg::Mldsa87 => c"",
        SigAlg::SlhdsaSha2_128s
        | SigAlg::SlhdsaShake128s
        | SigAlg::SlhdsaSha2_128f
        | SigAlg::SlhdsaShake128f
        | SigAlg::SlhdsaSha2_192s
        | SigAlg::SlhdsaShake192s
        | SigAlg::SlhdsaSha2_192f
        | SigAlg::SlhdsaShake192f
        | SigAlg::SlhdsaSha2_256s
        | SigAlg::SlhdsaShake256s
        | SigAlg::SlhdsaSha2_256f
        | SigAlg::SlhdsaShake256f => c"",
    }
}

/* The OpenSSL FIPS Provider do not export helper functions to set up
 * digest-sign operations. So we'll just have to brute force it */
#[derive(Debug)]
pub struct ProviderSignatureCtx {
    vtable: *mut EVP_SIGNATURE,
    ctx: *mut c_void,
}

impl ProviderSignatureCtx {
    pub fn new(
        ctx: &OsslContext,
        alg: SigAlg,
    ) -> Result<ProviderSignatureCtx, Error> {
        let sigtable = unsafe {
            EVP_SIGNATURE_fetch(
                ctx.ptr(),
                sigalg_to_legacy_name(alg).as_ptr(),
                null(),
            )
        };
        if sigtable.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }

        let ctx = unsafe {
            match (*sigtable).newctx {
                Some(f) => f(ctx.fips_provider() as *mut c_void, null()),
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }

        Ok(ProviderSignatureCtx {
            vtable: sigtable,
            ctx: ctx,
        })
    }

    pub fn digest_sign_init(
        &mut self,
        mdname: *const c_char,
        pkey: &EvpPkey,
        params: *const OSSL_PARAM,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_sign_init {
                Some(f) => {
                    if f(
                        self.ctx,
                        mdname,
                        (*pkey.as_ptr()).keydata as *mut c_void,
                        params,
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_sign_update(&mut self, data: &[u8]) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_sign_update {
                Some(f) => {
                    if f(self.ctx, data.as_ptr() as *const c_uchar, data.len())
                        != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_sign_final(
        &mut self,
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        unsafe {
            match (*self.vtable).digest_sign_final {
                Some(f) => {
                    let mut siglen = 0usize;
                    let siglen_ptr: *mut usize = &mut siglen;
                    let res = f(
                        self.ctx,
                        signature.as_mut_ptr() as *mut c_uchar,
                        siglen_ptr,
                        signature.len(),
                    );
                    if res != 1 {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                    Ok(siglen)
                }
                None => Err(Error::new(ErrorKind::NullPtr)),
            }
        }
    }

    pub fn digest_sign(
        &mut self,
        mut signature: Option<&mut [u8]>,
        tbs: &[u8],
    ) -> Result<usize, Error> {
        unsafe {
            match (*self.vtable).digest_sign {
                Some(f) => {
                    let mut siglen: usize;
                    let sigptr: *mut c_uchar;
                    match &mut signature {
                        Some(s) => {
                            sigptr = s.as_mut_ptr();
                            siglen = s.len();
                        }
                        None => {
                            sigptr = null_mut() as *mut c_uchar;
                            siglen = 0usize;
                        }
                    }
                    let siglen_ptr: *mut usize = &mut siglen;
                    let res = f(
                        self.ctx,
                        sigptr,
                        siglen_ptr,
                        siglen,
                        tbs.as_ptr() as *mut c_uchar,
                        tbs.len(),
                    );
                    if res != 1 {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                    Ok(siglen)
                }
                None => Err(Error::new(ErrorKind::NullPtr)),
            }
        }
    }

    pub fn digest_verify_init(
        &mut self,
        mdname: *const c_char,
        pkey: &EvpPkey,
        params: *const OSSL_PARAM,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify_init {
                Some(f) => {
                    if f(
                        self.ctx,
                        mdname,
                        (*pkey.as_ptr()).keydata as *mut c_void,
                        params,
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_verify_update(&mut self, data: &[u8]) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify_update {
                Some(f) => {
                    if f(self.ctx, data.as_ptr() as *const c_uchar, data.len())
                        != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_verify_final(
        &mut self,
        signature: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify_final {
                Some(f) => {
                    if f(
                        self.ctx,
                        signature.as_ptr() as *const c_uchar,
                        signature.len(),
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_verify(
        &mut self,
        signature: &[u8],
        tbs: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify {
                Some(f) => {
                    if f(
                        self.ctx,
                        signature.as_ptr() as *const c_uchar,
                        signature.len(),
                        tbs.as_ptr() as *const c_uchar,
                        tbs.len(),
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }
}

unsafe impl Send for ProviderSignatureCtx {}
unsafe impl Sync for ProviderSignatureCtx {}

pub(crate) fn pkey_type_name(pkey: *const EVP_PKEY) -> *const c_char {
    if pkey.is_null() {
        return null();
    }
    let keymgmt = unsafe { (*pkey).keymgmt };
    if keymgmt.is_null() {
        return null();
    }
    return unsafe { (*keymgmt).type_name };
}
