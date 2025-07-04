// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides access to the openSSL random number generator

use crate::bindings::*;
use crate::digest::{digest_to_string, DigestAlg};
use crate::{
    cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParamBuilder,
};

/// Wrapper around OpenSSL's `EVP_RAND_CTX`.
/// Represents a random generator instance, using
/// HMAC and the requested digest algorithm.
/// Valid values are generally Sha2_256 and Sha2_512
/// The personalization string can contain any data,
/// and is generally just a string.
///
/// The addtl data buffers for reseeding and generation
/// can always be just empty buffers, this won't affect
/// the quality of the randomness generated.
#[derive(Debug)]
pub struct EvpRandCtx {
    ptr: *mut EVP_RAND_CTX,
}

impl EvpRandCtx {
    pub fn new_hmac_drbg(
        ctx: &OsslContext,
        digest: DigestAlg,
        pers: &[u8],
    ) -> Result<EvpRandCtx, Error> {
        let rand = unsafe {
            EVP_RAND_fetch(ctx.ptr(), c"HMAC-DRBG".as_ptr(), std::ptr::null())
        };
        if rand.is_null() {
            trace_ossl!("EVP_RAND_fetch()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        let randctx = EvpRandCtx {
            ptr: unsafe { EVP_RAND_CTX_new(rand, std::ptr::null_mut()) },
        };
        unsafe { EVP_RAND_free(rand) };
        if randctx.ptr.is_null() {
            trace_ossl!("EVP_RAND_CTX_new()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        let mut params = OsslParamBuilder::with_capacity(2);
        params.add_const_c_string(cstr!(OSSL_DRBG_PARAM_MAC), c"HMAC")?;
        params.add_const_c_string(
            cstr!(OSSL_DRBG_PARAM_DIGEST),
            digest_to_string(digest),
        )?;
        let params = params.finalize();

        let ret = unsafe {
            EVP_RAND_instantiate(
                randctx.ptr,
                0,
                1,
                pers.as_ptr(),
                pers.len(),
                params.as_ptr(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_RAND_instantiate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(randctx)
    }

    pub fn reseed(
        &mut self,
        entropy: &[u8],
        addtl: &[u8],
    ) -> Result<(), Error> {
        let ret = unsafe {
            EVP_RAND_reseed(
                self.ptr,
                1,
                entropy.as_ptr(),
                entropy.len(),
                addtl.as_ptr(),
                addtl.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_RAND_reseed()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    pub fn generate(
        &mut self,
        addtl: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        let ret = unsafe {
            EVP_RAND_generate(
                self.ptr,
                output.as_mut_ptr(),
                output.len(),
                0,
                0,
                addtl.as_ptr() as *mut u8,
                addtl.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_RAND_generate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }
}

impl Drop for EvpRandCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_RAND_CTX_free(self.ptr);
        }
    }
}
