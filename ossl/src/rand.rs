// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides access to the openSSL random number generator

use std::ffi::{c_int, c_uint};

use crate::bindings::*;
use crate::digest::{digest_to_string, string_to_digest, DigestAlg};
use crate::{
    cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParamBuilder,
};

#[derive(Clone, Debug)]
pub enum EvpRandGetParam {
    /// OSSL_DRBG_PARAM_DIGEST
    Digest(DigestAlg),
    /// OSSL_DRBG_PARAM_MAX_ADINLEN
    MaxAdinLen(usize),
    /// OSSL_DRBG_PARAM_MAX_ENTROPYLEN
    MaxEntropyLen(usize),
    /// OSSL_DRBG_PARAM_MAX_NONCELEN
    MaxNonceLen(usize),
    /// OSSL_DRBG_PARAM_MAX_PERSLEN
    MaxPersLen(usize),
    /// OSSL_DRBG_PARAM_MIN_ENTROPYLEN
    MinEntropyLen(usize),
    /// OSSL_DRBG_PARAM_MIN_NONCELEN
    MinNonceLen(usize),
    /// OSSL_DRBG_PARAM_RESEED_COUNTER
    ReseedCounter(c_uint),
    /// OSSL_DRBG_PARAM_RESEED_REQUESTS
    ReseedRequests(c_uint),
    /// OSSL_DRBG_PARAM_RESEED_TIME
    ReseedTime(i64),
    /// OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL
    ReseedTimeInterval(u64),
    /// OSSL_RAND_PARAM_MAX_REQUEST
    MaxRequest(usize),
    /// OSSL_RAND_PARAM_STATE
    State(c_int),
    /// OSSL_RAND_PARAM_STRENGTH
    Strength(c_uint),
}

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

    pub fn get_ctx_params(
        &self,
        params: &mut [EvpRandGetParam],
    ) -> Result<(), Error> {
        const MAX_DIGEST_NAME_LEN: usize = 64;
        if params.is_empty() {
            return Ok(());
        }

        let mut params_builder = OsslParamBuilder::with_capacity(params.len());

        // Build the request
        for p in params.iter() {
            // It is fine for some of these to not be supported by the builder
            // if for example some integer types are not implemented.
            // Also, if the DRBG does not support a parameter, it will be ignored.
            match p {
                EvpRandGetParam::Digest(_) => params_builder
                    .add_empty_utf8_string(
                        cstr!(OSSL_DRBG_PARAM_DIGEST),
                        MAX_DIGEST_NAME_LEN,
                    ),
                EvpRandGetParam::MaxAdinLen(_) => params_builder
                    .add_owned_size_t(cstr!(OSSL_DRBG_PARAM_MAX_ADINLEN), 0),
                EvpRandGetParam::MaxEntropyLen(_) => params_builder
                    .add_owned_size_t(cstr!(OSSL_DRBG_PARAM_MAX_ENTROPYLEN), 0),
                EvpRandGetParam::MaxNonceLen(_) => params_builder
                    .add_owned_size_t(cstr!(OSSL_DRBG_PARAM_MAX_NONCELEN), 0),
                EvpRandGetParam::MaxPersLen(_) => params_builder
                    .add_owned_size_t(cstr!(OSSL_DRBG_PARAM_MAX_PERSLEN), 0),
                EvpRandGetParam::MinEntropyLen(_) => params_builder
                    .add_owned_size_t(cstr!(OSSL_DRBG_PARAM_MIN_ENTROPYLEN), 0),
                EvpRandGetParam::MinNonceLen(_) => params_builder
                    .add_owned_size_t(cstr!(OSSL_DRBG_PARAM_MIN_NONCELEN), 0),
                EvpRandGetParam::ReseedCounter(_) => params_builder
                    .add_owned_uint(cstr!(OSSL_DRBG_PARAM_RESEED_COUNTER), 0),
                EvpRandGetParam::ReseedRequests(_) => params_builder
                    .add_owned_uint(cstr!(OSSL_DRBG_PARAM_RESEED_REQUESTS), 0),
                EvpRandGetParam::ReseedTime(_) => params_builder
                    .add_owned_i64(cstr!(OSSL_DRBG_PARAM_RESEED_TIME), 0),
                EvpRandGetParam::ReseedTimeInterval(_) => params_builder
                    .add_owned_u64(
                        cstr!(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL),
                        0,
                    ),
                EvpRandGetParam::MaxRequest(_) => params_builder
                    .add_owned_size_t(cstr!(OSSL_RAND_PARAM_MAX_REQUEST), 0),
                EvpRandGetParam::State(_) => params_builder
                    .add_owned_int(cstr!(OSSL_RAND_PARAM_STATE), 0),
                EvpRandGetParam::Strength(_) => params_builder
                    .add_owned_uint(cstr!(OSSL_RAND_PARAM_STRENGTH), 0),
            }?;
        }

        let mut ossl_params = params_builder.finalize();
        if unsafe {
            EVP_RAND_CTX_get_params(self.ptr, ossl_params.as_mut_ptr())
        } != 1
        {
            trace_ossl!("EVP_RAND_CTX_get_params()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        // Fill the results
        for p in params.iter_mut() {
            match p {
                EvpRandGetParam::Digest(val) => {
                    let new_val = ossl_params
                        .get_utf8_string(cstr!(OSSL_DRBG_PARAM_DIGEST))?;
                    *val = string_to_digest(new_val)?;
                }
                EvpRandGetParam::MaxAdinLen(val) => {
                    *val = ossl_params
                        .get_size_t(cstr!(OSSL_DRBG_PARAM_MAX_ADINLEN))?;
                }
                EvpRandGetParam::MaxEntropyLen(val) => {
                    *val = ossl_params
                        .get_size_t(cstr!(OSSL_DRBG_PARAM_MAX_ENTROPYLEN))?;
                }
                EvpRandGetParam::MaxNonceLen(val) => {
                    *val = ossl_params
                        .get_size_t(cstr!(OSSL_DRBG_PARAM_MAX_NONCELEN))?;
                }
                EvpRandGetParam::MaxPersLen(val) => {
                    *val = ossl_params
                        .get_size_t(cstr!(OSSL_DRBG_PARAM_MAX_PERSLEN))?;
                }
                EvpRandGetParam::MinEntropyLen(val) => {
                    *val = ossl_params
                        .get_size_t(cstr!(OSSL_DRBG_PARAM_MIN_ENTROPYLEN))?;
                }
                EvpRandGetParam::MinNonceLen(val) => {
                    *val = ossl_params
                        .get_size_t(cstr!(OSSL_DRBG_PARAM_MIN_NONCELEN))?;
                }
                EvpRandGetParam::ReseedCounter(val) => {
                    *val = ossl_params
                        .get_uint(cstr!(OSSL_DRBG_PARAM_RESEED_COUNTER))?;
                }
                EvpRandGetParam::ReseedRequests(val) => {
                    *val = ossl_params
                        .get_uint(cstr!(OSSL_DRBG_PARAM_RESEED_REQUESTS))?;
                }
                EvpRandGetParam::ReseedTime(val) => {
                    *val = ossl_params
                        .get_i64(cstr!(OSSL_DRBG_PARAM_RESEED_TIME))?;
                }
                EvpRandGetParam::ReseedTimeInterval(val) => {
                    *val = ossl_params
                        .get_u64(cstr!(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL))?;
                }
                EvpRandGetParam::MaxRequest(val) => {
                    *val = ossl_params
                        .get_size_t(cstr!(OSSL_RAND_PARAM_MAX_REQUEST))?;
                }
                EvpRandGetParam::State(val) => {
                    *val = ossl_params.get_int(cstr!(OSSL_RAND_PARAM_STATE))?;
                }
                EvpRandGetParam::Strength(val) => {
                    *val = ossl_params
                        .get_uint(cstr!(OSSL_RAND_PARAM_STRENGTH))?;
                }
            }
        }
        Ok(())
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
