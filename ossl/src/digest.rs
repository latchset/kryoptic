// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the OpenSSL digest apis

use std::ffi::{c_uint, c_void, CStr};

use crate::bindings::*;

use crate::{
    trace_ossl, Error, ErrorKind, EvpMd, EvpMdCtx, OsslContext, OsslParam,
};

/// Higher level wrapper for Digest operations
#[derive(Debug)]
pub struct OsslDigest {
    /// The OpenSSL message digest context (`EVP_MD_CTX`).
    ctx: EvpMdCtx,
    /// The OpenSSL message digest algorithm (`EVP_MD`).
    md: EvpMd,
    /// Digest size as reported by OpenSSL's `EVP_MD_get_size`.
    size: usize,
}

impl OsslDigest {
    /// Fully initializes a new digest context that is ready to ingest data
    pub fn new(
        ctx: &OsslContext,
        digest: &CStr,
        params: Option<&OsslParam>,
    ) -> Result<OsslDigest, Error> {
        let md = EvpMd::new(ctx, digest)?;
        let size = usize::try_from(unsafe { EVP_MD_get_size(md.as_ptr()) })?;
        let mut dctx = OsslDigest {
            ctx: EvpMdCtx::new()?,
            md: md,
            size: size,
        };
        dctx.reset(params)?;
        Ok(dctx)
    }

    /// Re-initializes an existing context discarding any existing state
    pub fn reset(&mut self, params: Option<&OsslParam>) -> Result<(), Error> {
        let ret = unsafe {
            EVP_DigestInit_ex2(
                self.ctx.as_mut_ptr(),
                self.md.as_ptr(),
                match params {
                    Some(p) => p.as_ptr(),
                    None => std::ptr::null(),
                },
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_DigestInit_ex2()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Ingests data into the hashing mechanism
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let ret = unsafe {
            EVP_DigestUpdate(
                self.ctx.as_mut_ptr(),
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_DigestUpdate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Finalizes the state and produces the output digest
    /// No more operations are possible on this object unless `OsslDigest::reset` is
    /// called first.
    pub fn finalize(&mut self, digest: &mut [u8]) -> Result<usize, Error> {
        if digest.len() < self.size {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let mut retlen = c_uint::try_from(self.size)?;
        let ret = unsafe {
            EVP_DigestFinal_ex(
                self.ctx.as_mut_ptr(),
                digest.as_mut_ptr(),
                &mut retlen,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_DigestFinal_ex()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(retlen)?)
    }

    /// Provides the size of the expected output digest
    pub fn size(&self) -> usize {
        self.size
    }
}

unsafe impl Send for OsslDigest {}
unsafe impl Sync for OsslDigest {}
