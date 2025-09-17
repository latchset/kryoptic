// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the OpenSSL digest apis

use std::ffi::{c_uint, c_void, CStr};

use crate::bindings::*;

use crate::{cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam};

/// Wrapper around OpenSSL's `EVP_MD`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpMd {
    ptr: *mut EVP_MD,
}

/// Methods for creating and accessing `EvpMd`.
impl EvpMd {
    pub fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpMd, Error> {
        let ptr = unsafe {
            EVP_MD_fetch(ctx.ptr(), name.as_ptr(), std::ptr::null_mut())
        };
        if ptr.is_null() {
            trace_ossl!("EVP_MD_fetch()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpMd { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_MD`.
    pub unsafe fn as_ptr(&self) -> *const EVP_MD {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_MD`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_MD {
        self.ptr
    }
}

impl Clone for EvpMd {
    fn clone(&self) -> Self {
        let ret = unsafe { EVP_MD_up_ref(self.ptr) };

        if ret != 1 {
            panic!("EVP_MD_up_ref failed");
        }
        EvpMd { ptr: self.ptr }
    }
}

impl Drop for EvpMd {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpMd {}
unsafe impl Sync for EvpMd {}

/// Wrapper around OpenSSL's `EVP_MD_CTX`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpMdCtx {
    ptr: *mut EVP_MD_CTX,
}

/// Methods for creating and accessing `EvpMdCtx`.
impl EvpMdCtx {
    pub fn new() -> Result<EvpMdCtx, Error> {
        let ptr = unsafe { EVP_MD_CTX_new() };
        if ptr.is_null() {
            trace_ossl!("EVP_MD_ctx_new()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpMdCtx { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_MD_CTX`.
    pub unsafe fn as_ptr(&self) -> *const EVP_MD_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_MD_CTX`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_MD_CTX {
        self.ptr
    }

    /// Tries to clone the context.
    pub fn try_clone(&self) -> Result<EvpMdCtx, Error> {
        let mut new = Self::new()?;
        let ret =
            unsafe { EVP_MD_CTX_copy_ex(new.as_mut_ptr(), self.as_ptr()) };

        if ret != 1 {
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(new)
    }
}

impl Drop for EvpMdCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpMdCtx {}
unsafe impl Sync for EvpMdCtx {}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DigestAlg {
    Sha1,
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha2_512_224,
    Sha2_512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    #[cfg(feature = "rfc9580")]
    Md5,
}

pub(crate) fn digest_to_string(digest: DigestAlg) -> &'static CStr {
    match digest {
        DigestAlg::Sha1 => cstr!(OSSL_DIGEST_NAME_SHA1),
        DigestAlg::Sha2_224 => cstr!(OSSL_DIGEST_NAME_SHA2_224),
        DigestAlg::Sha2_256 => cstr!(OSSL_DIGEST_NAME_SHA2_256),
        DigestAlg::Sha2_384 => cstr!(OSSL_DIGEST_NAME_SHA2_384),
        DigestAlg::Sha2_512 => cstr!(OSSL_DIGEST_NAME_SHA2_512),
        DigestAlg::Sha2_512_224 => cstr!(OSSL_DIGEST_NAME_SHA2_512_224),
        DigestAlg::Sha2_512_256 => cstr!(OSSL_DIGEST_NAME_SHA2_512_256),
        DigestAlg::Sha3_224 => cstr!(OSSL_DIGEST_NAME_SHA3_224),
        DigestAlg::Sha3_256 => cstr!(OSSL_DIGEST_NAME_SHA3_256),
        DigestAlg::Sha3_384 => cstr!(OSSL_DIGEST_NAME_SHA3_384),
        DigestAlg::Sha3_512 => cstr!(OSSL_DIGEST_NAME_SHA3_512),
        #[cfg(feature = "rfc9580")]
        DigestAlg::Md5 => cstr!(OSSL_DIGEST_NAME_MD5),
    }
}

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
        digest: DigestAlg,
        params: Option<&OsslParam>,
    ) -> Result<OsslDigest, Error> {
        let md = EvpMd::new(ctx, digest_to_string(digest))?;
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

    /// Tries to clone the digest.
    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(OsslDigest {
            ctx: self.ctx.try_clone()?,
            md: self.md.clone(),
            size: self.size,
        })
    }
}

unsafe impl Send for OsslDigest {}
unsafe impl Sync for OsslDigest {}
