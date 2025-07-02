// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the OpenSSL EVP_MAC apis

use std::ffi::CStr;

use crate::bindings::*;
use crate::digest::DigestAlg;
use crate::{
    cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParamBuilder,
    OsslSecret,
};

/// Wrapper around OpenSSL's `EVP_MAC_CTX`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpMacCtx {
    ptr: *mut EVP_MAC_CTX,
}

/// Methods for creating (from a named MAC) and accessing `EvpMacCtx`.
impl EvpMacCtx {
    fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpMacCtx, Error> {
        let arg = unsafe {
            EVP_MAC_fetch(ctx.ptr(), name.as_ptr(), std::ptr::null_mut())
        };
        if arg.is_null() {
            trace_ossl!("EVP_MAC_fetch()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ptr = unsafe { EVP_MAC_CTX_new(arg) };
        unsafe {
            EVP_MAC_free(arg);
        }
        if ptr.is_null() {
            trace_ossl!("EVP_MAC_CTX_new()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpMacCtx { ptr })
    }

    /// Returns a mutable pointer to the underlying `EVP_MAC_CTX`.
    fn as_mut_ptr(&mut self) -> *mut EVP_MAC_CTX {
        self.ptr
    }
}

impl Drop for EvpMacCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_MAC_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpMacCtx {}
unsafe impl Sync for EvpMacCtx {}

/// Supported Mac Algorithms
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MacAlg {
    HmacSha1,
    HmacSha2_224,
    HmacSha2_256,
    HmacSha2_384,
    HmacSha2_512,
    HmacSha2_512_224,
    HmacSha2_512_256,
    HmacSha3_224,
    HmacSha3_256,
    HmacSha3_384,
    HmacSha3_512,
    CmacAes128,
    CmacAes192,
    CmacAes256,
}

pub(crate) fn mac_to_digest_and_type(
    mac: MacAlg,
) -> Result<(DigestAlg, &'static CStr), Error> {
    Ok(match mac {
        MacAlg::HmacSha1 => (DigestAlg::Sha1, cstr!(OSSL_MAC_NAME_HMAC)),
        MacAlg::HmacSha2_224 => {
            (DigestAlg::Sha2_224, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha2_256 => {
            (DigestAlg::Sha2_256, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha2_384 => {
            (DigestAlg::Sha2_384, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha2_512 => {
            (DigestAlg::Sha2_512, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha2_512_224 => {
            (DigestAlg::Sha2_512_224, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha2_512_256 => {
            (DigestAlg::Sha2_512_256, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha3_224 => {
            (DigestAlg::Sha3_224, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha3_256 => {
            (DigestAlg::Sha3_256, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha3_384 => {
            (DigestAlg::Sha3_384, cstr!(OSSL_MAC_NAME_HMAC))
        }
        MacAlg::HmacSha3_512 => {
            (DigestAlg::Sha3_512, cstr!(OSSL_MAC_NAME_HMAC))
        }
        _ => return Err(Error::new(ErrorKind::WrapperError)),
    })
}

pub(crate) fn add_mac_alg_to_params(
    params: &mut OsslParamBuilder,
    mac: MacAlg,
    digest_key_str: &CStr,
    cipher_key_str: &CStr,
) -> Result<&'static CStr, Error> {
    Ok(match mac {
        MacAlg::HmacSha1 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA1),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha2_224 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA2_224),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha2_256 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA2_256),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha2_384 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA2_384),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha2_512 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA2_512),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha2_512_224 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA2_512_224),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha2_512_256 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA2_512_256),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha3_224 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA3_224),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha3_256 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA3_256),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha3_384 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA3_384),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::HmacSha3_512 => {
            params.add_const_c_string(
                digest_key_str,
                cstr!(OSSL_DIGEST_NAME_SHA3_512),
            )?;
            cstr!(OSSL_MAC_NAME_HMAC)
        }
        MacAlg::CmacAes128 => {
            params.add_const_c_string(cipher_key_str, c"AES128")?;
            cstr!(OSSL_MAC_NAME_CMAC)
        }
        MacAlg::CmacAes192 => {
            params.add_const_c_string(cipher_key_str, c"AES192")?;
            cstr!(OSSL_MAC_NAME_CMAC)
        }
        MacAlg::CmacAes256 => {
            params.add_const_c_string(cipher_key_str, c"AES256")?;
            cstr!(OSSL_MAC_NAME_CMAC)
        }
    })
}

/// Higher level wrapper for Mac operations
#[derive(Debug)]
pub struct OsslMac {
    /// The OpenSSL message mac context (`EVP_MAC_CTX`).
    ctx: EvpMacCtx,
    /// The input key material
    key: OsslSecret,
    /// The MAC output size as reported by `EVP_MAC_CTX_get_mac_size`
    size: usize,
}

impl OsslMac {
    pub fn new(
        ctx: &OsslContext,
        mac: MacAlg,
        key: OsslSecret,
    ) -> Result<OsslMac, Error> {
        let mut params = OsslParamBuilder::with_capacity(1);
        let mac_type = add_mac_alg_to_params(
            &mut params,
            mac,
            cstr!(OSSL_MAC_PARAM_DIGEST),
            cstr!(OSSL_MAC_PARAM_CIPHER),
        )?;
        let params = params.finalize();

        let mut mctx = OsslMac {
            ctx: EvpMacCtx::new(ctx, mac_type)?,
            key,
            size: 0,
        };

        let ret = unsafe {
            EVP_MAC_init(
                mctx.ctx.as_mut_ptr(),
                mctx.key.as_ptr(),
                mctx.key.len(),
                params.as_ptr(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_MAC_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        mctx.size = unsafe { EVP_MAC_CTX_get_mac_size(mctx.ctx.as_mut_ptr()) };

        Ok(mctx)
    }

    pub fn reinit(&mut self) -> Result<(), Error> {
        let ret = unsafe {
            EVP_MAC_init(
                self.ctx.as_mut_ptr(),
                self.key.as_ptr(),
                self.key.len(),
                std::ptr::null_mut(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_MAC_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let ret = unsafe {
            EVP_MAC_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len())
        };
        if ret != 1 {
            trace_ossl!("EVP_MAC_update()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.size {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let mut outlen = 0usize;
        let ret = unsafe {
            EVP_MAC_final(
                self.ctx.as_mut_ptr(),
                output.as_mut_ptr(),
                &mut outlen,
                output.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_MAC_final()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(outlen)
    }

    pub fn size(&self) -> usize {
        self.size
    }
}
