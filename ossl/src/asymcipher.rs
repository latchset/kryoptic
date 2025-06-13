// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the several OpenSSL
//! asymmetric encryption apis

use std::ffi::CStr;

use crate::bindings::*;

use crate::{
    cstr, trace_ossl, Error, ErrorKind, EvpPkey, EvpPkeyCtx, OsslContext,
    OsslParam,
};

/// Known algorithms selectable for OsslAsymcipher
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EncAlg {
    RsaNoPad,
    RsaOaep,
    RsaPkcs1_5,
}

/// Oaep Parameters container
pub struct RsaOaepParams {
    pub digest: &'static CStr,
    pub mgf1: &'static CStr,
    pub label: Option<Vec<u8>>,
}

/// Helper to generate OsslParam arrays for RSA initialization
pub fn rsa_enc_params(
    alg: EncAlg,
    oaep_params: Option<&RsaOaepParams>,
) -> Result<OsslParam, Error> {
    let mut params = OsslParam::new();

    match alg {
        EncAlg::RsaNoPad => params.add_const_c_string(
            cstr!(OSSL_PKEY_PARAM_PAD_MODE),
            cstr!(OSSL_PKEY_RSA_PAD_MODE_NONE),
        )?,
        EncAlg::RsaOaep => {
            if let Some(oaep) = &oaep_params {
                params.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_PAD_MODE),
                    cstr!(OSSL_PKEY_RSA_PAD_MODE_OAEP),
                )?;
                params.add_const_c_string(
                    cstr!(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST),
                    oaep.digest,
                )?;
                params.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_MGF1_DIGEST),
                    oaep.mgf1,
                )?;
                match &oaep.label {
                    None => (),
                    Some(label) => params.add_octet_string(
                        cstr!(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL),
                        &label,
                    )?,
                }
            } else {
                return Err(Error::new(ErrorKind::NullPtr));
            }
        }
        EncAlg::RsaPkcs1_5 => params.add_const_c_string(
            cstr!(OSSL_PKEY_PARAM_PAD_MODE),
            cstr!(OSSL_PKEY_RSA_PAD_MODE_PKCSV15),
        )?,
    }

    params.finalize();
    return Ok(params);
}

/// Higher level wrapper for asymmetric encryption operations with OpenSSL
#[derive(Debug)]
pub struct OsslAsymcipher {
    /// The underlying OpenSSL EVP PKEY context.
    pkey_ctx: EvpPkeyCtx,
}

impl OsslAsymcipher {
    /// Initializes a new asymmetric encryption operation
    pub fn message_encrypt_new(
        libctx: &OsslContext,
        key: &mut EvpPkey,
        params: &OsslParam,
    ) -> Result<OsslAsymcipher, Error> {
        let mut ctx = OsslAsymcipher {
            pkey_ctx: key.new_ctx(libctx)?,
        };
        let ret = unsafe {
            EVP_PKEY_encrypt_init_ex(ctx.pkey_ctx.as_mut_ptr(), params.as_ptr())
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_encrypt_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(ctx)
    }

    /// Executes an encryption operation if 'output' contains a buffer
    /// or probes and returns the expected output length if 'output' is None
    pub fn message_encrypt(
        &mut self,
        plaintext: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, Error> {
        let (mut outlen, outbuf_ptr) = match output {
            Some(o) => (o.len(), o.as_mut_ptr()),
            None => (0, std::ptr::null_mut()),
        };
        let outlen_ptr: *mut usize = &mut outlen;

        let ret = unsafe {
            EVP_PKEY_encrypt(
                self.pkey_ctx.as_mut_ptr(),
                outbuf_ptr,
                outlen_ptr,
                plaintext.as_ptr(),
                plaintext.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_encrypt()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(outlen)
    }

    /// Initializes a new asymmetric decryption operation
    pub fn message_decrypt_new(
        libctx: &OsslContext,
        key: &mut EvpPkey,
        params: &OsslParam,
    ) -> Result<OsslAsymcipher, Error> {
        let mut ctx = OsslAsymcipher {
            pkey_ctx: key.new_ctx(libctx)?,
        };
        let ret = unsafe {
            EVP_PKEY_decrypt_init_ex(ctx.pkey_ctx.as_mut_ptr(), params.as_ptr())
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_decrypt_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(ctx)
    }

    /// Executes an decryption operation if 'output' contains a buffer
    /// or probes and returns the expected output length if 'output' is None
    pub fn message_decrypt(
        &mut self,
        ciphertext: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, Error> {
        let (mut outlen, outbuf_ptr) = match output {
            Some(o) => (o.len(), o.as_mut_ptr()),
            None => (0, std::ptr::null_mut()),
        };
        let outlen_ptr: *mut usize = &mut outlen;

        let ret = unsafe {
            EVP_PKEY_decrypt(
                self.pkey_ctx.as_mut_ptr(),
                outbuf_ptr,
                outlen_ptr,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_decrypt()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(outlen)
    }
}
