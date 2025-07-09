// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the several OpenSSL
//! asymmetric encryption apis

use crate::bindings::*;
use crate::digest::{digest_to_string, DigestAlg};
use crate::pkey::{EvpPkey, EvpPkeyCtx};
use crate::{cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam};

/// Known algorithms selectable for OsslAsymcipher
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EncAlg {
    RsaNoPad,
    RsaOaep,
    RsaPkcs1_5,
}

/// Oaep Parameters container
pub struct RsaOaepParams {
    pub digest: DigestAlg,
    pub mgf1: DigestAlg,
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
                    digest_to_string(oaep.digest),
                )?;
                params.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_MGF1_DIGEST),
                    digest_to_string(oaep.mgf1),
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

/// Asymmetric Cipher Operation
#[derive(Debug, PartialEq)]
pub enum EncOp {
    Encrypt,
    Decrypt,
}

/// Higher level wrapper for asymmetric encryption operations with OpenSSL
#[derive(Debug)]
pub struct OsslAsymcipher {
    /// The underlying OpenSSL EVP PKEY context.
    pkey_ctx: EvpPkeyCtx,
    /// The requested operation type
    op: EncOp,
}

impl OsslAsymcipher {
    /// Initializes a new asymmetric encryption or decryption operation
    pub fn new(
        libctx: &OsslContext,
        op: EncOp,
        key: &mut EvpPkey,
        params: &OsslParam,
    ) -> Result<OsslAsymcipher, Error> {
        let mut ctx = OsslAsymcipher {
            pkey_ctx: key.new_ctx(libctx)?,
            op: op,
        };
        let ret = match ctx.op {
            EncOp::Encrypt => unsafe {
                EVP_PKEY_encrypt_init_ex(
                    ctx.pkey_ctx.as_mut_ptr(),
                    params.as_ptr(),
                )
            },
            EncOp::Decrypt => unsafe {
                EVP_PKEY_decrypt_init_ex(
                    ctx.pkey_ctx.as_mut_ptr(),
                    params.as_ptr(),
                )
            },
        };
        if ret != 1 {
            match ctx.op {
                EncOp::Encrypt => {
                    trace_ossl!("EVP_PKEY_encrypt_init()");
                }
                EncOp::Decrypt => {
                    trace_ossl!("EVP_PKEY_decrypt_init()");
                }
            }
            trace_ossl!("EVP_PKEY_encrypt_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(ctx)
    }

    /// Executes an encryption operation if 'output' contains a buffer
    /// or probes and returns the expected output length if 'output' is None
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, Error> {
        if self.op != EncOp::Encrypt {
            return Err(Error::new(ErrorKind::WrapperError));
        }
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

    /// Executes an decryption operation if 'output' contains a buffer
    /// or probes and returns the expected output length if 'output' is None
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, Error> {
        if self.op != EncOp::Decrypt {
            return Err(Error::new(ErrorKind::WrapperError));
        }
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

/// Higher level wrapper for asymmetric encapsulation operations with OpenSSL
#[derive(Debug)]
pub struct OsslEncapsulation {
    /// The underlying OpenSSL EVP PKEY context.
    pkey_ctx: EvpPkeyCtx,
}

impl OsslEncapsulation {
    /// Initializes a new encapsulation operation
    pub fn new_encapsulation(
        libctx: &OsslContext,
        key: &mut EvpPkey,
    ) -> Result<OsslEncapsulation, Error> {
        let mut ctx = OsslEncapsulation {
            pkey_ctx: key.new_ctx(libctx)?,
        };
        let ret = unsafe {
            EVP_PKEY_encapsulate_init(
                ctx.pkey_ctx.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_encapsulate_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(ctx)
    }

    /// Encapsulates operation, returns ciphertext in the mutable slice and
    /// returns an encapsulated key as a vector as well as the actual size
    /// of the data returned in the ciphertext
    pub fn encapsulate(
        &mut self,
        ciphertext: &mut [u8],
    ) -> Result<(Vec<u8>, usize), Error> {
        let mut outlen = 0;
        let mut keylen = 0;

        let ret = unsafe {
            EVP_PKEY_encapsulate(
                self.pkey_ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                &mut outlen,
                std::ptr::null_mut(),
                &mut keylen,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_encapsulate()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        if ciphertext.len() < outlen {
            return Err(Error::new(ErrorKind::BufferSize));
        }

        let mut keydata = vec![0u8; keylen];
        let ret = unsafe {
            EVP_PKEY_encapsulate(
                self.pkey_ctx.as_mut_ptr(),
                ciphertext.as_mut_ptr(),
                &mut outlen,
                keydata.as_mut_ptr(),
                &mut keylen,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_encapsulate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        keydata.resize(keylen, 0);

        Ok((keydata, outlen))
    }

    /// Initializes a new decapsulation operation
    pub fn new_decapsulation(
        libctx: &OsslContext,
        key: &mut EvpPkey,
    ) -> Result<OsslEncapsulation, Error> {
        let mut ctx = OsslEncapsulation {
            pkey_ctx: key.new_ctx(libctx)?,
        };
        let ret = unsafe {
            EVP_PKEY_decapsulate_init(
                ctx.pkey_ctx.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_decapsulate_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(ctx)
    }

    /// Decapsulate operation, takes the ciphertext generated by the peer and
    /// returns an encapsulated key as a vector
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut keylen = 0;

        let ret = unsafe {
            EVP_PKEY_decapsulate(
                self.pkey_ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                &mut keylen,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_decapsulate()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        let mut keydata = vec![0u8; keylen];
        let ret = unsafe {
            EVP_PKEY_decapsulate(
                self.pkey_ctx.as_mut_ptr(),
                keydata.as_mut_ptr(),
                &mut keylen,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_decapsulate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        keydata.resize(keylen, 0);

        Ok(keydata)
    }
}
