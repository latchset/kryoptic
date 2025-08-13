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
) -> Result<OsslParam<'_>, Error> {
    let mut params_builder = crate::OsslParamBuilder::new();

    match alg {
        EncAlg::RsaNoPad => params_builder.add_const_c_string(
            cstr!(OSSL_PKEY_PARAM_PAD_MODE),
            cstr!(OSSL_PKEY_RSA_PAD_MODE_NONE),
        )?,
        EncAlg::RsaOaep => {
            if let Some(oaep) = &oaep_params {
                params_builder.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_PAD_MODE),
                    cstr!(OSSL_PKEY_RSA_PAD_MODE_OAEP),
                )?;
                params_builder.add_const_c_string(
                    cstr!(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST),
                    digest_to_string(oaep.digest),
                )?;
                params_builder.add_const_c_string(
                    cstr!(OSSL_PKEY_PARAM_MGF1_DIGEST),
                    digest_to_string(oaep.mgf1),
                )?;
                match &oaep.label {
                    None => (),
                    Some(label) => params_builder.add_octet_string(
                        cstr!(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL),
                        &label,
                    )?,
                }
            } else {
                return Err(Error::new(ErrorKind::NullPtr));
            }
        }
        EncAlg::RsaPkcs1_5 => params_builder.add_const_c_string(
            cstr!(OSSL_PKEY_PARAM_PAD_MODE),
            cstr!(OSSL_PKEY_RSA_PAD_MODE_PKCSV15),
        )?,
    }

    Ok(params_builder.finalize())
}

/// Asymmetric Cipher Operation
#[derive(Debug, PartialEq)]
pub enum EncOp {
    Encrypt,
    Decrypt,
    Encapsulate,
    Decapsulate,
}

/// Higher level wrapper for asymmetric cipher operations with OpenSSL
///
/// Supports Encryption, Decryption, Encapsulation, Decapsulation.
/// Whether any of these operation will work also depends on the type
/// of key provided.
///
/// An OsslError is returned if an operation is unsupported.
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
        params: Option<&OsslParam>,
    ) -> Result<OsslAsymcipher, Error> {
        let mut ctx = OsslAsymcipher {
            pkey_ctx: key.new_ctx(libctx)?,
            op: op,
        };
        let params_ptr = match params {
            Some(p) => p.as_ptr(),
            None => std::ptr::null(),
        };
        let ret = match ctx.op {
            EncOp::Encrypt => unsafe {
                EVP_PKEY_encrypt_init_ex(ctx.pkey_ctx.as_mut_ptr(), params_ptr)
            },
            EncOp::Decrypt => unsafe {
                EVP_PKEY_decrypt_init_ex(ctx.pkey_ctx.as_mut_ptr(), params_ptr)
            },
            EncOp::Encapsulate => unsafe {
                EVP_PKEY_encapsulate_init(ctx.pkey_ctx.as_mut_ptr(), params_ptr)
            },
            EncOp::Decapsulate => unsafe {
                EVP_PKEY_decapsulate_init(ctx.pkey_ctx.as_mut_ptr(), params_ptr)
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
                EncOp::Encapsulate => {
                    trace_ossl!("EVP_PKEY_encapsulate_init()");
                }
                EncOp::Decapsulate => {
                    trace_ossl!("EVP_PKEY_decapsulate_init()");
                }
            }
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

    /// Encapsulates operation, returns ciphertext in the mutable slice and
    /// returns an encapsulated key as a vector as well as the actual size
    /// of the data returned in the ciphertext
    pub fn encapsulate(
        &mut self,
        ciphertext: &mut [u8],
    ) -> Result<(Vec<u8>, usize), Error> {
        if self.op != EncOp::Encapsulate {
            return Err(Error::new(ErrorKind::WrapperError));
        }
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

    /// Decapsulate operation, takes the ciphertext generated by the peer and
    /// returns an encapsulated key as a vector
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.op != EncOp::Decapsulate {
            return Err(Error::new(ErrorKind::WrapperError));
        }
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
