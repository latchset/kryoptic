// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the OpenSSL
//! symmetric encryption apis

use std::ffi::{c_int, c_void, CStr};

use crate::bindings::*;
use crate::{
    cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam,
    OsslParamBuilder, OsslSecret,
};

/// Wrapper around OpenSSL's `EVP_CIPHER`, managing its lifecycle.
#[derive(Debug)]
struct EvpCipher {
    ptr: *mut EVP_CIPHER,
}

/// Methods for creating and accessing `EvpCipher`.
impl EvpCipher {
    fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpCipher, Error> {
        let ptr = unsafe {
            EVP_CIPHER_fetch(ctx.ptr(), name.as_ptr(), std::ptr::null_mut())
        };
        if ptr.is_null() {
            trace_ossl!("EVP_CIPHER_fetch()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpCipher { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_CIPHER`.
    unsafe fn as_ptr(&self) -> *const EVP_CIPHER {
        self.ptr
    }
}

impl Drop for EvpCipher {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpCipher {}
unsafe impl Sync for EvpCipher {}

/// Wrapper around OpenSSL's `EVP_CIPHER_CTX`, managing its lifecycle.
#[derive(Debug)]
struct EvpCipherCtx {
    ptr: *mut EVP_CIPHER_CTX,
}

/// Methods for creating and accessing `EvpCipherCtx`.
impl EvpCipherCtx {
    fn new() -> Result<EvpCipherCtx, Error> {
        let ptr = unsafe { EVP_CIPHER_CTX_new() };
        if ptr.is_null() {
            trace_ossl!("EVP_CIPHER_ctx_new()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpCipherCtx { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_CIPHER_CTX`.
    unsafe fn as_ptr(&self) -> *const EVP_CIPHER_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_CIPHER_CTX`.
    unsafe fn as_mut_ptr(&mut self) -> *mut EVP_CIPHER_CTX {
        self.ptr
    }
}

impl Drop for EvpCipherCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpCipherCtx {}
unsafe impl Sync for EvpCipherCtx {}

/// Aes Key Sizes
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AesSize {
    Aes128,
    Aes192,
    Aes256,
}
/// Camellia Key Sizes
#[cfg(feature = "rfc9580")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CamelliaSize {
    Camellia128,
    Camellia192,
    Camellia256,
}
/// Aes CTS comes in three modes
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AesCtsMode {
    CtsModeCS1,
    CtsModeCS2,
    CtsModeCS3,
}

/// Known algorithms selectable for OsslCipher
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EncAlg {
    AesCcm(AesSize),
    AesGcm(AesSize),
    AesCts(AesSize, AesCtsMode),
    AesCtr(AesSize),
    AesCbc(AesSize),
    AesEcb(AesSize),
    AesCfb8(AesSize),
    AesCfb1(AesSize),
    AesCfb128(AesSize),
    AesOcb(AesSize),
    AesOfb(AesSize),
    AesWrap(AesSize),
    AesWrapPad(AesSize),
    /* 3DES */
    #[cfg(feature = "rfc9580")]
    TripleDesCfb,
    #[cfg(feature = "rfc9580")]
    TripleDesCbc,
    #[cfg(feature = "rfc9580")]
    TripleDesEcb,
    #[cfg(feature = "rfc9580")]
    CamelliaCfb(CamelliaSize),
    #[cfg(feature = "rfc9580")]
    CamelliaCbc(CamelliaSize),
    #[cfg(feature = "rfc9580")]
    CamelliaEcb(CamelliaSize),
    #[cfg(feature = "rfc9580")]
    BlowfishCfb,
    #[cfg(feature = "rfc9580")]
    BlowfishCbc,
    #[cfg(feature = "rfc9580")]
    BlowfishEcb,
    #[cfg(feature = "rfc9580")]
    Cast5Cfb,
    #[cfg(feature = "rfc9580")]
    Cast5Cbc,
    #[cfg(feature = "rfc9580")]
    Cast5Ecb,
    #[cfg(feature = "rfc9580")]
    IdeaCfb,
    #[cfg(feature = "rfc9580")]
    IdeaCbc,
    #[cfg(feature = "rfc9580")]
    IdeaEcb,
}

/// Returns the Ossl name for the requested cipher
fn cipher_to_name(alg: EncAlg) -> &'static CStr {
    match alg {
        EncAlg::AesCcm(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_ccm),
            AesSize::Aes192 => cstr!(LN_aes_192_ccm),
            AesSize::Aes256 => cstr!(LN_aes_256_ccm),
        },
        EncAlg::AesGcm(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_gcm),
            AesSize::Aes192 => cstr!(LN_aes_192_gcm),
            AesSize::Aes256 => cstr!(LN_aes_256_gcm),
        },
        EncAlg::AesCtr(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_ctr),
            AesSize::Aes192 => cstr!(LN_aes_192_ctr),
            AesSize::Aes256 => cstr!(LN_aes_256_ctr),
        },
        EncAlg::AesCts(size, _) => match size {
            AesSize::Aes128 => c"AES-128-CBC-CTS",
            AesSize::Aes192 => c"AES-192-CBC-CTS",
            AesSize::Aes256 => c"AES-256-CBC-CTS",
        },
        EncAlg::AesCbc(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_cbc),
            AesSize::Aes192 => cstr!(LN_aes_192_cbc),
            AesSize::Aes256 => cstr!(LN_aes_256_cbc),
        },
        EncAlg::AesEcb(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_ecb),
            AesSize::Aes192 => cstr!(LN_aes_192_ecb),
            AesSize::Aes256 => cstr!(LN_aes_256_ecb),
        },
        EncAlg::AesCfb8(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_cfb8),
            AesSize::Aes192 => cstr!(LN_aes_192_cfb8),
            AesSize::Aes256 => cstr!(LN_aes_256_cfb8),
        },
        EncAlg::AesCfb1(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_cfb1),
            AesSize::Aes192 => cstr!(LN_aes_192_cfb1),
            AesSize::Aes256 => cstr!(LN_aes_256_cfb1),
        },
        EncAlg::AesCfb128(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_cfb128),
            AesSize::Aes192 => cstr!(LN_aes_192_cfb128),
            AesSize::Aes256 => cstr!(LN_aes_256_cfb128),
        },
        EncAlg::AesOcb(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_ocb),
            AesSize::Aes192 => cstr!(LN_aes_192_ocb),
            AesSize::Aes256 => cstr!(LN_aes_256_ocb),
        },
        EncAlg::AesOfb(size) => match size {
            AesSize::Aes128 => cstr!(LN_aes_128_ofb128),
            AesSize::Aes192 => cstr!(LN_aes_192_ofb128),
            AesSize::Aes256 => cstr!(LN_aes_256_ofb128),
        },
        EncAlg::AesWrap(size) => match size {
            AesSize::Aes128 => c"AES-128-WRAP",
            AesSize::Aes192 => c"AES-192-WRAP",
            AesSize::Aes256 => c"AES-256-WRAP",
        },
        EncAlg::AesWrapPad(size) => match size {
            AesSize::Aes128 => c"AES-128-WRAP-PAD",
            AesSize::Aes192 => c"AES-192-WRAP-PAD",
            AesSize::Aes256 => c"AES-256-WRAP-PAD",
        },
        #[cfg(feature = "rfc9580")]
        EncAlg::TripleDesCfb => c"DES-EDE3-CFB",
        #[cfg(feature = "rfc9580")]
        EncAlg::TripleDesCbc => c"DES-EDE3-CBC",
        #[cfg(feature = "rfc9580")]
        EncAlg::TripleDesEcb => c"DES-EDE3-ECB",
        #[cfg(feature = "rfc9580")]
        EncAlg::CamelliaCfb(size) => match size {
            CamelliaSize::Camellia128 => c"CAMELLIA-128-CFB",
            CamelliaSize::Camellia192 => c"CAMELLIA-192-CFB",
            CamelliaSize::Camellia256 => c"CAMELLIA-256-CFB",
        },
        #[cfg(feature = "rfc9580")]
        EncAlg::CamelliaCbc(size) => match size {
            CamelliaSize::Camellia128 => c"CAMELLIA-128-CBC",
            CamelliaSize::Camellia192 => c"CAMELLIA-192-CBC",
            CamelliaSize::Camellia256 => c"CAMELLIA-256-CBC",
        },
        #[cfg(feature = "rfc9580")]
        EncAlg::CamelliaEcb(size) => match size {
            CamelliaSize::Camellia128 => c"CAMELLIA-128-ECB",
            CamelliaSize::Camellia192 => c"CAMELLIA-192-ECB",
            CamelliaSize::Camellia256 => c"CAMELLIA-256-ECB",
        },
        #[cfg(feature = "rfc9580")]
        EncAlg::BlowfishCfb => c"BF-CFB",
        #[cfg(feature = "rfc9580")]
        EncAlg::BlowfishCbc => c"BF-CBC",
        #[cfg(feature = "rfc9580")]
        EncAlg::BlowfishEcb => c"BF-ECB",
        #[cfg(feature = "rfc9580")]
        EncAlg::Cast5Cfb => c"CAST5-CFB",
        #[cfg(feature = "rfc9580")]
        EncAlg::Cast5Cbc => c"CAST5-CBC",
        #[cfg(feature = "rfc9580")]
        EncAlg::Cast5Ecb => c"CAST5-ECB",
        #[cfg(feature = "rfc9580")]
        EncAlg::IdeaCfb => c"IDEA-CFB",
        #[cfg(feature = "rfc9580")]
        EncAlg::IdeaCbc => c"IDEA-CBC",
        #[cfg(feature = "rfc9580")]
        EncAlg::IdeaEcb => c"IDEA-ECB",
    }
}

pub struct AeadParams {
    /// Additional Authenticated Data (AAD)
    aad: Option<Vec<u8>>,
    /// Requested tag length
    tag_len: usize,
    /// The Data Length for CCM (ignored for other AEAD ciphers)
    ccm_data_len: usize,
}

impl AeadParams {
    /// Returns a new AeadParams structure
    pub fn new(
        aad: Option<Vec<u8>>,
        tag_len: usize,
        ccm_data_len: usize,
    ) -> AeadParams {
        AeadParams {
            aad: aad,
            tag_len: tag_len,
            ccm_data_len: ccm_data_len,
        }
    }
}

/// Higher level wrapper for symmetric encryption operations with OpenSSL
#[derive(Debug)]
pub struct OsslCipher {
    /// The underlying OpenSSL EVP Cipher context
    ctx: EvpCipherCtx,
    /// Wheter we encrypt (1) or decrypt (0)
    enc: c_int,
    /// The Key material
    key: OsslSecret,
    /// Optional IV buffer storage
    iv: Option<Vec<u8>>,
    /// Optional AAD buffer storage
    aad: Option<Vec<u8>>,
    /// The block size used in this operation. It is used to
    /// calculate the minimum acceptable output buffer size in
    /// update operations. This is 1 for streaming ciphers and
    /// AEAD constructions
    blocksize: usize,
}

impl OsslCipher {
    /// Initializes a cipher operation
    pub fn new(
        libctx: &OsslContext,
        alg: EncAlg,
        enc: bool,
        key: OsslSecret,
        iv: Option<Vec<u8>>,
        aead: Option<AeadParams>,
    ) -> Result<OsslCipher, Error> {
        let cipher = EvpCipher::new(libctx, cipher_to_name(alg))?;

        let mut ctx = OsslCipher {
            ctx: EvpCipherCtx::new()?,
            enc: if enc { 1 } else { 0 },
            key,
            iv,
            aad: None,
            blocksize: 1,
        };

        /* Need to initialize the cipher on the ctx first, as some modes
         * will attempt to set parameters that require it on the context,
         * before key and iv can be installed */
        let ret = unsafe {
            EVP_CipherInit_ex2(
                ctx.ctx.as_mut_ptr(),
                cipher.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                ctx.enc,
                std::ptr::null(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CipherInit_ex2()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        let params: OsslParam;
        let mut params_ptr = std::ptr::null() as *const OSSL_PARAM;

        /* For some modes there is setup that needs to be done
         * early, before the cipher ctx is fully initialized */
        match alg {
            EncAlg::AesCcm(_) | EncAlg::AesGcm(_) | EncAlg::AesOcb(_) => {
                ctx.aead_setup(alg, &aead)?
            }
            EncAlg::AesCts(_, mode) => {
                let mut params_builder = OsslParamBuilder::with_capacity(1);
                params_builder.add_const_c_string(
                    cstr!(OSSL_CIPHER_PARAM_CTS_MODE),
                    match mode {
                        AesCtsMode::CtsModeCS1 => {
                            cstr!(OSSL_CIPHER_CTS_MODE_CS1)
                        }
                        AesCtsMode::CtsModeCS2 => {
                            cstr!(OSSL_CIPHER_CTS_MODE_CS2)
                        }
                        AesCtsMode::CtsModeCS3 => {
                            cstr!(OSSL_CIPHER_CTS_MODE_CS3)
                        }
                    },
                )?;
                params = params_builder.finalize();
                params_ptr = params.as_ptr();
            }
            _ => (),
        }

        let iv_ptr = match &ctx.iv {
            Some(iv) => {
                let len =
                    unsafe { EVP_CIPHER_CTX_get_iv_length(ctx.ctx.as_ptr()) };
                if len != 0 && iv.len() != usize::try_from(len)? {
                    return Err(Error::new(ErrorKind::BadArg));
                }
                iv.as_ptr()
            }
            None => std::ptr::null(),
        };

        /* complete initialization now that all necessary parameters have
         * been processed */
        let ret = unsafe {
            EVP_CipherInit_ex2(
                ctx.ctx.as_mut_ptr(),
                std::ptr::null(),
                ctx.key.as_ptr(),
                iv_ptr,
                ctx.enc,
                params_ptr,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CipherInit_ex2()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        /* For CCM we need to pass in the expected data length,
         * OpenSSL has a very quirky way to do it ... */
        match alg {
            EncAlg::AesCcm(_) => {
                let ret = unsafe {
                    let datalen = match &aead {
                        Some(x) => x.ccm_data_len,
                        None => return Err(Error::new(ErrorKind::BadArg)),
                    };
                    let mut outlen: c_int = 0;
                    EVP_CipherUpdate(
                        ctx.ctx.as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut outlen,
                        std::ptr::null(),
                        c_int::try_from(datalen)?,
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_CipherUpdate()");
                    return Err(Error::new(ErrorKind::OsslError));
                }
            }
            _ => (),
        }

        /* Now it is time to set the AAD, if any, for AEAD ciphers */
        match aead {
            Some(x) => {
                ctx.aad = x.aad;
                if let Some(aad) = &ctx.aad {
                    let ret = unsafe {
                        let mut outlen: c_int = 0;
                        EVP_CipherUpdate(
                            ctx.ctx.as_mut_ptr(),
                            std::ptr::null_mut(),
                            &mut outlen,
                            aad.as_ptr(),
                            c_int::try_from(aad.len())?,
                        )
                    };
                    if ret != 1 {
                        trace_ossl!("EVP_CipherUpdate()");
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
            }
            None => {
                ctx.blocksize = unsafe {
                    usize::try_from(EVP_CIPHER_CTX_get_block_size(
                        ctx.ctx.as_mut_ptr(),
                    ))?
                };
            }
        }

        Ok(ctx)
    }

    /// Check if the cipher is supported in the given context
    ///
    /// Note, that some ciphers are not supported in default
    /// provider and need a legacy provider loaded.
    pub fn is_supported(libctx: &OsslContext, alg: EncAlg) -> bool {
        match EvpCipher::new(libctx, cipher_to_name(alg)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Helper to set context parameters for AEAD modes
    fn aead_setup(
        &mut self,
        alg: EncAlg,
        aead: &Option<AeadParams>,
    ) -> Result<(), Error> {
        let params = match aead {
            Some(p) => p,
            None => return Err(Error::new(ErrorKind::BadArg)),
        };
        let iv_len = match &self.iv {
            Some(iv) => iv.len(),
            None => return Err(Error::new(ErrorKind::BadArg)),
        };
        let ret = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx.as_mut_ptr(),
                c_int::try_from(EVP_CTRL_AEAD_SET_IVLEN)?,
                c_int::try_from(iv_len)?,
                std::ptr::null_mut(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CIPHER_CTX_ctrl()");
            return Err(Error::new(ErrorKind::OsslError));
        }

        match alg {
            EncAlg::AesCcm(_) => {
                /* Sets the TAG length only */
                let ret = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                        c_int::try_from(params.tag_len)?,
                        std::ptr::null_mut(),
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_CIPHER_CTX_ctrl()");
                    return Err(Error::new(ErrorKind::OsslError));
                }
            }
            _ => (),
        }

        Ok(())
    }

    /// Utility option to set the cipher padding.
    /// Not all ciphers can set padding.
    /// Should be called only immediately after initialization.
    pub fn set_padding(&mut self, b: bool) -> Result<(), Error> {
        let ret = unsafe {
            EVP_CIPHER_CTX_set_padding(
                self.ctx.as_mut_ptr(),
                match b {
                    true => 1,
                    false => 0,
                },
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CIPHER_CTX_set_padding()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Ingests plain text data and possibly outputs encrypted data.
    ///
    /// This api tries to be as efficient as possible and avoid
    /// allocations, therefore it takes a slice where to return
    /// output.
    ///
    /// Whether data is emitted depends on the mode of operation and
    /// the data provided.
    ///
    /// OpenSSL's APIs have very sharp edges, and make assumptions
    /// on the size of the output buffers and will happily
    /// overwrite a short buffer.
    ///
    /// To make this API as safe as possible sometimes a buffer
    /// larger than what is strictly needed is required by te API.
    /// If the buffer is not large enough a `ErrorKind::BufferSize`
    /// is returned and no data is ingested.
    ///
    /// The caller can retry with an appropriately sized larger
    /// buffer.
    ///
    /// The `buffer_size` call can be used to inquire on the required
    /// minimum buffer size.
    /// On success the actual output length is returned.
    ///
    /// The rest of the output buffer will contain undetermined data.
    pub fn update(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if output.len() < self.buffer_size(input.len()) {
            return Err(Error::new(ErrorKind::BufferSize));
        }

        let mut outlen = c_int::try_from(output.len())?;
        let ret = unsafe {
            EVP_CipherUpdate(
                self.ctx.as_mut_ptr(),
                output.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                c_int::try_from(input.len())?,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CipherUpdate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(outlen)?)
    }

    /// Finalizes this encryption operation.
    /// May return a final block of output.
    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.buffer_size(0) {
            return Err(Error::new(ErrorKind::BufferSize));
        }

        let mut outlen = c_int::try_from(output.len())?;
        let ret = unsafe {
            EVP_CipherFinal_ex(
                self.ctx.as_mut_ptr(),
                output.as_mut_ptr(),
                &mut outlen,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CipherFinal_ex()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(outlen)?)
    }

    /// Sets te TAG for AEAD modes, or an error otherwise.
    /// This is usually called just before the `finalize` call.
    pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        let ret = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx.as_mut_ptr(),
                c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                c_int::try_from(tag.len())?,
                tag.as_ptr() as *mut c_void,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CIPHER_CTX_ctrl()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Returns the tag for AEAD modes, or an error otherwise.
    /// Should be called only after the `finalize` call.
    pub fn get_tag(&mut self, tag: &mut [u8]) -> Result<(), Error> {
        let ret = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx.as_mut_ptr(),
                c_int::try_from(EVP_CTRL_AEAD_GET_TAG)?,
                c_int::try_from(tag.len())?,
                tag.as_mut_ptr() as *mut c_void,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_CIPHER_CTX_ctrl()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Returns the block size, or `None` for stream ciphers and AEAD
    /// constructions.
    pub fn block_size(&self) -> Option<usize> {
        if self.blocksize == 1 {
            None
        } else {
            Some(self.blocksize)
        }
    }

    pub fn buffer_size(&self, input: usize) -> usize {
        if self.blocksize == 1 {
            return input;
        }
        if input == 0 {
            return self.blocksize;
        }
        let remainder = input % self.blocksize;
        if remainder == 0 {
            input
        } else {
            input + self.blocksize - remainder
        }
    }
}
