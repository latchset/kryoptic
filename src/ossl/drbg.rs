// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements Deterministic Random Bit Generators (DRBGs) based on
//! HMAC, as specified in NIST SP 800-90A, using the OpenSSL EVP_RAND API.

use std::ffi::c_char;

use crate::error::Result;
use crate::mechanism::DRBG;
use crate::ossl::bindings::*;

use pkcs11::*;

#[cfg(not(feature = "fips"))]
use crate::ossl::get_libctx;

#[cfg(feature = "fips")]
use crate::ossl::fips::*;

/// Implements HMAC-DRBG using SHA-256 as the underlying hash function.
#[derive(Debug)]
pub struct HmacSha256Drbg {
    /// Flag indicating if the DRBG has been successfully instantiated.
    initialized: bool,
    /// Pointer to the OpenSSL EVP_RAND_CTX state.
    state: *mut EVP_RAND_CTX,
}

impl Drop for HmacSha256Drbg {
    fn drop(&mut self) {
        unsafe {
            EVP_RAND_CTX_free(self.state);
        }
    }
}

impl HmacSha256Drbg {
    /// Creates and initializes a new HMAC-DRBG (SHA-256) instance.
    /// Calls the internal `init` method with a default personalization string.
    pub fn new() -> Result<HmacSha256Drbg> {
        unsafe {
            let rng_spec: &[u8; 10] = b"HMAC-DRBG\0";
            let rand = EVP_RAND_fetch(
                get_libctx(),
                rng_spec.as_ptr() as *const c_char,
                std::ptr::null(),
            );

            let mut rng = HmacSha256Drbg {
                initialized: false,
                state: EVP_RAND_CTX_new(rand, std::ptr::null_mut()),
            };
            EVP_RAND_free(rand);

            let personalization_string = b"HMAC SHA256 DRBG Initialization";
            rng.init(&[0u8; 0], &[0u8; 0], personalization_string)?;
            Ok(rng)
        }
    }
}

impl DRBG for HmacSha256Drbg {
    /// Instantiates the DRBG state.
    ///
    /// Corresponds to the Instantiate operation in NIST SP 800-90A.
    /// Configures the underlying EVP_RAND context to use HMAC and SHA-256.
    fn init(
        &mut self,
        _entropy: &[u8],
        _nonce: &[u8],
        pers: &[u8],
    ) -> Result<()> {
        unsafe {
            let rng_mac = b"HMAC\0";
            let rng_digest = b"SHA256\0";
            let params = [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_DRBG_PARAM_MAC.as_ptr() as *const c_char,
                    rng_mac.as_ptr() as *mut c_char,
                    rng_mac.len() - 1,
                ),
                OSSL_PARAM_construct_utf8_string(
                    OSSL_DRBG_PARAM_DIGEST.as_ptr() as *const c_char,
                    rng_digest.as_ptr() as *mut c_char,
                    rng_digest.len() - 1,
                ),
                OSSL_PARAM_construct_end(),
            ];

            let res = EVP_RAND_instantiate(
                self.state,
                0,
                1,
                pers.as_ptr(),
                pers.len(),
                params.as_ptr(),
            );
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }
        self.initialized = true;
        Ok(())
    }

    /// Reseeds the DRBG state with additional entropy.
    ///
    /// Corresponds to the Reseed operation in NIST SP 800-90A.
    fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        unsafe {
            let res = EVP_RAND_reseed(
                self.state,
                1,
                entropy.as_ptr(),
                entropy.len(),
                addtl.as_ptr(),
                addtl.len(),
            );
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }
        Ok(())
    }

    /// Generates random bytes from the DRBG.
    ///
    /// Corresponds to the Generate operation in NIST SP 800-90A.
    /// Can optionally include additional input (`addtl`).
    fn generate(&mut self, addtl: &[u8], output: &mut [u8]) -> Result<()> {
        if !self.initialized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let res = unsafe {
            EVP_RAND_generate(
                self.state,
                output.as_mut_ptr(),
                output.len(),
                0,
                0,
                addtl.as_ptr() as *mut u8,
                addtl.len(),
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(())
    }
}

unsafe impl Send for HmacSha256Drbg {}
unsafe impl Sync for HmacSha256Drbg {}

/// Implements HMAC-DRBG using SHA-512 as the underlying hash function.
#[derive(Debug)]
pub struct HmacSha512Drbg {
    /// Flag indicating if the DRBG has been successfully instantiated.
    initialized: bool,
    /// Pointer to the OpenSSL EVP_RAND_CTX state.
    state: *mut EVP_RAND_CTX,
}

impl Drop for HmacSha512Drbg {
    fn drop(&mut self) {
        unsafe {
            EVP_RAND_CTX_free(self.state);
        }
    }
}

impl HmacSha512Drbg {
    /// Creates and initializes a new HMAC-DRBG (SHA-512) instance.
    /// Calls the internal `init` method with a default personalization string.
    pub fn new() -> Result<HmacSha512Drbg> {
        unsafe {
            let rng_spec = b"HMAC-DRBG\0";
            let rand = EVP_RAND_fetch(
                get_libctx(),
                rng_spec.as_ptr() as *const c_char,
                std::ptr::null(),
            );

            let mut rng = HmacSha512Drbg {
                initialized: false,
                state: EVP_RAND_CTX_new(rand, std::ptr::null_mut()),
            };
            EVP_RAND_free(rand);

            let personalization_string = b"HMAC SHA512 DRBG Initialization";
            rng.init(&[0u8; 0], &[0u8; 0], personalization_string)?;
            Ok(rng)
        }
    }
}

impl DRBG for HmacSha512Drbg {
    /// Instantiates the DRBG state.
    ///
    /// Corresponds to the Instantiate operation in NIST SP 800-90A.
    /// Configures the underlying EVP_RAND context to use HMAC and SHA-512.
    fn init(
        &mut self,
        _entropy: &[u8],
        _nonce: &[u8],
        pers: &[u8],
    ) -> Result<()> {
        unsafe {
            let rng_mac = b"HMAC\0";
            let rng_digest = b"SHA512\0";
            let params = [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_DRBG_PARAM_MAC.as_ptr() as *const c_char,
                    rng_mac.as_ptr() as *mut c_char,
                    rng_mac.len() - 1,
                ),
                OSSL_PARAM_construct_utf8_string(
                    OSSL_DRBG_PARAM_DIGEST.as_ptr() as *const c_char,
                    rng_digest.as_ptr() as *mut c_char,
                    rng_digest.len() - 1,
                ),
                OSSL_PARAM_construct_end(),
            ];

            let res = EVP_RAND_instantiate(
                self.state,
                0,
                1,
                pers.as_ptr(),
                pers.len(),
                params.as_ptr(),
            );
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }
        self.initialized = true;
        Ok(())
    }

    /// Reseeds the DRBG state with additional entropy.
    ///
    /// Corresponds to the Reseed operation in NIST SP 800-90A.
    fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        unsafe {
            let res = EVP_RAND_reseed(
                self.state,
                1,
                entropy.as_ptr(),
                entropy.len(),
                addtl.as_ptr(),
                addtl.len(),
            );
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }
        Ok(())
    }

    /// Generates random bytes from the DRBG.
    ///
    /// Corresponds to the Generate operation in NIST SP 800-90A.
    /// Can optionally include additional input (`addtl`).
    fn generate(&mut self, addtl: &[u8], output: &mut [u8]) -> Result<()> {
        if !self.initialized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let res = unsafe {
            EVP_RAND_generate(
                self.state,
                output.as_mut_ptr(),
                output.len(),
                0,
                0,
                addtl.as_ptr() as *mut u8,
                addtl.len(),
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(())
    }
}

unsafe impl Send for HmacSha512Drbg {}
unsafe impl Sync for HmacSha512Drbg {}
