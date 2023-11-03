// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::cryptography;
use super::err_rv;
use super::error;
use super::interface;
use super::mechanism;
use cryptography::*;
use error::{KError, KResult};
use interface::*;
use mechanism::*;
use std::fmt::Debug;

use getrandom;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct HmacSha256Drbg {
    initialized: bool,
    state: Hacl_HMAC_DRBG_state,
}

impl Drop for HmacSha256Drbg {
    fn drop(&mut self) {
        if self.initialized {
            /*
             * UNSAFE:  The following zeroization depends on internal
             * knowledge of the implementation which does not currently
             * provide zeroization and allocated buffers with lengths
             * that are hardcoded in code but not stored in the structure
             * itself. This means that a change in the implementation may
             * cause this unsafe code to crash.
             */
            unsafe {
                let hashlen: usize = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_256,
                )
                .try_into()
                .unwrap();
                let k = std::slice::from_raw_parts_mut(
                    self.state.k as *mut u8,
                    hashlen,
                );
                let v = std::slice::from_raw_parts_mut(
                    self.state.v as *mut u8,
                    hashlen,
                );
                let rc = std::slice::from_raw_parts_mut(
                    self.state.reseed_counter as *mut u32,
                    1,
                );
                k.zeroize();
                v.zeroize();
                rc.zeroize();

                /* Free the buffers after zeroization */
                Hacl_HMAC_DRBG_free(Spec_Hash_Definitions_SHA2_256, self.state);
            }
            self.initialized = false;
        }
    }
}

impl HmacSha256Drbg {
    pub fn new() -> KResult<HmacSha256Drbg> {
        let mut s = HmacSha256Drbg {
            initialized: false,
            state: unsafe {
                Hacl_HMAC_DRBG_create_in(Spec_Hash_Definitions_SHA2_256)
            },
        };
        let minlen: usize = unsafe {
            Hacl_HMAC_DRBG_min_length(Spec_Hash_Definitions_SHA2_256)
                .try_into()
                .unwrap()
        };
        let mut entropy: Vec<u8> = vec![0; minlen];
        if getrandom::getrandom(entropy.as_mut_slice()).is_err() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut nonce: Vec<u8> = vec![0; minlen];
        if getrandom::getrandom(nonce.as_mut_slice()).is_err() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let personalization_string = "HMAC SHA256 DRBG Initialization";
        s.init(&entropy, &nonce, personalization_string.as_bytes())?;
        Ok(s)
    }
}

impl DRBG for HmacSha256Drbg {
    fn init(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        pers: &[u8],
    ) -> KResult<()> {
        unsafe {
            Hacl_HMAC_DRBG_instantiate(
                Spec_Hash_Definitions_SHA2_256,
                self.state,
                entropy.len().try_into().unwrap(),
                entropy.as_ptr() as *mut u8,
                nonce.len().try_into().unwrap(),
                nonce.as_ptr() as *mut u8,
                pers.len().try_into().unwrap(),
                pers.as_ptr() as *mut u8,
            );
        }
        self.initialized = true;
        Ok(())
    }
    fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> KResult<()> {
        if !self.initialized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        unsafe {
            Hacl_HMAC_DRBG_reseed(
                Spec_Hash_Definitions_SHA2_256,
                self.state,
                entropy.len().try_into().unwrap(),
                entropy.as_ptr() as *mut u8,
                addtl.len().try_into().unwrap(),
                addtl.as_ptr() as *mut u8,
            );
        }
        Ok(())
    }
    fn generate(&mut self, addtl: &[u8], output: &mut [u8]) -> KResult<()> {
        if !self.initialized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut res = unsafe {
            Hacl_HMAC_DRBG_generate(
                Spec_Hash_Definitions_SHA2_256,
                output.as_mut_ptr(),
                self.state,
                output.len().try_into().unwrap(),
                addtl.len().try_into().unwrap(),
                addtl.as_ptr() as *mut u8,
            )
        };
        if !res {
            let mut entropy: [u8; 32] = [0; 32];
            if getrandom::getrandom(&mut entropy).is_err() {
                return err_rv!(CKR_GENERAL_ERROR);
            }
            self.reseed(&entropy, addtl)?;
            res = unsafe {
                Hacl_HMAC_DRBG_generate(
                    Spec_Hash_Definitions_SHA2_256,
                    output.as_mut_ptr(),
                    self.state,
                    output.len().try_into().unwrap(),
                    addtl.len().try_into().unwrap(),
                    addtl.as_ptr() as *mut u8,
                )
            };
            if !res {
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }
        Ok(())
    }
}

unsafe impl Send for HmacSha256Drbg {}
unsafe impl Sync for HmacSha256Drbg {}

#[derive(Debug)]
pub struct HmacSha512Drbg {
    initialized: bool,
    state: Hacl_HMAC_DRBG_state,
}

impl Drop for HmacSha512Drbg {
    fn drop(&mut self) {
        if self.initialized {
            /*
             * UNSAFE:  The following zeroization depends on internal
             * knowledge of the implementation which does not currently
             * provide zeroization and allocated buffers with lengths
             * that are hardcoded in code but not stored in the structure
             * itself. This means that a change in the implementation may
             * cause this unsafe code to crash.
             */
            unsafe {
                let hashlen: usize = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_512,
                )
                .try_into()
                .unwrap();
                let k = std::slice::from_raw_parts_mut(
                    self.state.k as *mut u8,
                    hashlen,
                );
                let v = std::slice::from_raw_parts_mut(
                    self.state.v as *mut u8,
                    hashlen,
                );
                let rc = std::slice::from_raw_parts_mut(
                    self.state.reseed_counter as *mut u32,
                    1,
                );
                k.zeroize();
                v.zeroize();
                rc.zeroize();

                /* Free the buffers after zeroization */
                Hacl_HMAC_DRBG_free(Spec_Hash_Definitions_SHA2_512, self.state);
            }
            self.initialized = false;
        }
    }
}

impl HmacSha512Drbg {
    pub fn new() -> KResult<HmacSha512Drbg> {
        let mut s = HmacSha512Drbg {
            initialized: false,
            state: unsafe {
                Hacl_HMAC_DRBG_create_in(Spec_Hash_Definitions_SHA2_512)
            },
        };
        let minlen: usize = unsafe {
            Hacl_HMAC_DRBG_min_length(Spec_Hash_Definitions_SHA2_512)
                .try_into()
                .unwrap()
        };
        let mut entropy: Vec<u8> = vec![0; minlen];
        if getrandom::getrandom(entropy.as_mut_slice()).is_err() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut nonce: Vec<u8> = vec![0; minlen];
        if getrandom::getrandom(nonce.as_mut_slice()).is_err() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let personalization_string = "HMAC SHA512 DRBG Initialization";
        s.init(&entropy, &nonce, personalization_string.as_bytes())?;
        Ok(s)
    }
}

impl DRBG for HmacSha512Drbg {
    fn init(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        pers: &[u8],
    ) -> KResult<()> {
        unsafe {
            Hacl_HMAC_DRBG_instantiate(
                Spec_Hash_Definitions_SHA2_512,
                self.state,
                entropy.len().try_into().unwrap(),
                entropy.as_ptr() as *mut u8,
                nonce.len().try_into().unwrap(),
                nonce.as_ptr() as *mut u8,
                pers.len().try_into().unwrap(),
                pers.as_ptr() as *mut u8,
            );
        }
        self.initialized = true;
        Ok(())
    }
    fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> KResult<()> {
        if !self.initialized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        unsafe {
            Hacl_HMAC_DRBG_reseed(
                Spec_Hash_Definitions_SHA2_512,
                self.state,
                entropy.len().try_into().unwrap(),
                entropy.as_ptr() as *mut u8,
                addtl.len().try_into().unwrap(),
                addtl.as_ptr() as *mut u8,
            );
        }
        Ok(())
    }
    fn generate(&mut self, addtl: &[u8], output: &mut [u8]) -> KResult<()> {
        if !self.initialized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut res = unsafe {
            Hacl_HMAC_DRBG_generate(
                Spec_Hash_Definitions_SHA2_512,
                output.as_mut_ptr(),
                self.state,
                output.len().try_into().unwrap(),
                addtl.len().try_into().unwrap(),
                addtl.as_ptr() as *mut u8,
            )
        };
        if !res {
            let mut entropy: [u8; 32] = [0; 32];
            if getrandom::getrandom(&mut entropy).is_err() {
                return err_rv!(CKR_GENERAL_ERROR);
            }
            self.reseed(&entropy, addtl)?;
            res = unsafe {
                Hacl_HMAC_DRBG_generate(
                    Spec_Hash_Definitions_SHA2_512,
                    output.as_mut_ptr(),
                    self.state,
                    output.len().try_into().unwrap(),
                    addtl.len().try_into().unwrap(),
                    addtl.as_ptr() as *mut u8,
                )
            };
            if !res {
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }
        Ok(())
    }
}

unsafe impl Send for HmacSha512Drbg {}
unsafe impl Sync for HmacSha512Drbg {}
