// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::os::raw::*;

use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{Digest, MechOperation};
use crate::ossl::bindings::*;
use crate::ossl::common::*;

#[derive(Debug)]
pub struct HashOperation {
    mech: CK_MECHANISM_TYPE,
    state: HashState,
    finalized: bool,
    in_use: bool,
}

#[derive(Debug)]
pub struct HashState {
    md: EvpMd,
    ctx: EvpMdCtx,
}

impl HashState {
    pub fn new(alg: *const c_char) -> Result<HashState> {
        Ok(HashState {
            md: EvpMd::new(alg)?,
            ctx: EvpMdCtx::new()?,
        })
    }
}

unsafe impl Send for HashState {}
unsafe impl Sync for HashState {}

impl HashOperation {
    pub fn new(mech: CK_MECHANISM_TYPE) -> Result<HashOperation> {
        let alg: *const c_char = mech_type_to_digest_name(mech);
        if alg.is_null() {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        Ok(HashOperation {
            mech: mech,
            state: HashState::new(alg)?,
            finalized: false,
            in_use: false,
        })
    }
    fn digest_init(&mut self) -> Result<()> {
        unsafe {
            match EVP_DigestInit(
                self.state.ctx.as_mut_ptr(),
                self.state.md.as_ptr(),
            ) {
                1 => Ok(()),
                _ => Err(CKR_DEVICE_ERROR)?,
            }
        }
    }
}

impl MechOperation for HashOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    fn reset(&mut self) -> Result<()> {
        self.finalized = false;
        self.in_use = false;
        Ok(())
    }
}

impl Digest for HashOperation {
    fn digest(&mut self, data: &[u8], digest: &mut [u8]) -> Result<()> {
        if self.in_use || self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if digest.len() != self.digest_len()? {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.finalized = true;
        /* NOTE: It is ok if data and digest point to the same buffer*/
        let mut digest_len = c_uint::try_from(self.digest_len()?)?;
        let r = unsafe {
            EVP_Digest(
                data.as_ptr() as *const c_void,
                data.len(),
                digest.as_mut_ptr(),
                &mut digest_len,
                self.state.md.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        if r != 1 || usize::try_from(digest_len)? != digest.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(())
    }

    fn digest_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            self.digest_init()?;
            self.in_use = true;
        }
        let r = unsafe {
            EVP_DigestUpdate(
                self.state.ctx.as_mut_ptr(),
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
        match r {
            1 => Ok(()),
            _ => {
                self.finalized = true;
                Err(CKR_DEVICE_ERROR)?
            }
        }
    }

    fn digest_final(&mut self, digest: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if digest.len() != self.digest_len()? {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.finalized = true;
        let mut digest_len = c_uint::try_from(self.digest_len()?)?;
        let r = unsafe {
            EVP_DigestFinal_ex(
                self.state.ctx.as_mut_ptr(),
                digest.as_mut_ptr(),
                &mut digest_len,
            )
        };
        if r != 1 || usize::try_from(digest_len)? != digest.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(())
    }

    fn digest_len(&self) -> Result<usize> {
        let len = unsafe { EVP_MD_get_size(self.state.md.as_ptr()) };
        Ok(usize::try_from(len)?)
    }
}
