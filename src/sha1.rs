// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::cryptography;
use super::err_rv;
use super::error;
use super::interface;
use super::mechanism;
use super::object;
use cryptography::*;
use error::{KError, KResult};
use interface::*;
use mechanism::*;

use std::fmt::Debug;

#[derive(Debug)]
struct SHA1Mechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SHA1Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn digest_new(&self, mech: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
        if mech.mechanism != CKM_SHA_1 {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(Box::new(SHA1Operation::new()))
    }
}

#[derive(Debug)]
pub struct SHA1Operation {
    state: SHA1state,
    finalized: bool,
    in_use: bool,
}

impl SHA1Operation {
    pub fn new() -> SHA1Operation {
        SHA1Operation {
            state: SHA1state::new(),
            finalized: false,
            in_use: false,
        }
    }
}

impl MechOperation for SHA1Operation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        CKM_SHA_1
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Digest for SHA1Operation {
    fn digest(&mut self, data: &[u8], digest: &mut [u8]) -> KResult<()> {
        if self.in_use || self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest.len() != self.digest_len()? {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        self.finalized = true;
        /* NOTE: It is ok if data and digest point to the same buffer*/
        unsafe {
            Hacl_Streaming_SHA1_legacy_hash(
                data.as_ptr() as *mut u8,
                data.len() as u32,
                digest.as_mut_ptr(),
            )
        }
        Ok(())
    }

    fn digest_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            unsafe {
                Hacl_Streaming_SHA1_legacy_init(self.state.get_state());
            }
            self.in_use = true;
        }
        let r = unsafe {
            Hacl_Streaming_SHA1_legacy_update(
                self.state.get_state(),
                data.as_ptr() as *mut u8,
                data.len() as u32,
            )
        };
        match r {
            cryptography::Hacl_Streaming_Types_Success => Ok(()),
            cryptography::Hacl_Streaming_Types_MaximumLengthExceeded => {
                self.finalized = true;
                err_rv!(CKR_DATA_LEN_RANGE)
            }
            _ => {
                self.finalized = true;
                err_rv!(CKR_DEVICE_ERROR)
            }
        }
    }

    fn digest_final(&mut self, digest: &mut [u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest.len() != self.digest_len()? {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        self.finalized = true;
        unsafe {
            Hacl_Streaming_SHA1_legacy_finish(
                self.state.get_state(),
                digest.as_mut_ptr(),
            );
        }
        Ok(())
    }

    fn digest_len(&self) -> KResult<usize> {
        Ok(unsafe {
            Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_SHA1) as usize
        })
    }
}

pub fn register(mechs: &mut Mechanisms, _: &mut object::ObjectTemplates) {
    mechs.add_mechanism(
        CKM_SHA_1,
        Box::new(SHA1Mechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
}
