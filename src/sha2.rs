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
struct SHA256Mechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SHA256Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn digest_new(&self, mech: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
        if mech.mechanism != CKM_SHA256 {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        let op = SHA256Operation {
            state: SHA256state::new(),
            finalized: false,
            in_use: false,
        };
        Ok(Box::new(op))
    }
}

#[derive(Debug)]
struct SHA256Operation {
    state: SHA256state,
    finalized: bool,
    in_use: bool,
}

impl MechOperation for SHA256Operation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        CKM_SHA256
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Digest for SHA256Operation {
    fn digest(
        &mut self,
        data: &[u8],
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use || self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        } else {
            unsafe {
                let len = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_256,
                ) as u64;
                if digest.is_null() {
                    *digest_len = len;
                    return Ok(());
                } else {
                    if *digest_len < len {
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                }
            }
        }
        self.finalized = true;
        /* NOTE: It is ok if data and digest point to the same buffer*/
        unsafe {
            Hacl_Streaming_SHA2_hash_256(
                data.as_ptr() as *mut u8,
                data.len() as u32,
                digest,
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
                Hacl_Streaming_SHA2_init_256(self.state.get_state());
            }
            self.in_use = true;
        }
        let r = unsafe {
            Hacl_Streaming_SHA2_update_256(
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

    fn digest_final(
        &mut self,
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        } else {
            unsafe {
                let len = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_256,
                ) as u64;
                if digest.is_null() {
                    *digest_len = len;
                    return Ok(());
                } else {
                    if *digest_len < len {
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                }
            }
        }
        self.finalized = true;
        unsafe {
            Hacl_Streaming_SHA2_finish_256(self.state.get_state(), digest);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SHA384Mechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SHA384Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn digest_new(&self, mech: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
        if mech.mechanism != CKM_SHA384 {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        let op = SHA384Operation {
            state: SHA384state::new(),
            finalized: false,
            in_use: false,
        };
        Ok(Box::new(op))
    }
}

#[derive(Debug)]
struct SHA384Operation {
    state: SHA384state,
    finalized: bool,
    in_use: bool,
}

impl MechOperation for SHA384Operation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        CKM_SHA384
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Digest for SHA384Operation {
    fn digest(
        &mut self,
        data: &[u8],
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use || self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        } else {
            unsafe {
                let len = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_384,
                ) as u64;
                if digest.is_null() {
                    *digest_len = len;
                    return Ok(());
                } else {
                    if *digest_len < len {
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                }
            }
        }
        self.finalized = true;
        /* NOTE: It is ok if data and digest point to the same buffer*/
        unsafe {
            Hacl_Streaming_SHA2_hash_384(
                data.as_ptr() as *mut u8,
                data.len() as u32,
                digest,
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
                Hacl_Streaming_SHA2_init_384(self.state.get_state());
            }
            self.in_use = true;
        }
        let r = unsafe {
            Hacl_Streaming_SHA2_update_384(
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

    fn digest_final(
        &mut self,
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        } else {
            unsafe {
                let len = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_384,
                ) as u64;
                if digest.is_null() {
                    *digest_len = len;
                    return Ok(());
                } else {
                    if *digest_len < len {
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                }
            }
        }
        self.finalized = true;
        unsafe {
            Hacl_Streaming_SHA2_finish_384(self.state.get_state(), digest);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SHA512Mechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SHA512Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn digest_new(&self, mech: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
        if mech.mechanism != CKM_SHA512 {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        let op = SHA512Operation {
            state: SHA512state::new(),
            finalized: false,
            in_use: false,
        };
        Ok(Box::new(op))
    }
}

#[derive(Debug)]
struct SHA512Operation {
    state: SHA512state,
    finalized: bool,
    in_use: bool,
}

impl MechOperation for SHA512Operation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        CKM_SHA512
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Digest for SHA512Operation {
    fn digest(
        &mut self,
        data: &[u8],
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use || self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        } else {
            unsafe {
                let len = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_512,
                ) as u64;
                if digest.is_null() {
                    *digest_len = len;
                    return Ok(());
                } else {
                    if *digest_len < len {
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                }
            }
        }
        self.finalized = true;
        /* NOTE: It is ok if data and digest point to the same buffer*/
        unsafe {
            Hacl_Streaming_SHA2_hash_512(
                data.as_ptr() as *mut u8,
                data.len() as u32,
                digest,
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
                Hacl_Streaming_SHA2_init_512(self.state.get_state());
            }
            self.in_use = true;
        }
        let r = unsafe {
            Hacl_Streaming_SHA2_update_512(
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

    fn digest_final(
        &mut self,
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        } else {
            unsafe {
                let len = Hacl_Hash_Definitions_hash_len(
                    Spec_Hash_Definitions_SHA2_512,
                ) as u64;
                if digest.is_null() {
                    *digest_len = len;
                    return Ok(());
                } else {
                    if *digest_len < len {
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                }
            }
        }
        self.finalized = true;
        unsafe {
            Hacl_Streaming_SHA2_finish_512(self.state.get_state(), digest);
        }
        Ok(())
    }
}

pub fn register(mechs: &mut Mechanisms, _: &mut object::ObjectTemplates) {
    mechs.add_mechanism(
        CKM_SHA256,
        Box::new(SHA256Mechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA384,
        Box::new(SHA384Mechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA512,
        Box::new(SHA512Mechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
}
