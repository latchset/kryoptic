// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::hacl;
use hacl::*;

#[derive(Debug)]
pub struct HashState {
    alg: Spec_Hash_Definitions_hash_alg,
    s: *mut EverCrypt_Hash_Incremental_hash_state,
}

impl HashState {
    pub fn new(alg: Spec_Hash_Definitions_hash_alg) -> HashState {
        HashState {
            alg: alg,
            s: std::ptr::null_mut(),
        }
    }

    pub fn init(&mut self) {
        unsafe {
            self.s = EverCrypt_Hash_Incremental_create_in(self.alg);
        }
    }

    pub fn reset(&mut self) {
        if self.s.is_null() {
            self.init();
        }
        unsafe {
            EverCrypt_Hash_Incremental_init(self.s);
        }
    }

    pub fn get_alg(&self) -> Spec_Hash_Definitions_hash_alg {
        self.alg
    }

    pub fn get_state(&mut self) -> *mut EverCrypt_Hash_Incremental_hash_state {
        if self.s.is_null() {
            self.init();
        }
        self.s
    }
}

impl Drop for HashState {
    fn drop(&mut self) {
        if !self.s.is_null() {
            unsafe {
                EverCrypt_Hash_Incremental_free(self.s);
            }
            self.s = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for HashState {}
unsafe impl Sync for HashState {}

impl HashOperation {
    pub fn new(mech: CK_MECHANISM_TYPE) -> KResult<HashOperation> {
        let alg = match mech {
            CKM_SHA_1 => Spec_Hash_Definitions_SHA1,
            CKM_SHA224 => Spec_Hash_Definitions_SHA2_224,
            CKM_SHA256 => Spec_Hash_Definitions_SHA2_256,
            CKM_SHA384 => Spec_Hash_Definitions_SHA2_384,
            CKM_SHA512 => Spec_Hash_Definitions_SHA2_512,
            CKM_SHA3_224 => Spec_Hash_Definitions_SHA3_224,
            CKM_SHA3_256 => Spec_Hash_Definitions_SHA3_256,
            CKM_SHA3_384 => Spec_Hash_Definitions_SHA3_384,
            CKM_SHA3_512 => Spec_Hash_Definitions_SHA3_512,
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        Ok(HashOperation {
            mech: mech,
            state: HashState::new(alg),
            finalized: false,
            in_use: false,
        })
    }
    pub fn hashlen(&self) -> usize {
        unsafe { Hacl_Hash_Definitions_hash_len(self.specdef()) as usize }
    }
    pub fn blocklen(&self) -> usize {
        unsafe { Hacl_Hash_Definitions_block_len(self.specdef()) as usize }
    }
    pub fn specdef(&self) -> Spec_Hash_Definitions_hash_alg {
        self.state.get_alg()
    }
}

impl MechOperation for HashOperation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
    fn reset(&mut self) -> KResult<()> {
        self.finalized = false;
        self.in_use = false;
        Ok(())
    }
}

impl Digest for HashOperation {
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
            EverCrypt_Hash_Incremental_hash(
                self.specdef(),
                digest.as_mut_ptr(),
                data.as_ptr() as *mut u8,
                data.len() as u32,
            );
        }
        Ok(())
    }

    fn digest_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            self.state.reset();
            self.in_use = true;
        }
        let r = unsafe {
            EverCrypt_Hash_Incremental_update(
                self.state.get_state(),
                data.as_ptr() as *mut u8,
                data.len() as u32,
            )
        };
        match r {
            hacl::EverCrypt_Error_Success => Ok(()),
            hacl::EverCrypt_Error_MaximumLengthExceeded => {
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
            EverCrypt_Hash_Incremental_finish(
                self.state.get_state(),
                digest.as_mut_ptr(),
            );
        }
        Ok(())
    }

    fn digest_len(&self) -> KResult<usize> {
        Ok(self.hashlen())
    }
}
