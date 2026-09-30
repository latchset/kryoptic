// Copyright 2026
// See LICENSE.txt file for terms

//! This module implements PKCS#11 digest (hashing) mechanisms using the
//! AWS-LC-backed `awslc::digest::Digest`. Mirrors `crate::ossl::hash`.

use crate::awslc::common::mech_type_to_digest_alg;
use crate::error::Result;
use crate::mechanism::{Digest, MechOperation};
use crate::pkcs11::*;

use crate::lowlevel::digest::Digest as AwsLcDigest;

#[derive(Debug)]
pub struct HashOperation {
    mech: CK_MECHANISM_TYPE,
    hasher: AwsLcDigest,
    finalized: bool,
    in_use: bool,
}

impl HashOperation {
    pub fn new(mech: CK_MECHANISM_TYPE) -> Result<HashOperation> {
        Ok(HashOperation {
            mech,
            hasher: AwsLcDigest::new(mech_type_to_digest_alg(mech)?)?,
            finalized: false,
            in_use: false,
        })
    }

    /// `src/hash.rs`'s `HashMechanism::digest_restore` and
    /// `internal_hash_restore_op` call `HashOperation::restore`
    /// unconditionally (regardless of backend), so this must exist even
    /// though it always fails: AWS-LC's `EVP_MD_CTX` has no serialize API
    /// to reconstruct a context from saved state.
    pub fn restore(
        _mech: CK_MECHANISM_TYPE,
        _state: &[u8],
    ) -> Result<HashOperation> {
        Err(CKR_SAVED_STATE_INVALID)?
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
        self.hasher.reset()?;
        self.finalized = false;
        self.in_use = false;
        Ok(())
    }

    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        Some(true)
    }

    // state_size/state_save keep the MechOperation trait defaults
    // (CKR_STATE_UNSAVEABLE): AWS-LC's EVP_MD_CTX has no serialize API, so
    // C_DigestGetOperationState/C_DigestSetOperationState are unsupported
    // on this backend for now.
}

impl Digest for HashOperation {
    fn digest(&mut self, data: &[u8], digest: &mut [u8]) -> Result<()> {
        if self.in_use || self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if digest.len() != self.hasher.size() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.finalized = true;
        self.hasher.update(data)?;
        let len = self.hasher.finalize(digest)?;
        if len != digest.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(())
    }

    fn digest_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        match self.hasher.update(data) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.finalized = true;
                Err(CKR_DEVICE_ERROR)?
            }
        }
    }

    fn digest_final(&mut self, digest: &mut [u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if digest.len() != self.hasher.size() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.finalized = true;
        let len = self.hasher.finalize(digest)?;
        if len != digest.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(())
    }

    fn digest_len(&self) -> Result<usize> {
        Ok(self.hasher.size())
    }
}
