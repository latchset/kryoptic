// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements PKCS#11 digest (hashing) mechanisms using the
//! OpenSSL EVP_Digest interface.

use crate::error::Result;
use crate::mechanism::{Digest, MechOperation};
use crate::ossl::common::{mech_type_to_digest_alg, osslctx};
use crate::pkcs11::*;
use crate::session::OpIntState;

use ossl::digest::OsslDigest;

/// Represents an active hash (digest) operation.
#[derive(Debug)]
pub struct HashOperation {
    /// The specific hash mechanism being used (e.g., CKM_SHA256).
    mech: CK_MECHANISM_TYPE,
    /// The underlying OpenSSL digest (algorithm and context).
    hasher: OsslDigest,
    /// Enum indicating the internal operation state.
    state: OpIntState,
}

impl HashOperation {
    /// Creates a new `HashOperation` for the specified mechanism type.
    /// Determines the OpenSSL algorithm name from the mechanism type.
    pub fn new(mech: CK_MECHANISM_TYPE) -> Result<HashOperation> {
        Ok(HashOperation {
            mech: mech,
            hasher: OsslDigest::new(
                osslctx(),
                mech_type_to_digest_alg(mech)?,
                None,
            )?,
            state: OpIntState::Initialized,
        })
    }

    pub fn restore(
        mech: CK_MECHANISM_TYPE,
        state: &[u8],
    ) -> Result<HashOperation> {
        let mut op = Self::new(mech)?;
        op.hasher.set_state(state)?;
        op.state = OpIntState::Updated;
        Ok(op)
    }
}

impl MechOperation for HashOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.state == OpIntState::Finalized
    }
    fn reset(&mut self) -> Result<()> {
        self.hasher.reset(None)?;
        self.state = OpIntState::Initialized;
        Ok(())
    }
    fn state_size(&self) -> Result<usize> {
        Ok(self
            .hasher
            .get_state_size()
            .map_err(|_| CKR_STATE_UNSAVEABLE)?)
    }
    fn state_save(&self, state: &mut [u8]) -> Result<usize> {
        Ok(self
            .hasher
            .get_state(state)
            .map_err(|_| CKR_STATE_UNSAVEABLE)?)
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        Some(true)
    }
}

impl Digest for HashOperation {
    fn digest(&mut self, data: &[u8], digest: &mut [u8]) -> Result<()> {
        if self.state != OpIntState::Initialized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if digest.len() != self.hasher.size() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.state = OpIntState::Finalized;
        self.hasher.update(data)?;
        let len = self.hasher.finalize(digest)?;
        if len != digest.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(())
    }

    fn digest_update(&mut self, data: &[u8]) -> Result<()> {
        if self.state == OpIntState::Finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.state = OpIntState::Updated;
        match self.hasher.update(data) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.state = OpIntState::Finalized;
                Err(CKR_DEVICE_ERROR)?
            }
        }
    }

    fn digest_final(&mut self, digest: &mut [u8]) -> Result<()> {
        if self.state == OpIntState::Finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if digest.len() != self.hasher.size() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.state = OpIntState::Finalized;
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
