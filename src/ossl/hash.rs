// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements PKCS#11 digest (hashing) mechanisms using the
//! OpenSSL EVP_Digest interface.

use crate::error::Result;
use crate::mechanism::{Digest, MechOperation};
use crate::ossl::common::{mech_type_to_digest_alg, osslctx};
use crate::pkcs11::*;

use ossl::digest::OsslDigest;

/// Represents an active hash (digest) operation.
#[derive(Debug)]
pub struct HashOperation {
    /// The specific hash mechanism being used (e.g., CKM_SHA256).
    mech: CK_MECHANISM_TYPE,
    /// The underlying OpenSSL digest (algorithm and context).
    hasher: OsslDigest,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
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
            finalized: false,
            in_use: false,
        })
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
        self.hasher.reset(None)?;
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
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
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
