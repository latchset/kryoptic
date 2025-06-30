// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms to access the
//! Miscellaneous simple key derivation mechanisms

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::native::simplekdf::SimpleKDFOperation;
use crate::object::ObjectFactories;
use crate::pkcs11::*;

/// Object that holds Mechanisms for SimpleKDF
static SIMPLE_KDF_MECH: LazyLock<Box<dyn Mechanism>> = LazyLock::new(|| {
    Box::new(SimpleKDFMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
            flags: CKF_DERIVE,
        },
    })
});

/// Registers all Simple KDF mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for ckm in &[
        CKM_CONCATENATE_BASE_AND_KEY,
        CKM_CONCATENATE_BASE_AND_DATA,
        CKM_CONCATENATE_DATA_AND_BASE,
        CKM_XOR_BASE_AND_DATA,
    ] {
        mechs.add_mechanism(*ckm, &(*SIMPLE_KDF_MECH));
    }
}

/// Object that represents the Simple KDF mechanism
#[derive(Debug)]
struct SimpleKDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SimpleKDFMechanism {
    /// Returns a reference to the mechanism info
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes a SimpleKDF Derive operation
    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            CKM_CONCATENATE_BASE_AND_KEY
            | CKM_CONCATENATE_BASE_AND_DATA
            | CKM_CONCATENATE_DATA_AND_BASE
            | CKM_XOR_BASE_AND_DATA => {
                Ok(Box::new(SimpleKDFOperation::new(mech)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}
