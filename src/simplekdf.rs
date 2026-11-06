// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms to access the
//! Miscellaneous simple key derivation mechanisms

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::native::simplekdf::{PubFromPrivOperation, SimpleKDFOperation};
use crate::object::ObjectFactories;
use crate::pkcs11::*;

/// Object that holds Mechanisms for SimpleKDF mechanisms
static KDF_MECHS: LazyLock<[Box<dyn Mechanism>; 6]> = LazyLock::new(|| {
    [
        Box::new(SimpleKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_CONCATENATE_BASE_AND_KEY,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(SimpleKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_CONCATENATE_BASE_AND_DATA,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(SimpleKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_CONCATENATE_DATA_AND_BASE,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(SimpleKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_XOR_BASE_AND_DATA,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(SimpleKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_EXTRACT_KEY_FROM_KEY,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(SimpleKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_PUB_KEY_FROM_PRIV_KEY,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
    ]
});

/// Registers all Simple KDF mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for mbox in &(*KDF_MECHS) {
        let mtype = (*mbox).mechinfo().mech_type();
        mechs.add_mechanism(mtype, mbox);
    }
}

/// Object that represents the Simple KDF mechanism
#[derive(Debug)]
struct SimpleKDFMechanism {
    minfo: MechanismInfo,
}

impl Mechanism for SimpleKDFMechanism {
    /// Returns a reference to the mechanism info
    fn mechinfo(&self) -> &MechanismInfo {
        &self.minfo
    }

    /// Initializes a SimpleKDF Derive operation
    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info().flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            CKM_CONCATENATE_BASE_AND_KEY
            | CKM_CONCATENATE_BASE_AND_DATA
            | CKM_CONCATENATE_DATA_AND_BASE
            | CKM_XOR_BASE_AND_DATA
            | CKM_EXTRACT_KEY_FROM_KEY => {
                Ok(Box::new(SimpleKDFOperation::new(mech)?))
            }
            CKM_PUB_KEY_FROM_PRIV_KEY => {
                Ok(Box::new(PubFromPrivOperation::new(mech)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}
