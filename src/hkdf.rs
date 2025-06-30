// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms to access the HMAC-based
//! Key Derivation Function (HKDF) as specified in
//! [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::object::{GenericSecretKeyMechanism, ObjectFactories};
use crate::ossl::hkdf::HKDFOperation;
use crate::pkcs11::*;

/// Object that holds Mechanisms for HKDF
static HKDF_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(HKDFMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                flags: CKF_DERIVE,
            },
        }),
        Box::new(GenericSecretKeyMechanism::new(CKK_HKDF)),
    ]
});

/// Registers all HKDF related mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for ckm in &[CKM_HKDF_DERIVE, CKM_HKDF_DATA] {
        mechs.add_mechanism(*ckm, &(*HKDF_MECHS)[0]);
    }
    mechs.add_mechanism(CKM_HKDF_KEY_GEN, &(*HKDF_MECHS)[1]);
}

/// Object that represents the HKDF mechanism
#[derive(Debug)]
struct HKDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for HKDFMechanism {
    /// Returns a reference to the mechanism info
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes a HKDF Derive operation
    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            CKM_HKDF_DERIVE | CKM_HKDF_DATA => {
                Ok(Box::new(HKDFOperation::new(mech)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}
