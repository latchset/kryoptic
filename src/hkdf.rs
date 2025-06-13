// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms to access the HMAC-based
//! Key Derivation Function (HKDF) as specified in
//! [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)

use std::fmt::Debug;

use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::object::{GenericSecretKeyMechanism, ObjectFactories};
use crate::ossl::hkdf::HKDFOperation;

use pkcs11::*;

/// Registers all HKDF related mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    HKDFMechanism::register_mechanisms(mechs);
}

/// Object that represents the HKDF mechanism
#[derive(Debug)]
struct HKDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl HKDFMechanism {
    /// Instantiates and registers the HKDF related mechanisms
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_HKDF_DERIVE,
            Box::new(HKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_HKDF_DATA,
            Box::new(HKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_HKDF_KEY_GEN,
            Box::new(GenericSecretKeyMechanism::new(CKK_HKDF)),
        );
    }
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
